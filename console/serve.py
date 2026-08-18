#!/usr/bin/env python3
"""
serve.py — the local review app: pick a log, analyze it, review the findings.

    python3 console/serve.py                      # opens the picker
    python3 console/serve.py --input sample-2.log --compare   # analyze immediately

Then use http://127.0.0.1:8765/ — the same URL for every run.

Three log sources, and the difference between them matters:

  bundled   files already in this repo (samples/ + sample-2.log)
  upload    a file from your machine — read locally, never sent anywhere
  url       PUBLIC test data fetched over the network, e.g. LogHub. This is the
            only source that touches the network, and it downloads *to* you; your
            own logs are never uploaded. The UI keeps it visually separate for
            exactly that reason.

Local and read-only by construction:
  - binds 127.0.0.1 only, never 0.0.0.0
  - GET serves the console and its state; POST /api/analyze is the only write-ish
    route, and all it does is run the analyzer over a log you chose
  - the analyzer itself never touches the systems that produced the log
  - the port is reclaimed from a previous instance on start, so a refresh can
    never show you a stale run

Stdlib only. (cgi is gone in 3.13, so multipart is parsed with email.parser.)
"""

import argparse
import http.server
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from email import policy
from email.parser import BytesParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import adapter  # noqa: E402
import export  # noqa: E402
sys.path.insert(0, str(ROOT))
import log_analyzer as la  # noqa: E402

CONSOLE_HTML = HERE / "anomaly_console.html"
STATE_FILE = HERE / "console_state.json"        # gitignored; handy for debugging

# Completed runs are written here so the dashboard survives a refresh, a restart, or
# a closed laptop. Without this, state lived only in the server process and a restart
# silently lost work that took minutes to produce.
RUNS_DIR = HERE / ".runs"
MAX_RUNS = 25

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
DOWNLOAD_TIMEOUT = 60

# ---------------------------------------------------------------------------
# File-type acceptance
# ---------------------------------------------------------------------------
# A gate at the door ONLY. Accepting a file never changes parsing or severity:
# an accepted file whose format nothing recognizes still comes back as
# "0 lines parsed" with the unrecognized-format banner, never a fake all-clear.

ACCEPT_EXTS = {".log", ".txt", ".out", ".syslog", ".messages", ".err"}
ACCEPT_BARE_NAMES = {"syslog", "messages", "auth"}      # extension-less system logs
SNIFF_BYTES = 64 * 1024
REJECT_NOT_TEXT = "This doesn't look like a text log file."


def accepted_by_name(filename):
    """Names that already mark a file as a log, including rotated .log.1/.log.2."""
    name = Path(filename or "").name.lower()
    if not name:
        return False
    if "." not in name:
        return name in ACCEPT_BARE_NAMES
    stem, _, ext = name.rpartition(".")
    if f".{ext}" in ACCEPT_EXTS:
        return True
    return ext.isdigit() and stem.endswith(".log")


def looks_like_text(data):
    """Sniff the head of the file: text has no NUL bytes and decodes cleanly."""
    head = data[:SNIFF_BYTES]
    if b"\x00" in head:
        return False
    for enc in ("utf-8", "latin-1"):
        try:
            head.decode(enc)
            return True
        except UnicodeDecodeError:
            continue
    return False


def check_file_accepted(filename, data):
    """Accept known log names outright; sniff everything else, rejecting non-text."""
    if accepted_by_name(filename):
        return
    if not looks_like_text(data):
        raise ValueError(REJECT_NOT_TEXT)

# Public log corpora, offered as one-click chips. Nothing is fetched until asked.
SUGGESTED_URLS = [
    {"label": "LogHub · OpenSSH (2k lines)",
     "url": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"},
    {"label": "LogHub · Linux (2k lines)",
     "url": "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log"},
    {"label": "LogHub · Apache (2k lines)",
     "url": "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log"},
]

# Mutable app state: what the console is currently showing.
STATE = {"idle": True}

# The analyzer can run for minutes. It runs on a worker thread and reports
# progress here, so /api/analyze returns immediately and the browser can show
# what is happening instead of hanging on an open request.
JOB = {"status": "idle"}
JOB_LOCK = threading.Lock()


def set_job(**fields):
    with JOB_LOCK:
        JOB.update(fields)


def job_snapshot():
    with JOB_LOCK:
        return dict(JOB)


WORKDIR = None                                   # temp dir for uploads/downloads


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

CURRENT_RUN_FILE = None          # the history file STATE came from, if any


def save_run(state):
    """Persist a completed run so it can be reopened later."""
    global CURRENT_RUN_FILE
    RUNS_DIR.mkdir(exist_ok=True)
    run_id = state.get("runId") or "run"
    stamp = (state.get("generatedAt") or "").replace(":", "").replace("-", "")[:15]
    path = RUNS_DIR / f"{stamp}-{run_id}.json".replace("/", "_")
    try:
        path.write_text(json.dumps(state))
    except OSError:
        return None
    CURRENT_RUN_FILE = path.name
    # Keep the directory bounded; these are whole reports, not log lines.
    # Ordered by the timestamp in the name, never mtime: a run is rewritten whenever a
    # reviewer marks a finding, and mtime ordering would have made reviewing a run
    # promote it to "newest" — and evict the wrong file here.
    for old in sorted(RUNS_DIR.glob("*.json"), key=lambda f: f.name)[:-MAX_RUNS]:
        old.unlink(missing_ok=True)
    return path.name


def list_runs():
    """Saved runs, newest first, as navigation entries."""
    if not RUNS_DIR.exists():
        return []
    out = []
    for path in sorted(RUNS_DIR.glob("*.json"), key=lambda f: f.name, reverse=True):
        try:
            s = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        out.append({
            "marked": len(s.get("marks") or {}),
            "file": path.name,
            "runId": s.get("runId", path.stem),
            "label": s.get("sourceLabel", ""),
            "generatedAt": s.get("generatedAt", ""),
            "findings": len(s.get("findings", [])),
            "unrecognized": bool(s.get("unrecognized")),
            "compareRun": bool(s.get("compareRun")),
        })
    return out


def load_run(name):
    """Reopen a saved run. Name is matched against the index, never joined blindly."""
    if name not in {r["file"] for r in list_runs()}:
        raise ValueError("no such run")
    return json.loads((RUNS_DIR / name).read_text())


def carry_marks(previous, state):
    """Keep marks when the SAME run is published again (rules-only, then explained).

    Finding ids are positional, so a mark made on the rules-only publish would land on
    a different finding once the model's findings are merged in. A mark is kept only
    where the id still names a finding with the same title; anything else is dropped.
    Losing a mark is recoverable — silently moving one to another finding is not.
    """
    marks = (previous or {}).get("marks") or {}
    if not marks:
        return {}
    now = {f.get("id"): f.get("title") for f in state.get("findings", [])}
    before = {f.get("id"): f.get("title") for f in (previous.get("findings") or [])}
    return {fid: v for fid, v in marks.items()
            if fid in now and now[fid] == before.get(fid)}


def persist_state():
    """Write STATE to the live state file AND back into its run-history entry.

    Anything a reviewer adds after the analyzer finishes — marks, on-demand
    explanations — is only in memory until this runs. Writing the live file alone was
    the old bug: the work survived a refresh but vanished the moment the run was
    reopened from history, because history still held the version saved at run time.
    """
    try:
        STATE_FILE.write_text(json.dumps(STATE, indent=2))
    except OSError:
        pass
    if not CURRENT_RUN_FILE:
        return
    try:
        (RUNS_DIR / CURRENT_RUN_FILE).write_text(json.dumps(STATE))
    except OSError:
        pass


def bundled_samples():
    """Logs shipped with the repo, as picker entries. Whitelist for `sample`."""
    out = []
    # *.csv covers Log360 exports; routing stays content-based in normalize.py,
    # so a CSV that is NOT a Log360 export still hits the honest banner.
    sample_paths = sorted([*(ROOT / "samples").glob("*.log"),
                           *(ROOT / "samples").glob("*.csv")])
    for path in [ROOT / "sample-2.log", *sample_paths]:
        if not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        try:
            lines = sum(1 for _ in path.open(errors="replace"))
        except OSError:
            continue
        out.append({"value": rel, "name": path.name, "lines": lines,
                    "bytes": path.stat().st_size})
    return out


def resolve_sample(value):
    """Map a picker value to a real path, refusing anything not on the whitelist.

    The whitelist is the point: this endpoint takes a string from a browser, and
    joining it onto a path would let any file on the machine be read back through
    the console.
    """
    allowed = {s["value"] for s in bundled_samples()}
    if value not in allowed:
        raise ValueError(f"not a bundled sample: {value!r}")
    return ROOT / value


def fetch_url(url, dest_dir):
    """Download PUBLIC test data to a temp file. Never uploads anything."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http(s) URLs can be fetched")
    if not parsed.netloc:
        raise ValueError("that does not look like a URL")

    req = urllib.request.Request(url, headers={"User-Agent": "log-analyzer-console/1.0"})
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"file is larger than {MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB")
    if not data.strip():
        raise ValueError("the URL returned an empty file")

    name = Path(urllib.parse.unquote(parsed.path)).name or "downloaded.log"
    check_file_accepted(name, data)
    dest = Path(dest_dir) / name
    dest.write_bytes(data)
    return dest


def save_upload(filename, data, dest_dir):
    """Write an uploaded file to the temp dir. It never leaves this machine."""
    if not data:
        raise ValueError("the uploaded file was empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)}MB")
    check_file_accepted(filename, data)
    safe = Path(filename or "uploaded.log").name or "uploaded.log"
    dest = Path(dest_dir) / safe
    dest.write_bytes(data)
    return dest


def parse_multipart(body, content_type):
    """Minimal multipart/form-data reader (cgi was removed in Python 3.13)."""
    raw = b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    fields = {}
    if not msg.is_multipart():
        return fields
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        fields[name] = (part.get_filename(), part.get_payload(decode=True))
    return fields


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def run_analyzer(input_path, compare, out_prefix, extra_args=(), on_progress=None):
    """Run the analyzer, streaming its progress lines instead of blocking silently."""
    cmd = [sys.executable, str(ROOT / "log_analyzer.py"),
           "--input", str(input_path), "--output", str(out_prefix)]
    if compare:
        cmd.append("--compare")
    cmd += list(extra_args)
    print(f"\n$ {' '.join(cmd)}", flush=True)

    env = dict(os.environ, LOG_ANALYZER_PROGRESS="1", PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    tail = []
    # iter(readline) not `for line in proc.stdout`: the latter uses a read-ahead
    # buffer, which delays progress lines by thousands of bytes — long enough that
    # the UI looked stuck at 0 while the analyzer was several chunks in.
    for line in iter(proc.stdout.readline, ""):
        line = line.rstrip("\n")
        if line.startswith("PROGRESS "):
            try:
                if on_progress:
                    on_progress(json.loads(line[len("PROGRESS "):]))
            except json.JSONDecodeError:
                pass
            continue
        print(line, flush=True)
        tail.append(line)
        del tail[:-40]
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("\n".join(tail[-12:]) or f"analyzer exited {proc.returncode}")
    return Path(f"{out_prefix}.json")


def analyze(source, value, compare, filename=None, data=None, threat_intel=None):
    """Resolve a source to a file, analyze it, and become the console's state."""
    global STATE
    started = time.monotonic()
    work = Path(tempfile.mkdtemp(prefix="analysis-", dir=WORKDIR))
    set_job(status="running", phase="reading", done=0, total=0, findings=0,
            label=str(value or filename or "log"), started=started, error=None)

    if source == "sample":
        log_path = resolve_sample(value)
    elif source == "url":
        log_path = fetch_url(value, work)
    elif source == "upload":
        log_path = save_upload(filename, data, work)
    else:
        raise ValueError(f"unknown source {source!r}")

    report_path = work / "run.json"

    def publish(report_json, partial):
        """Make a report the console's current state."""
        global STATE, CURRENT_RUN_FILE
        # A new run is not saved to history until it finishes, and it is emphatically
        # not the previous run: detach first, or a mark made while explanations are
        # still arriving would be written into the run before it.
        CURRENT_RUN_FILE = None
        state = adapter.adapt(report_json, None)
        # A reviewer can mark a finding while explanations are still arriving; the
        # rules-only publish and the final one are the same run, so those marks follow.
        state["marks"] = carry_marks(
            STATE if STATE.get("logPath") == str(log_path) else None, state)
        state["idle"] = False
        state["partial"] = partial
        state["logPath"] = str(log_path)
        state["sourceKind"] = source
        state["sourceLabel"] = (value if source in ("sample", "url")
                                else (filename or "uploaded file"))
        STATE = state
        try:
            STATE_FILE.write_text(json.dumps(state, indent=2))
        except OSError:
            pass
        return state

    def on_progress(p):
        elapsed = time.monotonic() - started
        done, total = p.get("done", 0), p.get("total", 0)
        # Estimate from observed pace rather than a guess, and only once there is
        # something to extrapolate from.
        eta = int(elapsed / done * (total - done)) if done and total else None
        set_job(phase=p.get("phase", "working"), done=done, total=total,
                findings=p.get("findings", JOB.get("findings", 0)),
                chunks=p.get("chunks"), gapFill=p.get("gapFill"), etaSeconds=eta)

        # The detector is done long before the model is. Publish those findings now
        # so the reviewer reads real results while explanations are still arriving.
        if p.get("partialReady") and report_path.exists():
            try:
                publish(json.loads(report_path.read_text()), partial=True)
                set_job(partialReady=True)
                print("  published rules-only findings; explanations still running",
                      flush=True)
            except (OSError, json.JSONDecodeError):
                pass

    set_job(phase="rules")
    run_analyzer(log_path, compare, work / "run", on_progress=on_progress)
    state = publish(json.loads(report_path.read_text()), partial=False)
    save_run(state)
    print(f"  serving run id : {state['runId']}", flush=True)
    return state


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class ConsoleHandler(http.server.BaseHTTPRequestHandler):
    """Serves the console, its state, and the analyze endpoint. Nothing else."""

    protocol_version = "HTTP/1.1"

    def _send(self, body, content_type, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj).encode(), "application/json; charset=utf-8", status)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html", "/anomaly_console.html"):
            self._send(CONSOLE_HTML.read_bytes(), "text/html; charset=utf-8")
        elif path == "/console_state.json":
            self._json(STATE)
        elif path == "/api/sources":
            self._json({"samples": bundled_samples(), "suggestedUrls": SUGGESTED_URLS})
        elif path == "/api/progress":
            self._json(job_snapshot())
        elif path == "/api/export":
            if STATE.get("idle"):
                return self.send_error(409, "nothing to export yet")
            body = export.build(STATE).encode()
            name = f"{STATE.get('runId', 'run')}.html".replace("/", "_")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/runs":
            self._json({"runs": list_runs(), "current": STATE.get("runId")})
        else:
            self.send_error(404, "This server only serves the console, its state, and /api")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/analyze":
            self._analyze()
        elif path == "/api/progress":
            self._json(job_snapshot())
        elif path == "/api/open":
            self._open_run()
        elif path == "/api/explain":
            self._explain()
        elif path == "/api/mark":
            self._mark()
        elif path == "/api/reset":
            global STATE, CURRENT_RUN_FILE
            STATE = {"idle": True}
            CURRENT_RUN_FILE = None
            self._json(STATE)
        else:
            self.send_error(405, "This console only accepts POST /api/analyze")

    do_PUT = do_DELETE = do_PATCH = lambda self: self.send_error(405, "read-only")

    def _analyze(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD_BYTES:
            return self._json({"error": "file too large"}, 413)
        body = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")

        try:
            if ctype.startswith("multipart/form-data"):
                fields = parse_multipart(body, ctype)
                filename, data = fields.get("file", (None, None))
                source = "upload"
                value = filename
                compare = (fields.get("compare", (None, b""))[1] or b"") in (b"1", b"true", b"on")
            else:
                payload = json.loads(body or b"{}")
                source = payload.get("source")
                value = payload.get("value")
                compare = bool(payload.get("compare"))
                filename = data = None
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"error": f"could not read the request: {e}"}, 400)

        print(f"\n  analyze: source={source} value={str(value)[:70]!r} compare={compare}",
              flush=True)

        if job_snapshot().get("status") == "running":
            return self._json({"error": "an analysis is already running"}, 409)

        def worker():
            """The analyzer takes minutes; the browser must not wait on the socket."""
            try:
                analyze(source, value, compare, filename=filename, data=data)
                set_job(status="done", phase="done", error=None)
            except ValueError as e:
                set_job(status="error", error=str(e))
            except urllib.error.URLError as e:
                set_job(status="error", error=f"could not fetch that URL: {e.reason}")
            except Exception as e:
                set_job(status="error", error=f"analysis failed: {e}")

        set_job(status="running", phase="starting", done=0, total=0, error=None,
                label=str(value or filename or "log"))
        threading.Thread(target=worker, daemon=True).start()
        # 202: accepted, not finished. The client polls /api/progress.
        return self._json({"status": "running"}, 202)

    def _open_run(self):
        """Load a saved run back into the dashboard."""
        global STATE
        length = int(self.headers.get("Content-Length") or 0)
        try:
            name = json.loads(self.rfile.read(length) or b"{}").get("file")
            state = load_run(name)
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "no such run"}, 404)
        global CURRENT_RUN_FILE
        STATE = state
        # Marks and on-demand explanations made from here on belong to THIS file.
        CURRENT_RUN_FILE = name
        persist_state()
        print(f"  reopened run: {state.get('runId')}", flush=True)
        return self._json(state)

    def _explain(self):
        """Explain ONE finding on demand.

        Eager explanations are capped, so most findings arrive with the rule verdict,
        evidence, predicate and timeline — everything deterministic — and no prose.
        This generates the prose for a single finding when a reviewer opens it, which
        is the only moment it is actually needed.
        """
        global STATE
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "bad request"}, 400)

        fid = payload.get("id")
        finding = next((f for f in STATE.get("findings", []) if f.get("id") == fid), None)
        if not finding:
            return self._json({"error": "no such finding"}, 404)
        if finding.get("explanation"):
            return self._json(finding)                     # already explained

        log_path = Path(STATE.get("logPath", ""))
        lines = [e.get("line") for e in finding.get("timeline", []) if e.get("line")]
        if not log_path.exists() or not lines:
            return self._json({"error": "cannot locate this finding's source lines"}, 409)

        size = 25
        idx = (max(lines) - 1) // size
        all_lines = log_path.read_text(errors="replace").splitlines(True)
        chunk = all_lines[idx * size:(idx + 1) * size]

        ctx = ("Pre-flagged anomalies (from deterministic detectors — treat severities as "
               "authoritative):\n"
               f"- [{finding.get('sev')}] {finding.get('type')}: {finding.get('title')}")
        try:
            text = la.explain_single(la.LLM_BASE_URL, la.LLM_API_KEY, la.LLM_MODEL,
                                     chunk, idx, ctx, rule_id=finding.get("type"))
        except Exception as e:
            return self._json({"error": f"explanation failed: {e}"}, 500)

        if not text:
            text = "The model returned no explanation for this finding."
        finding["explanation"] = text
        finding["explanationOnDemand"] = True
        persist_state()
        print(f"  explained on demand: {fid}", flush=True)
        return self._json(finding)

    def _mark(self):
        """Record an analyst's true-positive / false-positive mark on a finding.

        Marks used to live only in the page, so a refresh — or reopening the run
        tomorrow — threw the review away. They are the reviewer's own judgement, not
        the model's or the rules', and nothing else in the report can reconstruct them.
        """
        global STATE
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "bad request"}, 400)

        fid, value = payload.get("id"), payload.get("mark")
        if not any(f.get("id") == fid for f in STATE.get("findings", [])):
            return self._json({"error": "no such finding"}, 404)
        if value not in ("tp", "fp", None):
            return self._json({"error": "mark must be tp, fp, or null"}, 400)

        marks = dict(STATE.get("marks") or {})
        if value is None:
            marks.pop(fid, None)
        else:
            marks[fid] = value
        STATE["marks"] = marks
        persist_state()
        return self._json({"marks": marks})

    def log_message(self, fmt, *args):
        # Format first: log_error() passes (code, message), so indexing args and
        # assuming a string crashed the handler thread on every 404/405 — which
        # surfaced as an empty reply rather than the status code we meant to send.
        msg = fmt % args
        if "/console_state.json" in msg:
            return                                # poll noise
        print(f"  {self.address_string()} {msg}", flush=True)


# ---------------------------------------------------------------------------
# Port ownership
# ---------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"


def _listeners_on(port):
    """PIDs actually LISTENing on the port, on macOS/Linux/Windows.

    `-sTCP:LISTEN` matters on the lsof path: a plain `lsof -ti tcp:PORT` also
    returns the browser and curl processes holding ESTABLISHED connections, and
    killing those does nothing to free the port while looking like it did.

    Returns None when the platform's tool is unavailable, so the caller falls
    through to bind() and reports a clear error rather than guessing.
    """
    try:
        if IS_WINDOWS:
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                                 capture_output=True, text=True).stdout
            pids = set()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3].upper() == "LISTENING" \
                        and parts[1].endswith(f":{port}"):
                    if parts[4].isdigit():
                        pids.add(int(parts[4]))
            return sorted(pids)
        out = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True).stdout
    except (FileNotFoundError, OSError):
        return None
    return [int(p) for p in out.split() if p.strip().isdigit()]


def _cmdline(pid):
    """Command line of a process, for the "is this our console?" safety check."""
    try:
        if IS_WINDOWS:
            out = subprocess.run(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine"],
                capture_output=True, text=True).stdout
            return " ".join(out.split("\n")[1:]).strip()
        return subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                              capture_output=True, text=True).stdout.strip()
    except (FileNotFoundError, OSError):
        return ""


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def claim_port(port):
    """Make the new run win the port, or fail loudly. Never serve stale data."""
    pids = _listeners_on(port)
    if pids is None:
        return
    pids = [p for p in pids if p != os.getpid()]
    if not pids:
        return

    for pid in pids:
        cmd = _cmdline(pid)
        if "serve.py" not in cmd:
            print(f"\nERROR: port {port} is held by a process that is not this console "
                  f"(pid {pid}):\n  {cmd[:120]}")
            print("Refusing to kill it. Free the port, or pass --port <other>.")
            sys.exit(1)

        print(f"  reclaiming port {port} from the previous console (pid {pid})")
        signals = [(signal.SIGTERM, 5.0)]
        if not IS_WINDOWS:
            signals.append((signal.SIGKILL, 3.0))
        for sig, grace in signals:
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                break
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline and _alive(pid):
                time.sleep(0.1)
            if not _alive(pid):
                break
        if _alive(pid):
            print(f"\nERROR: could not stop the previous console (pid {pid}) on port {port}.")
            print("Refusing to start: the old run would keep serving stale data.")
            sys.exit(1)

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not [p for p in (_listeners_on(port) or []) if p != os.getpid()]:
            return
        time.sleep(0.1)
    print(f"\nERROR: port {port} is still held after terminating the previous console.")
    print("Refusing to start rather than leave a stale run being served.")
    sys.exit(1)


def bind(port):
    """Bind, retrying briefly through TIME_WAIT. Loud failure, never a traceback."""
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    last = None
    for _ in range(20):
        try:
            return http.server.ThreadingHTTPServer(("127.0.0.1", port), ConsoleHandler)
        except OSError as e:
            last = e
            time.sleep(0.25)
    print(f"\nERROR: could not bind 127.0.0.1:{port} ({last}).")
    print("Refusing to start: a stale console may still be serving the previous run.")
    hint = (f"netstat -ano | findstr :{port}" if IS_WINDOWS
            else f"lsof -nP -iTCP:{port} -sTCP:LISTEN")
    print(f"Check with:  {hint}")
    print(f"Or start on another port:  python3 console/serve.py --port {port + 1}")
    sys.exit(1)


def main():
    global WORKDIR
    ap = argparse.ArgumentParser(description="Local review console for the log analyzer")
    ap.add_argument("--input", help="Analyze this log immediately instead of showing the picker")
    ap.add_argument("--report", help="Serve an existing analyzer report.json")
    ap.add_argument("--compare", action="store_true",
                    help="With --input: also run the unprimed LLM-alone pass")
    ap.add_argument("--threat-intel", default=None,
                    help="Optional threat_detector.py report.json, for MITRE chips")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="Do not open a browser")
    args = ap.parse_args()

    global STATE, CURRENT_RUN_FILE
    with tempfile.TemporaryDirectory(prefix="anomaly-console-") as tmp:
        WORKDIR = tmp
        try:
            if args.report:
                report = json.loads(Path(args.report).read_text())
                threat = (json.loads(Path(args.threat_intel).read_text())
                          if args.threat_intel else None)
                STATE = adapter.adapt(report, threat)
                STATE["idle"] = False
                STATE["sourceKind"] = "report"
                STATE["sourceLabel"] = args.report
            elif args.input:
                # --input accepts any path, unlike the picker's `sample` source: this
                # one came from the user's own shell, not from a browser request, so
                # the whitelist that protects the HTTP endpoint does not apply.
                work = Path(tempfile.mkdtemp(prefix="analysis-", dir=WORKDIR))
                report_path = run_analyzer(Path(args.input), args.compare, work / "run")
                report = json.loads(report_path.read_text())
                threat = (json.loads(Path(args.threat_intel).read_text())
                          if args.threat_intel else None)
                STATE = adapter.adapt(report, threat)
                STATE["idle"] = False
                STATE["sourceKind"] = "cli"
                STATE["sourceLabel"] = args.input
        except Exception as e:
            print(f"\nERROR: {e}")
            sys.exit(1)

        # A run started from the shell is a run like any other: save it, so it can be
        # reopened later and so a reviewer's marks have somewhere to be written. Only
        # browser-started runs used to reach history, which made marks on --input runs
        # quietly page-local.
        if not STATE.get("idle"):
            save_run(STATE)

        if STATE.get("idle"):
            # A restart should not throw away a run that took minutes to produce.
            recent = list_runs()
            if recent:
                try:
                    STATE = load_run(recent[0]["file"])
                    CURRENT_RUN_FILE = recent[0]["file"]
                    print(f"  restored the last run: {STATE.get('runId')} "
                          f"({len(recent)} saved run(s) available)")
                except (ValueError, json.JSONDecodeError):
                    pass

        url = f"http://127.0.0.1:{args.port}/"
        claim_port(args.port)
        server = bind(args.port)

        run_id = "picker (no analysis yet)" if STATE.get("idle") else STATE["runId"]
        line = f"  Console: {url}   run: {run_id}"
        bar = "─" * (len(line) + 2)
        print(f"\n┌{bar}┐")
        print(f"│{line}  │")
        print(f"└{bar}┘")
        if STATE.get("idle"):
            print("  Choose a log in the browser: bundled sample, local file, or public URL.")
        else:
            print(f"  serving run id : {STATE['runId']}")
            print(f"  generated at   : {STATE.get('generatedAt', '')[:19]}")
        print("  Re-running serve.py replaces this run at the same URL — just refresh.")
        print("  Ctrl-C to stop.\n", flush=True)

        if not args.no_open:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  stopped.")
        finally:
            shutil.rmtree(STATE_FILE.parent / "__pycache__", ignore_errors=True)


if __name__ == "__main__":
    main()
