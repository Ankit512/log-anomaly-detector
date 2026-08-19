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
import ipaddress
import json
import os
import shutil
import signal
import socket
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
import redact  # noqa: E402
import soc  # noqa: E402
sys.path.insert(0, str(ROOT))
import log_analyzer as la  # noqa: E402
sys.path.insert(0, str(ROOT / "threat_intel"))
from tactic_phase_map import phase_for_tactics  # noqa: E402

CONSOLE_HTML = HERE / "anomaly_console.html"
OVERVIEW_HTML = HERE / "overview.html"
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

ACCEPT_EXTS = {".log", ".txt", ".out", ".syslog", ".messages", ".err",
               ".csv", ".tsv", ".xml", ".json", ".jsonl", ".ndjson",
               ".html", ".htm", ".raw"}
ACCEPT_BARE_NAMES = {"syslog", "messages", "auth"}      # extension-less system logs
SNIFF_BYTES = 64 * 1024
REJECT_NOT_TEXT = "This doesn't look like a text log file."
# What the UIs tell the user. Kept next to ACCEPT_EXTS so the promise and the
# gate cannot drift apart; any other extension still gets the text sniff.
ACCEPTED_LABEL = "LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text"


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

# Where explanations COMPUTE. Rules, severity, correlation and the honest
# surfaces always run locally regardless of this setting; a remote node only
# ever receives redacted finding-lines (through console/redact.py, the single
# outbound choke point) and only returns advisory prose — never a verdict.
COMPUTE = {"mode": "local"}


def compute_state(sent_lines=0):
    """The console-facing compute descriptor, including the honest banner."""
    if COMPUTE.get("mode") != "remote":
        return {"remote": False}
    host = (urllib.parse.urlparse(COMPUTE.get("baseUrl", "")).hostname
            or COMPUTE.get("baseUrl", ""))
    plural = "" if sent_lines == 1 else "s"
    return {
        "remote": True, "host": host, "sentLines": sent_lines,
        "banner": (f"Compute runs on {host}. {sent_lines} finding-line{plural} sent "
                   "(redacted). Raw log stays on this machine."),
    }


def set_compute(payload):
    """Validate and apply a compute-location change. Returns the masked config."""
    mode = payload.get("mode")
    if mode == "local":
        COMPUTE.clear()
        COMPUTE["mode"] = "local"
    elif mode == "remote":
        base = (payload.get("baseUrl") or "").strip().rstrip("/")
        parsed = urllib.parse.urlparse(base)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("remote base URL must look like http(s)://host[:port]/v1")
        COMPUTE.clear()
        COMPUTE.update(mode="remote", baseUrl=base,
                       apiKey=(payload.get("apiKey") or "").strip(),
                       model=(payload.get("model") or "").strip())
    else:
        raise ValueError("compute mode must be 'local' or 'remote'")
    return masked_compute()


def masked_compute():
    """The config as the browser may see it — never the key itself."""
    out = {"mode": COMPUTE.get("mode", "local")}
    if out["mode"] == "remote":
        out.update(baseUrl=COMPUTE.get("baseUrl", ""), model=COMPUTE.get("model", ""),
                   hasKey=bool(COMPUTE.get("apiKey")))
    return out

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
    # The stamp has second granularity, so two analyses of the same source in
    # the same second would land on the SAME filename and the first would be
    # silently overwritten — a dropped run in the history. Suffix instead.
    serial = 1
    while path.exists():
        serial += 1
        path = RUNS_DIR / f"{stamp}-{run_id}-{serial}.json".replace("/", "_")
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


def runs_summary():
    """Aggregate view across ALL saved runs — the whole history, one shape.

    Pure read of the history directory. Per-run severity counts and technique
    frequencies are the SAME values the per-run dashboard shows (stored by
    adapter.adapt; frequencies recomputed from the stored findings' mitre lists
    when an older run predates the stored form — both come from the same
    rule_mitre_map). Nothing is fabricated and nothing is silently dropped: a
    history file that cannot be read appears in runs[] flagged "unreadable",
    and a run that predates severity counts is flagged "dataComplete": false
    and contributes zeros, never guesses.
    """
    entries = []
    combined = {b: 0 for b in adapter.BUCKETS}
    mitre = {}
    total_lines = total_findings = 0

    listed = list_runs()                      # already newest first

    for r in listed:
        try:
            s = load_run(r["file"])
        except (ValueError, OSError, json.JSONDecodeError):
            entries.append({"file": r["file"], "runId": r.get("runId", ""),
                            "unreadable": True})
            continue

        counts = s.get("severityCounts")
        data_complete = isinstance(counts, dict)
        if not data_complete:
            counts = {}
        freq = s.get("mitreFrequency")
        if not isinstance(freq, list):
            freq = adapter._mitre_frequency(s.get("findings", []))

        entry = {
            "file": r["file"],
            "runId": s.get("runId", ""),
            "generatedAt": s.get("generatedAt", ""),
            "sourceLabel": s.get("sourceLabel", ""),
            "linesParsed": s.get("linesParsed", 0),
            "findingCount": len(s.get("findings", [])),
            "severityCounts": {b: int(counts.get(b, 0)) for b in adapter.BUCKETS},
            "topTechniques": freq[:5],
            "unrecognized": bool(s.get("unrecognized")),
            "dataComplete": data_complete,
        }
        entries.append(entry)

        total_lines += entry["linesParsed"]
        total_findings += entry["findingCount"]
        for b in adapter.BUCKETS:
            combined[b] += entry["severityCounts"][b]
        for t in freq:                        # full frequency, not just the top slice
            agg = mitre.setdefault(t["id"], {"id": t["id"], "name": t["name"],
                                             "tactic": t["tactic"], "count": 0})
            agg["count"] += t["count"]

    # list_runs() filters files it cannot parse (right for the picker); an
    # aggregate must not pretend they don't exist. Surface them, flagged.
    if RUNS_DIR.exists():
        listed_files = {r["file"] for r in listed}
        for path in sorted(RUNS_DIR.glob("*.json"), key=lambda f: f.name, reverse=True):
            if path.name not in listed_files:
                entries.append({"file": path.name, "runId": "", "unreadable": True})

    return {
        "runs": entries,
        "totals": {
            "runCount": len(entries),
            "linesParsed": total_lines,
            "findingCount": total_findings,
            "severityCounts": combined,
            "mitreFrequency": sorted(mitre.values(),
                                     key=lambda e: (-e["count"], e["id"])),
        },
    }


# ---------------------------------------------------------------------------
# SOC Overview data (/api/overview + /api/ask)
# ---------------------------------------------------------------------------

# The Overview's KPI/alert buckets. Findings with other severities (e.g. an
# LLM note rated INFO) are real but are notes, not alerts — they stay on the
# Alerts console and are deliberately not counted into these KPIs.
KPI_BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _finding_sev_counts(findings):
    counts = {b: 0 for b in KPI_BUCKETS}
    for f in findings:
        sev = str(f.get("sev", "")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _prior_run_state():
    """The saved run immediately OLDER than the current one, for 'vs previous'.

    The current run is usually itself the newest history entry, so entries with
    generatedAt >= the current stamp are skipped. None when there is no prior —
    the caller then reports null deltas rather than inventing a comparison.
    """
    cur = STATE.get("generatedAt") or ""
    for r in list_runs():                      # newest first
        if (r.get("generatedAt") or "") < cur:
            try:
                return load_run(r["file"])
            except (ValueError, OSError, json.JSONDecodeError):
                continue
    return None


def _delta(cur, prev):
    """{pct, dir} vs the prior run; None when there is no honest base.

    prev == 0 gives no denominator for a percentage, so that is null too —
    never a made-up "100%". Equal counts show as 0% down (flat).
    """
    if prev is None or prev == 0:
        return None
    return {"pct": round(abs(cur - prev) / prev * 100),
            "dir": "up" if cur > prev else "down"}


def overview_state(window=None):
    """The SOC Overview payload, entirely derived from the current run's state.

    Every number traces to the adapter state (findings, mitreFrequency) or the
    run history (deltas). Nothing is estimated: no prior run -> null deltas; a
    finding without a timestamp is absent from the time chart; a finding whose
    rule maps to no tactic gets a blank attacker status.
    """
    if STATE.get("idle"):
        return {"error": "no run yet — analyze a log first"}

    findings = STATE.get("findings", [])
    counts = _finding_sev_counts(findings)
    total = sum(counts.values())

    prior = _prior_run_state()
    if prior is None:
        deltas = {k: None for k in ("total", "critical", "high", "medium", "low")}
    else:
        p_counts = _finding_sev_counts(prior.get("findings", []))
        deltas = {"total": _delta(total, sum(p_counts.values()))}
        for b in KPI_BUCKETS:
            deltas[b.lower()] = _delta(counts[b], p_counts[b])

    bins = {}
    for f in findings:
        sev = str(f.get("sev", "")).upper()
        stamp = f.get("stamp") or ""
        if sev not in KPI_BUCKETS or len(stamp) < 13:
            continue
        hour = stamp[:13] + ":00:00Z"
        b = bins.setdefault(hour, {"t": hour, "critical": 0, "high": 0,
                                   "medium": 0, "low": 0})
        b[sev.lower()] += 1

    tactic_counts = {}
    for t in STATE.get("mitreFrequency") or []:
        tactic_counts[t["tactic"]] = tactic_counts.get(t["tactic"], 0) + t["count"]

    latest = []
    for f in sorted(findings, key=lambda f: f.get("stamp") or "", reverse=True)[:10]:
        tactics = []
        for t in f.get("mitre") or []:
            if t.get("tactic") and t["tactic"] not in tactics:
                tactics.append(t["tactic"])
        latest.append({
            "id": f.get("id"),
            "time": (f.get("stamp") or "")[:19].replace("T", " "),
            "severity": f.get("sev", ""),
            "attackerStatus": phase_for_tactics(tactics),
            "tactics": tactics,
            "name": f.get("title", ""),
            "source": STATE.get("sourceLabel", ""),
        })

    files = []
    if STATE.get("sourceLabel"):
        files.append({"name": Path(STATE["sourceLabel"]).name,
                      "ok": not STATE.get("unrecognized")})
    for s in bundled_samples():
        name = Path(s["value"]).name
        if all(f["name"] != name for f in files):
            files.append({"name": name, "ok": True})

    # The label states what is actually shown — the current run's own window.
    # A ?window=... preference is echoed nowhere until history-window filtering
    # exists; pretending "Last 24 Hours" over single-run data would be a lie.
    label = "Current run" + (f" · {STATE['runWindow']}" if STATE.get("runWindow") else "")

    return {
        "generatedAt": STATE.get("generatedAt", ""),
        "timeWindowLabel": label,
        "kpis": {"total": total, "critical": counts["CRITICAL"],
                 "high": counts["HIGH"], "medium": counts["MEDIUM"],
                 "low": counts["LOW"], "deltas": deltas},
        "severityDonut": [{"bucket": b, "count": counts[b],
                           "pct": round(counts[b] / total * 100) if total else 0}
                          for b in KPI_BUCKETS],
        "alertsOverTime": {"bins": [bins[k] for k in sorted(bins)]},
        "mitreTactics": [{"tactic": k, "count": v} for k, v in
                         sorted(tactic_counts.items(), key=lambda kv: (-kv[1], kv[0]))],
        "latestAlerts": latest,
        "ingestion": {"acceptedLabel": ACCEPTED_LABEL,
                      "files": files[:8]},
        "model": (COMPUTE.get("model") or la.LLM_MODEL
                  if COMPUTE.get("mode") == "remote" else la.LLM_MODEL),
    }


ASK_SYSTEM = (
    "You are an advisory SOC analyst assistant for a local log-analysis console. "
    "Answer the reviewer's question using ONLY the findings summary provided. "
    "Severities and verdicts were assigned by deterministic rules and are final: "
    "you explain and advise, you never change, suppress, or escalate them. "
    'If the summary does not hold the answer, say so plainly. '
    'Reply as JSON: {"answer": "<your answer>"}.'
)

# The streaming path renders tokens as they arrive, so the reply must be plain
# prose — a JSON wrapper would leak braces into the stream. Same advisory
# framing and same read-only contract as ASK_SYSTEM, minus the JSON envelope.
ASK_SYSTEM_STREAM = (
    "You are an advisory SOC analyst assistant for a local log-analysis console. "
    "Answer the reviewer's question using ONLY the findings summary provided. "
    "Severities and verdicts were assigned by deterministic rules and are final: "
    "you explain and advise, you never change, suppress, or escalate them. "
    "If the summary does not hold the answer, say so plainly. "
    "Reply in plain prose — no JSON, no code fences."
)


def ask_analyst(question, state=None, compute=None):
    """One advisory answer about the CURRENT findings. Read-only by design.

    The prompt carries a findings SUMMARY (severity, rule, title, host, time),
    never the raw log. With remote compute, the summary and the question both
    pass through console/redact.py — the same outbound choke point as
    explanations — before leaving. The reply is prose for a human; nothing
    here writes to STATE, severities, or verdicts.
    """
    base, key, model, user = _ask_prompt(question, state, compute)
    reply = la.strip_fences(la.chat_completion(base, key, model, ASK_SYSTEM, user))
    try:                       # chat_completion asks for a JSON object reply
        answer = json.loads(reply).get("answer")
    except (json.JSONDecodeError, AttributeError):
        answer = None
    return (answer or reply).strip()


def _ask_prompt(question, state=None, compute=None):
    """Build the (base, key, model, user) for one analyst question — the shared
    summary + redaction both the blocking and streaming paths use. The summary
    carries finding metadata only (severity, rule, title, host, time), never
    raw log text; remote compute routes it through the redaction choke point."""
    state = STATE if state is None else state
    compute = COMPUTE if compute is None else compute
    question = str(question)[:2000]

    findings = state.get("findings", [])
    parts = [f"Run {state.get('runId', '?')} — {state.get('runParsed', '')} — "
             f"{len(findings)} finding(s)."]
    for f in findings[:40]:
        parts.append(f"- [{f.get('sev')}] {f.get('type')}: {f.get('title')} "
                     f"(host {f.get('host')}, at {f.get('time') or 'unknown time'})")
    if len(findings) > 40:
        parts.append(f"...and {len(findings) - 40} more finding(s) not listed.")

    if compute.get("mode") == "remote":
        hosts = {f.get("host") for f in findings if f.get("hostDerived")}
        parts, _ = redact.redact_lines(parts, hosts=hosts)
        question = redact.redact_text(question, hosts=hosts)
        base = compute["baseUrl"]
        key = compute.get("apiKey") or "unused"
        model = compute.get("model") or la.LLM_MODEL
    else:
        base, key, model = la.LLM_BASE_URL, la.LLM_API_KEY, la.LLM_MODEL

    user = "Findings summary:\n" + "\n".join(parts) + f"\n\nQuestion: {question}"
    return base, key, model, user


def ask_analyst_stream(question, state=None, compute=None):
    """Yield the analyst reply as prose chunks (advisory, read-only). Same
    summary/redaction as ask_analyst; only the delivery differs."""
    base, key, model, user = _ask_prompt(question, state, compute)
    yield from la.chat_completion_stream(base, key, model, ASK_SYSTEM_STREAM, user)


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


def validate_public_url(url):
    """Reject anything that is not a plain PUBLIC http(s) URL, so a pasted link
    cannot be turned into a server-side request against the loopback interface,
    the cloud metadata endpoint, or the local network (SSRF). Returns the parsed
    URL on success; raises ValueError (→ honest 400) otherwise.

    Every address the host resolves to must be globally routable — a hostname
    that resolves to ANY private/loopback/link-local/reserved address is
    refused. (There is a small TOCTOU window between this check and the fetch;
    for a localhost single-user console fetching public test logs that is an
    acceptable MVP posture, and the size/text gates still apply.)"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http(s) URLs can be fetched")
    host = parsed.hostname
    if not host:
        raise ValueError("that does not look like a URL")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"could not resolve host {host!r}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise ValueError(
                "that URL points at a private, loopback, or link-local address — "
                "only public log URLs can be fetched")
    return parsed


def fetch_url(url, dest_dir):
    """Download PUBLIC test data to a temp file. Never uploads anything."""
    parsed = validate_public_url(url)

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


def llm_reachable(timeout=2):
    """Probe the explanation endpoint. Used ONLY to decide the rules-only
    fallback — never to change what the rules decide. An HTTP error status
    still counts as reachable; only a connection failure does not."""
    try:
        req = urllib.request.Request(
            la.LLM_BASE_URL.rstrip("/") + "/models",
            headers={"Authorization": f"Bearer {la.LLM_API_KEY}"})
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


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
        # A fresh run has sent nothing anywhere yet; the counter grows only when
        # the gated on-demand path actually transmits redacted finding-lines.
        state["compute"] = compute_state(0)
        state["logPath"] = str(log_path)
        state["sourceKind"] = source
        state["sourceLabel"] = (value if source in ("sample", "url")
                                else (filename or "uploaded file"))
        # Honest surface: when the model endpoint was down, the run carries the
        # reason its findings have no explanations. (Bound before any publish.)
        state["llmNote"] = llm_note
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
    # Remote compute: the analyzer run is rules-only, so not one byte of log
    # text leaves during analysis. Explanations happen later, on demand, and
    # only through the redaction choke point in explain_finding().
    extra, llm_note = (), None
    if COMPUTE.get("mode") == "remote":
        extra = ("--rules-only",)
    elif not llm_reachable():
        # A downed model endpoint must not block analysis: rules own severity
        # and verdicts, so the run is complete without it — only the advisory
        # explanations are skipped, and the run says so instead of erroring.
        extra = ("--rules-only",)
        llm_note = (f"model endpoint unreachable ({la.LLM_BASE_URL}) — "
                    "rules-only run; verdicts are complete, advisory "
                    "explanations skipped")
        set_job(note=llm_note)
        print(f"  {llm_note}", flush=True)
    run_analyzer(log_path, compare, work / "run", extra_args=extra,
                 on_progress=on_progress)
    state = publish(json.loads(report_path.read_text()), partial=False)
    save_run(state)
    print(f"  serving run id : {state['runId']}", flush=True)
    return state


def explain_finding(finding, state, compute=None):
    """Advisory explanation for ONE finding, wherever compute runs.

    Local mode is today's path, unchanged: the ~25-line chunk around the
    finding goes to the model on this machine. Remote mode sends ONLY the
    finding's own lines — never the chunk, never the whole log — and only
    after console/redact.py has masked IPs, usernames and hostnames. Either
    way the model's reply is advisory prose; verdicts were computed locally
    long before this runs.

    Returns (text, sent) where sent counts the redacted finding-lines that
    actually left this machine (always 0 in local mode).
    """
    compute = COMPUTE if compute is None else compute
    log_path = Path(state.get("logPath", ""))
    lines = [e.get("line") for e in finding.get("timeline", []) if e.get("line")]
    if not log_path.exists() or not lines:
        raise LookupError("cannot locate this finding's source lines")

    ctx = ("Pre-flagged anomalies (from deterministic detectors — treat severities as "
           "authoritative):\n"
           f"- [{finding.get('sev')}] {finding.get('type')}: {finding.get('title')}")

    if compute.get("mode") == "remote":
        # REDACTION CHOKE POINT — the only place outbound text is assembled.
        all_lines = log_path.read_text(errors="replace").splitlines()
        wanted = sorted({n for n in lines if 0 < n <= len(all_lines)})
        hosts = {f.get("host") for f in state.get("findings", []) if f.get("hostDerived")}
        redacted, _ = redact.redact_lines([all_lines[n - 1] for n in wanted], hosts=hosts)
        payload = [line + "\n" for line in redacted]
        result = la.analyze_chunk(compute["baseUrl"], compute.get("apiKey") or "unused",
                                  compute.get("model") or la.LLM_MODEL,
                                  payload, 0, redact.redact_text(ctx, hosts=hosts))
        sent = len(payload)
    else:
        size = 25
        idx = (max(lines) - 1) // size
        all_lines = log_path.read_text(errors="replace").splitlines(True)
        chunk = all_lines[idx * size:(idx + 1) * size]
        result = la.analyze_chunk(la.LLM_BASE_URL, la.LLM_API_KEY, la.LLM_MODEL,
                                  chunk, idx, ctx)
        sent = 0

    text = ""
    for ex in result.get("explanations", []):
        if ex.get("explanation") and (not ex.get("rule_id")
                                      or ex.get("rule_id") == finding.get("type")):
            text = ex["explanation"]
            break
    return text or "The model returned no explanation for this finding.", sent


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
        # The SOC Overview is the landing page; the dark review console is the
        # "Alerts" drill-down. /anomaly_console.html keeps old bookmarks alive.
        if path in ("/", "/index.html", "/overview.html"):
            self._send(OVERVIEW_HTML.read_bytes(), "text/html; charset=utf-8")
        elif path in ("/alerts", "/console", "/anomaly_console.html"):
            self._send(CONSOLE_HTML.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/overview":
            self._json(overview_state())
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
        elif path == "/api/runs-summary":
            self._json(runs_summary())
        elif path == "/api/compute":
            self._json(masked_compute())
        # --- SOC subsystems (console/soc.py; contract in docs/soc_subsystems.md)
        elif path == "/api/incidents":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._json({"incidents": soc.list_incidents(
                STATE, state_filter=(qs.get("state") or [None])[0])})
        elif path.startswith("/api/incidents/"):
            inc = soc.get_incident(path.split("/")[3])
            self._json(inc) if inc else self._json({"error": "no such incident"}, 404)
        elif path == "/api/assets":
            if STATE.get("idle"):
                self._json({"error": "no run yet — analyze a log first"})
            else:
                self._json({"assets": soc.derive_assets(STATE)})
        elif path == "/api/users":
            if STATE.get("idle"):
                self._json({"error": "no run yet — analyze a log first"})
            else:
                self._json({"users": soc.derive_users(STATE)})
        elif path == "/api/cases":
            self._json({"cases": soc.list_cases()})
        elif path.startswith("/api/cases/"):
            case = soc.get_case(path.split("/")[3])
            self._json(case) if case else self._json({"error": "no such case"}, 404)
        elif path == "/api/reports":
            self._json({"reports": soc.list_reports()})
        elif path == "/api/threat-intel":
            self._json(soc.threat_intel_summary())
        elif path == "/api/metrics":
            self._json(soc.metrics(STATE, [r.get("label") for r in list_runs()]))
        else:
            self.send_error(404, "This server only serves the console, its state, and /api")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        global STATE, CURRENT_RUN_FILE
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
        elif path == "/api/compute":
            self._set_compute()
        elif path == "/api/ask":
            self._ask()
        elif path.startswith("/api/incidents/") and path.endswith("/state"):
            self._incident_state(path.split("/")[3])
        elif path == "/api/cases":
            self._create_case()
        elif path == "/api/reports":
            if STATE.get("idle"):
                return self._json({"error": "no run to report on yet"}, 409)
            self._json(soc.generate_report(STATE))
        elif path == "/api/reset":
            STATE = {"idle": True}
            CURRENT_RUN_FILE = None
            self._json(STATE)
        else:
            self.send_error(405, "This console only accepts POST /api/analyze")

    do_PUT = do_DELETE = lambda self: self.send_error(405, "read-only")

    def do_PATCH(self):
        """PATCH exists for exactly one thing: editing an analyst-created case."""
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/cases/"):
            return self.send_error(405, "read-only")
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            case = soc.patch_case(path.split("/")[3], payload)
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"error": str(e)}, 400)
        if not case:
            return self._json({"error": "no such case"}, 404)
        return self._json(case)

    def _incident_state(self, iid):
        """Analyst lifecycle transition on one incident."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            inc = soc.set_incident_state(iid, payload.get("state"))
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"error": str(e)}, 400)
        if not inc:
            return self._json({"error": "no such incident"}, 404)
        print(f"  incident {iid}: -> {inc['state']}", flush=True)
        return self._json(inc)

    def _create_case(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            case = soc.create_case(payload)
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"error": str(e)}, 400)
        print(f"  case created: {case['id']} {case['title'][:40]!r}", flush=True)
        return self._json(case, 201)

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
                # {"url": "..."} is a shorthand for {"source":"url","value":"..."}.
                if payload.get("url") and not payload.get("source"):
                    source, value = "url", payload["url"]
                else:
                    source = payload.get("source")
                    value = payload.get("value")
                compare = bool(payload.get("compare"))
                filename = data = None
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"error": f"could not read the request: {e}"}, 400)

        print(f"\n  analyze: source={source} value={str(value)[:70]!r} compare={compare}",
              flush=True)

        # Validate a pasted URL synchronously so an obviously-bad link (wrong
        # scheme, unresolvable, or an SSRF target) is an immediate honest 400
        # rather than a background job that only fails on poll.
        if source == "url":
            try:
                validate_public_url(str(value or ""))
            except ValueError as e:
                return self._json({"error": str(e)}, 400)

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

    def _ask(self):
        """AI Analyst chat: one advisory answer over the current findings."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "bad request"}, 400)
        question = str(payload.get("question") or "").strip()
        if not question:
            return self._json({"error": "ask a question"}, 400)
        if STATE.get("idle"):
            return self._json({"error": "no run yet — analyze a log first, "
                                        "then ask about its findings"}, 409)
        if payload.get("stream"):
            return self._ask_stream(question)
        try:
            answer = ask_analyst(question)
        except Exception as e:
            # An unreachable model is an honest error, never a made-up answer.
            return self._json({"error": f"the analyst model is not reachable: {e}"}, 502)
        print(f"  analyst asked: {question[:60]!r}", flush=True)
        return self._json({"answer": answer})

    def _ask_stream(self, question):
        """Stream the analyst reply as Server-Sent Events: one `{"delta": ...}`
        per token, a final `{"done": true}`, or `{"error": ...}` if the model
        is unreachable. The client can cancel by dropping the connection — the
        write then fails and we simply stop. Nothing here is fabricated: an
        empty stream ends honestly, an unreachable model is an error event."""
        print(f"  analyst asked (stream): {question[:60]!r}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

        def send(obj):
            self.wfile.write(f"data: {json.dumps(obj)}\n\n".encode())
            self.wfile.flush()

        try:
            any_token = False
            for chunk in ask_analyst_stream(question):
                any_token = True
                send({"delta": chunk})
            if not any_token:
                send({"delta": "(the model returned an empty reply)"})
            send({"done": True})
        except (BrokenPipeError, ConnectionResetError):
            # The client cancelled — stop quietly; nothing was fabricated.
            return
        except Exception as e:
            try:
                send({"error": f"the analyst model is not reachable: {e}"})
            except OSError:
                pass

    def _set_compute(self):
        """Switch where explanations compute. Never changes what runs locally."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            cfg = set_compute(json.loads(self.rfile.read(length) or b"{}"))
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"error": str(e)}, 400)
        if not STATE.get("idle"):
            STATE["compute"] = compute_state((STATE.get("compute") or {}).get("sentLines", 0))
            try:
                STATE_FILE.write_text(json.dumps(STATE, indent=2))
            except OSError:
                pass
        print(f"  compute: {cfg}", flush=True)
        return self._json(cfg)

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

        try:
            text, sent = explain_finding(finding, STATE)
        except LookupError:
            return self._json({"error": "cannot locate this finding's source lines"}, 409)
        except Exception as e:
            return self._json({"error": f"explanation failed: {e}"}, 500)

        if not text:
            text = "The model returned no explanation for this finding."
        finding["explanation"] = text
        finding["explanationOnDemand"] = True
        if sent:
            # Keep the honest banner honest: N is what actually left, cumulatively.
            prev = (STATE.get("compute") or {}).get("sentLines", 0)
            STATE["compute"] = compute_state(prev + sent)
        # persist_state() writes both the live state file AND the reopened run file,
        # so an on-demand explanation lands in the run (run-history writeback).
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
