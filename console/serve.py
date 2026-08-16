#!/usr/bin/env python3
"""
serve.py — run the analyzer (or read an existing report) and serve the console.

One command from the repo root:

    python3 console/serve.py --input sample-2.log --compare
    python3 console/serve.py --report demo_report.json
    python3 console/serve.py --report demo_report.json --threat-intel demo_threat_report.json

Then open the printed http://127.0.0.1:8765/ address.

The port is fixed (override with --port) and a previous serve.py holding it is
replaced, so re-running always serves the NEW run at the SAME URL — refresh the tab
you already have open. State is sent no-store and fetched with a cache-buster, so a
refresh can never show you the previous run.

Read-only and local by construction:
  - binds 127.0.0.1 only, never 0.0.0.0
  - serves GET/HEAD; every other method is refused
  - serves exactly two files from console/, nothing else on disk
  - runs the analyzer as a subprocess with the same flags you would type

Stdlib only.
"""

import argparse
import http.server
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import adapter  # noqa: E402

CONSOLE_HTML = HERE / "anomaly_console.html"


def run_analyzer(input_path, compare, out_prefix, extra_args):
    cmd = [sys.executable, str(ROOT / "log_analyzer.py"),
           "--input", str(input_path), "--output", str(out_prefix)]
    if compare:
        cmd.append("--compare")
    cmd += extra_args
    print(f"$ {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"\nERROR: the analyzer exited {result.returncode}; nothing to serve.")
        sys.exit(result.returncode)
    return Path(f"{out_prefix}.json")


def _listeners_on(port):
    """PIDs actually LISTENing on the port.

    `-sTCP:LISTEN` matters: a plain `lsof -ti tcp:PORT` also returns the browser
    and curl processes holding ESTABLISHED connections, and killing those does
    nothing to free the port while looking like it did something.

    Returns None when lsof is unavailable, so the caller can fall back to bind.
    """
    try:
        out = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    return [int(p) for p in out.split() if p.strip().isdigit()]


def _cmdline(pid):
    return subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                          capture_output=True, text=True).stdout.strip()


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def claim_port(port):
    """Make the new run win the port, or fail loudly. Never serve stale data.

    An analyst keeps one tab open and refreshes it. If a previous serve.py keeps
    the port, that tab silently shows the PREVIOUS run — the worst failure mode
    for a review surface, because a stale answer looks exactly like a fresh one.
    So: take the port, verify it was taken, and if it cannot be taken, exit rather
    than leave the old server answering.

    Only ever terminates a process whose command line names this script. Anything
    else on the port is a foreign service, and killing it is not ours to do.
    """
    pids = _listeners_on(port)
    if pids is None:
        return                       # no lsof; bind() reports failure loudly
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
        for sig, grace in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 3.0)):
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

    # Confirm the port is genuinely free before claiming success.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        remaining = _listeners_on(port) or []
        if not [p for p in remaining if p != os.getpid()]:
            return
        time.sleep(0.1)
    print(f"\nERROR: port {port} is still held after terminating the previous console.")
    print("Refusing to start rather than leave a stale run being served.")
    sys.exit(1)


def bind(port):
    """Bind, retrying briefly through TIME_WAIT. Loud failure, never a traceback."""
    http.server.HTTPServer.allow_reuse_address = True
    last = None
    for _ in range(20):
        try:
            return http.server.HTTPServer(("127.0.0.1", port), ConsoleHandler)
        except OSError as e:
            last = e
            time.sleep(0.25)
    print(f"\nERROR: could not bind 127.0.0.1:{port} ({last}).")
    print("Refusing to start: a stale console may still be serving the previous run.")
    print("Check with:  lsof -nP -iTCP:%d -sTCP:LISTEN" % port)
    sys.exit(1)


class ConsoleHandler(http.server.BaseHTTPRequestHandler):
    """Serves the console and its state. No filesystem traversal, no writes."""

    state_json = b"{}"

    def _send(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html", "/anomaly_console.html"):
            self._send(CONSOLE_HTML.read_bytes(), "text/html; charset=utf-8")
        elif path == "/console_state.json":
            self._send(self.state_json, "application/json; charset=utf-8")
        else:
            self.send_error(404, "This server only serves the console and its state")

    def do_HEAD(self):
        self.do_GET()

    def _refuse(self):
        self.send_error(405, "This console is read-only")

    do_POST = do_PUT = do_DELETE = do_PATCH = _refuse

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")


def main():
    ap = argparse.ArgumentParser(description="Serve the anomaly console against a real run")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Log file to analyze, then serve")
    src.add_argument("--report", help="Existing analyzer report.json to serve")
    ap.add_argument("--compare", action="store_true",
                    help="With --input: also run the unprimed LLM-alone pass")
    ap.add_argument("--threat-intel", default=None,
                    help="Optional threat_detector.py report.json, for MITRE chips")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true", help="Do not open a browser")
    ap.add_argument("analyzer_args", nargs="*",
                    help="Extra args passed through to log_analyzer.py")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="anomaly-console-") as tmp:
        if args.input:
            report_path = run_analyzer(args.input, args.compare,
                                       Path(tmp) / "run", args.analyzer_args)
        else:
            report_path = Path(args.report)
            if not report_path.exists():
                print(f"ERROR: report not found: {report_path}")
                sys.exit(1)

        report = json.loads(report_path.read_text())
        threat = (json.loads(Path(args.threat_intel).read_text())
                  if args.threat_intel else None)
        state = adapter.adapt(report, threat)
        ConsoleHandler.state_json = json.dumps(state).encode()

        n = len(state["findings"])
        print(f"\n  {n} finding(s) · {state['runParsed']}")
        if state["compareRun"]:
            print(f"  compare: {state['underratedCount']} under-rated "
                  f"({state['chunksUsable']}/{state['chunksTotal']} chunks usable)")
        else:
            print("  compare: not run — the under-rated pill will say so rather than show 0")
        if state["degraded"] or state["analyzerErrors"]:
            print("  partial run: some chunks had no usable model output")

        url = f"http://127.0.0.1:{args.port}/"
        claim_port(args.port)
        server = bind(args.port)

        # The terminal and the page must name the SAME run, so a stale tab is
        # identifiable at a glance instead of being indistinguishable from a fresh one.
        line = f"  Console: {url}   run: {state['runId']}"
        bar = "─" * (len(line) + 2)
        print(f"\n┌{bar}┐")
        print(f"│{line}  │")
        print(f"└{bar}┘")
        print(f"  serving run id : {state['runId']}")
        print(f"  generated at   : {state.get('generatedAt', '')[:19]}")
        print("  Re-running serve.py replaces this run at the same URL — just refresh.")
        print("  Ctrl-C to stop.\n", flush=True)
        if not args.no_open:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  stopped.")


if __name__ == "__main__":
    main()
