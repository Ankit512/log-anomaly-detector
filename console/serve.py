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


def free_the_port(port):
    """Take the port back from a previous serve.py so re-runs reuse the same URL.

    An analyst keeps one tab open. If every run bound a new port, that tab would
    keep showing a stale run while the new one sat somewhere else — the worst
    failure mode for a review surface, because nothing looks wrong.

    Only ever kills a process whose command line contains this script's name;
    anything else holding the port is reported and left alone.
    """
    try:
        pids = subprocess.run(["lsof", "-ti", f"tcp:{port}"],
                              capture_output=True, text=True).stdout.split()
    except FileNotFoundError:
        return                      # no lsof: fall through to the bind error
    for pid in pids:
        cmd = subprocess.run(["ps", "-p", pid, "-o", "command="],
                             capture_output=True, text=True).stdout.strip()
        if "serve.py" not in cmd:
            print(f"  port {port} is held by something that is not this console "
                  f"(pid {pid}): {cmd[:60]}")
            continue
        print(f"  replacing the previous console on port {port} (pid {pid})")
        try:
            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError):
            pass
    if pids:
        time.sleep(0.6)             # let the socket clear before rebinding


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
        free_the_port(args.port)
        http.server.HTTPServer.allow_reuse_address = True
        server = http.server.HTTPServer(("127.0.0.1", args.port), ConsoleHandler)
        bar = "─" * (len(url) + 18)
        print(f"\n  ┌{bar}┐")
        print(f"  │   Console:  {url}   │")
        print(f"  └{bar}┘")
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
