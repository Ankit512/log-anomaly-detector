#!/usr/bin/env python3
"""
export.py — turn a completed run into ONE self-contained .html file.

    python3 console/export.py report.json -o run.html
    python3 console/export.py --latest -o run.html      # most recent saved run

The result opens in any browser by double-clicking it. No Python, no Ollama, no
server, no internet — the run's state is inlined as a JavaScript variable and the
console's own renderer draws it. Filters, finding selection and the keyboard
shortcuts all work; everything that would need a server is switched off rather
than left present and broken.

This is what you send to someone who needs to read the findings but should not have
to install anything to do it.
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import adapter  # noqa: E402

CONSOLE_HTML = HERE / "anomaly_console.html"
RUNS_DIR = HERE / ".runs"


def build(state):
    """Inline a run's state into the console template."""
    template = CONSOLE_HTML.read_text()

    # `</script>` inside JSON would close the tag early and break the page; the
    # escape is invisible to JSON.parse but not to the HTML parser.
    payload = json.dumps(state, ensure_ascii=False).replace("</", "<\\/")

    inject = (
        "<script>\n"
        "/* Inlined by console/export.py — this file is self-contained. The renderer\n"
        "   below reads this instead of fetching anything, so the page makes zero\n"
        "   network requests. */\n"
        f"window.CONSOLE_DATA = {payload};\n"
        "window.STANDALONE = true;\n"
        "</script>\n"
    )

    marker = '<script>\n"use strict";'
    if marker not in template:
        raise RuntimeError("console template changed shape; cannot find the script marker")
    return template.replace(marker, inject + marker, 1)


def latest_run():
    if not RUNS_DIR.exists():
        return None
    # By name, not mtime: run files are rewritten when a reviewer marks a finding, so
    # mtime no longer means "most recent run". The name carries the run's timestamp.
    files = sorted(RUNS_DIR.glob("*.json"), key=lambda f: f.name, reverse=True)
    return json.loads(files[0].read_text()) if files else None


def state_from_report(path, threat_intel=None):
    report = json.loads(Path(path).read_text())
    threat = json.loads(Path(threat_intel).read_text()) if threat_intel else None
    state = adapter.adapt(report, threat)
    state["idle"] = False
    state["sourceLabel"] = report.get("source_file", "")
    state["sourceKind"] = "report"
    return state


def main():
    ap = argparse.ArgumentParser(
        description="Export a completed run as one self-contained HTML file")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("report", nargs="?", help="analyzer report.json to export")
    src.add_argument("--latest", action="store_true", help="export the most recent saved run")
    ap.add_argument("--threat-intel", default=None, help="optional threat_detector report.json")
    ap.add_argument("-o", "--output", default="run.html")
    args = ap.parse_args()

    state = latest_run() if args.latest else state_from_report(args.report, args.threat_intel)
    if not state:
        print("ERROR: no run to export (none saved yet, or the report is unreadable)")
        return 1

    out = Path(args.output)
    out.write_text(build(state))

    findings = len(state.get("findings", []))
    explained = sum(1 for f in state.get("findings", []) if f.get("explanation"))
    print(f"wrote {out}  ({out.stat().st_size:,} bytes)")
    print(f"  run       : {state.get('runId')}")
    print(f"  findings  : {findings}  ({explained} with explanations baked in)")
    marked = len(state.get("marks") or {})
    if marked:
        print(f"  marks     : {marked} analyst mark(s) carried into the export")
    print(f"  open it   : open {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
