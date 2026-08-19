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
import csv
import io
import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

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


# ---------------------------------------------------------------------------
# Machine-readable serializers — CSV / XML / JSON / Markdown
#
# Every serializer below emits ONLY what the run already carries: the same
# findings, severities, and MITRE tags the rules produced and the adapter shaped
# (see console/adapter.py). No field is invented, no sample row is added; an
# idle run has no findings to write, and the caller (serve.py) returns 409
# rather than letting these emit an empty-but-official-looking file.
#
# The column vocabulary is fixed and shared across formats so a CSV and an XML
# export of the same run describe the same facts:
#   id, severity (final verdict), ruleSeverity, provenance, type, host, time,
#   title, ruleRef, mitre (techniques the finding carries).
# ---------------------------------------------------------------------------

# (key in a finding dict, column/element name). Order is the export column order.
_FIELDS = [
    ("id", "id"),
    ("sev", "severity"),
    ("ruleSev", "ruleSeverity"),
    ("prov", "provenance"),
    ("type", "type"),
    ("host", "host"),
    ("time", "time"),
    ("title", "title"),
    ("ruleRef", "ruleRef"),
]


def _mitre_pairs(finding):
    """The finding's MITRE techniques as (id, name, tactic) triples — exactly
    what the adapter attached, nothing added."""
    return [(t.get("id", ""), t.get("name", ""), t.get("tactic", ""))
            for t in (finding.get("mitre") or [])]


def _mitre_flat(finding):
    """Techniques joined for the flat (CSV / Markdown) formats: 'T1110 Brute Force'."""
    return "; ".join(f"{tid} {name}".strip() for tid, name, _ in _mitre_pairs(finding))


def build_csv(state):
    """One row per finding, RFC-4180 quoted by the stdlib csv writer."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([col for _, col in _FIELDS] + ["mitre"])
    for f in state.get("findings", []):
        writer.writerow([str(f.get(key, "")) for key, _ in _FIELDS] + [_mitre_flat(f)])
    return out.getvalue()


def build_xml(state):
    """A <report><run/><findings>…</findings></report> tree, properly escaped."""
    def attr(v):
        return quoteattr(str(v if v is not None else ""))

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append("<report>")
    lines.append(
        "  <run"
        f" runId={attr(state.get('runId', ''))}"
        f" generatedAt={attr(state.get('generatedAt', ''))}"
        f" window={attr(state.get('runWindow', ''))}"
        f" hosts={attr(state.get('runHosts', ''))}"
        f" linesParsed={attr(state.get('linesParsed', 0))}"
        f" linesUnparsed={attr(state.get('linesUnparsed', 0))}"
        f" source={attr(state.get('sourceLabel', ''))}/>")
    lines.append("  <findings>")
    for f in state.get("findings", []):
        lines.append("    <finding>")
        for key, name in _FIELDS:
            lines.append(f"      <{name}>{escape(str(f.get(key, '')))}</{name}>")
        pairs = _mitre_pairs(f)
        if pairs:
            lines.append("      <mitre>")
            for tid, tname, tactic in pairs:
                lines.append(
                    f"        <technique id={attr(tid)} name={attr(tname)}"
                    f" tactic={attr(tactic)}/>")
            lines.append("      </mitre>")
        else:
            lines.append("      <mitre/>")
        lines.append("    </finding>")
    lines.append("  </findings>")
    lines.append("</report>")
    return "\n".join(lines) + "\n"


def build_json(state):
    """The run's real state, machine-readable — the same object export.py loads
    and the same one /api/console_state serves. Pretty-printed for a file."""
    return json.dumps(state, ensure_ascii=False, indent=2)


def build_markdown(state):
    """A readable findings table. Pipes/newlines in fields are escaped so one
    finding never breaks the table."""
    def cell(v):
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")

    run = (f"# Report — {state.get('runId', 'run')}\n\n"
           f"- **Generated:** {state.get('generatedAt') or 'n/a'}\n"
           f"- **Window:** {state.get('runWindow') or 'n/a'}\n"
           f"- **Hosts:** {state.get('runHosts') or 'n/a'}\n"
           f"- **Parsed:** {state.get('runParsed') or 'n/a'}\n"
           f"- **Findings:** {len(state.get('findings', []))}\n\n")

    headers = [col for _, col in _FIELDS] + ["mitre"]
    table = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for f in state.get("findings", []):
        row = [cell(f.get(key, "")) for key, _ in _FIELDS] + [cell(_mitre_flat(f))]
        table.append("| " + " | ".join(row) + " |")
    if not state.get("findings"):
        table.append("| _no findings in this run_ |" + " |" * len(headers))
    return run + "\n".join(table) + "\n"


# format -> (serializer, content-type, extension). serve.py branches on this.
SERIALIZERS = {
    "html": (build, "text/html; charset=utf-8", "html"),
    "csv": (build_csv, "text/csv; charset=utf-8", "csv"),
    "xml": (build_xml, "application/xml; charset=utf-8", "xml"),
    "json": (build_json, "application/json; charset=utf-8", "json"),
    "md": (build_markdown, "text/markdown; charset=utf-8", "md"),
}


def serialize(state, fmt):
    """Render `state` in `fmt`. Returns (bytes, content_type, extension).
    Raises KeyError for an unknown format (serve.py maps that to 400)."""
    serializer, content_type, ext = SERIALIZERS[fmt]
    return serializer(state).encode("utf-8"), content_type, ext


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
