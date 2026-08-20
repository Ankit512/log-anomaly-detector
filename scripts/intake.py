#!/usr/bin/env python3
"""
intake.py — one-command safe intake: analyze locally, redact, share the redaction.

    python3 scripts/intake.py /path/to/your.log
    python3 scripts/intake.py /path/to/your.log -o intake_out

Everything runs on THIS machine. The analyze pass is the analyzer's
deterministic rules-only path (no model call, no preflight, no network I/O of
any kind). The report that is safe to share is produced by pushing every
log-derived string through console/redact.py — the project's single egress
choke point — before console/export.py serializes it. This file never
implements masking of its own; it only decides WHICH strings are given to the
choke point (all of them, minus machine-minted metadata like hashes and
ISO timestamps the adapter itself generated).

Outputs (in the chosen output directory):

    report.local.json      unredacted analyzer report   — KEEP ON YOUR MACHINE
    report.local.md        unredacted markdown report   — KEEP ON YOUR MACHINE
    report.redacted.md     masked findings report       — safe to share
    report.redacted.html   masked self-contained console — safe to share

Honesty rules carried through from the analyzer: an unrecognized format or an
empty file produces a report that SAYS so ("0 lines parsed", "NOT an
all-clear") — never a fake clean bill of health, and never a fabricated
finding.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "console"))

import log_analyzer  # noqa: E402
import redact        # noqa: E402  console/redact.py — THE masking choke point
import export        # noqa: E402  console/export.py — report serializers

# State keys whose values are machine-minted metadata, never source-log text:
# ids the adapter generated, CSS colors, sha256 hashes, and ISO/clock stamps
# the adapter formatted itself. Everything else — titles, evidence, raw lines,
# hosts, messages, chips, labels — goes through redact(). The skip list exists
# only because masking a clock stamp would REPLACE it with a fake [IP-n]
# placeholder; skipping keeps the report accurate without letting any
# log-derived string bypass the choke point.
SKIP_KEYS = {
    "id", "findingId", "sevColor", "dot",
    "generatedAt", "stamp", "ts", "time", "t", "runWindow",
    "input_sha256", "detector_sha256", "model", "endpoint",
    "ruleset", "temperature",
}


def _collect_scope(report, state):
    """Hosts and usernames the run actually saw, to seed the redaction scope.

    IP masking needs no seeding (redact.py matches addresses itself), but
    hostname/username masking is list-driven, so the lists are gathered from
    what the parser and rules recorded — nothing is guessed.
    """
    hosts, users = set(), set()
    for f in state.get("findings", []):
        if f.get("hostDerived") and f.get("host"):
            hosts.add(f["host"])
    for e in state.get("events", []):
        if e.get("host"):
            hosts.add(e["host"])
    for f in report.get("findings", []):
        ents = f.get("entities") or {}
        if ents.get("host"):
            hosts.add(str(ents["host"]))
        if ents.get("user"):
            users.add(str(ents["user"]))
        for u in ents.get("usernames_sample") or []:
            users.add(str(u))
    return hosts, users


def _redact_state(state, redactor):
    """Deep-walk the console state, masking every string through one shared
    Redactor scope so a value maps to the same placeholder everywhere."""
    def walk(node, key=None):
        if isinstance(node, str):
            return node if key in SKIP_KEYS else redactor.redact(node)
        if isinstance(node, dict):
            return {k: walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, key) for v in node]
        return node
    return walk(state)


def _banner(state):
    """The honest state, mirrored from the console's own three-way distinction."""
    if state.get("emptyInput"):
        return ("**EMPTY INPUT — 0 lines.** Nothing was analyzed, so this report "
                "is NOT an all-clear: there was nothing to check.")
    if state.get("unrecognized"):
        total = state.get("linesUnparsed", 0)
        return (f"**FORMAT NOT RECOGNIZED — 0 of {total} line(s) parsed.** "
                "Nothing was analyzed, so this report is NOT an all-clear: "
                "no rule evaluated a single line.")
    return None


def _header(state, redactor):
    c = redactor.counts
    lines = [
        "# Safe intake report (REDACTED)",
        "",
        "This report was generated entirely on the log owner's machine. "
        "No log content left that machine during analysis.",
        "",
        f"- **Redaction:** ON — {c['IP']} IP(s), {c['USER']} username(s), "
        f"{c['HOST']} hostname(s) masked. Placeholders are deterministic "
        "([IP-1] always means the same address), so patterns stay visible "
        "without exposing the value.",
        f"- **Parsed:** {state.get('runParsed', 'n/a')}",
        f"- **Findings:** {len(state.get('findings', []))}",
        "",
    ]
    banner = _banner(state)
    if banner:
        lines += [banner, ""]
    return "\n".join(lines)


def run_intake(input_path, out_dir, lines_per_chunk=25):
    """Analyze (rules-only, local) -> redact -> write shareable reports.

    Returns {"paths": {...}, "state": redacted_state, "counts": mask_counts}.
    """
    path = Path(input_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"log file not found: {input_path}")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    prefix = out / "report.local"

    # Deterministic pass only: rules, severities, correlation. rules_only
    # skips the model AND its preflight, so no network I/O happens at all.
    # Safe-intake is the HONEST flow by contract: an unrecognized file must report
    # "0 parsed — not an all-clear", never be force-parsed into a clean-looking report.
    # (The interactive analyzer defaults to force; intake deliberately does not.)
    log_analyzer.run(str(path), str(prefix), lines_per_chunk,
                     model="(none — rules only)", base_url="(local — no model call)",
                     api_key="", rules_only=True, unrecognized_mode="honest")

    report = json.loads(Path(f"{prefix}.json").read_text())
    state = export.state_from_report(f"{prefix}.json")

    hosts, users = _collect_scope(report, state)
    redactor = redact.Redactor(hosts=hosts, users=users)
    redacted = _redact_state(state, redactor)

    md_path = out / "report.redacted.md"
    md_path.write_text(_header(redacted, redactor) + export.build_markdown(redacted))
    html_path = out / "report.redacted.html"
    html_path.write_text(export.build(redacted))

    return {
        "paths": {
            "local_json": Path(f"{prefix}.json"),
            "local_md": Path(f"{prefix}.md"),
            "redacted_md": md_path,
            "redacted_html": html_path,
        },
        "state": redacted,
        "counts": dict(redactor.counts),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Safe intake: local rules-only analysis -> redacted, shareable report")
    ap.add_argument("log", help="path to the log file to analyze (stays local)")
    ap.add_argument("-o", "--out-dir", default="intake_out",
                    help="output directory (default: ./intake_out)")
    ap.add_argument("--lines-per-chunk", type=int, default=25, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    try:
        result = run_intake(args.log, args.out_dir, args.lines_per_chunk)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1

    c = result["counts"]
    p = result["paths"]
    banner = _banner(result["state"])
    print()
    print("Safe intake complete — everything ran on this machine.")
    if banner:
        print(f"  HONEST STATE: {banner.replace('**', '')}")
    print(f"  Masked: {c['IP']} IP(s), {c['USER']} username(s), {c['HOST']} hostname(s)")
    print(f"  KEEP LOCAL (unredacted): {p['local_json']}, {p['local_md']}")
    print(f"  SAFE TO SHARE (redacted): {p['redacted_md']}")
    print(f"                            {p['redacted_html']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
