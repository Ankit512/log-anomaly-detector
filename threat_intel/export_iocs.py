#!/usr/bin/env python3
"""
export_iocs.py — turn an analyzer report into a clean IOC list for threat matching.

`threat_detector.py` documents a pipeline built on `anomaly_detector.py
--export-flagged`, a flag that only ever existed in a rejected prototype of the
detector. This is the replacement, and it works from the other end: the analyzer's
report already records every principal a rule fired on, inside each finding's
`entities`, so nothing new needs to be added to the validated detector.

Reading entities rather than grepping the raw log matters — the detector's IOC
regexes are deliberately permissive, so scanning a whole log harvests every IP that
appears anywhere, including your own hosts and unrelated traffic. Exporting only
what a rule actually flagged keeps the matched set precise.

Entity-key precedence (ip -> dest_ip -> host) matches `entity_of()` in
tests/eval/run_eval.py; the eval harness and this exporter must agree on what a
finding "is about", so keep them in step if either changes.

Usage:
  python3 threat_intel/export_iocs.py report.json > iocs.txt
  python3 threat_intel/export_iocs.py report.json --ips-only > iocs.txt
  python3 threat_intel/export_iocs.py report.json --min-severity high > iocs.txt

Stdlib only. Read-only: reads a report, writes to stdout.
"""

import argparse
import json
import sys
from pathlib import Path

# Same precedence as tests/eval/run_eval.py:entity_of()
ENTITY_KEYS = ("ip", "dest_ip", "host")

# Which keys are externally-meaningful indicators vs internal asset names.
NETWORK_KEYS = ("ip", "dest_ip")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def entity_of(finding):
    """Return (key, value) for the principal this finding is about, or (None, None)."""
    entities = finding.get("entities") or {}
    for key in ENTITY_KEYS:
        if entities.get(key):
            return key, str(entities[key])
    return None, None


def iocs_from_report(report, ips_only=False, min_severity="info"):
    """Extract deduplicated IOCs from an analyzer report, best severity first."""
    threshold = SEVERITY_RANK.get(min_severity.lower(), 4)
    best = {}          # value -> (rank, key, severity, type, summary)

    for finding in report.get("findings", []):
        key, value = entity_of(finding)
        if not value:
            continue
        if ips_only and key not in NETWORK_KEYS:
            continue
        severity = str(finding.get("severity", "info")).lower()
        rank = SEVERITY_RANK.get(severity, 4)
        if rank > threshold:
            continue
        # Keep the most severe finding per value; an IP flagged twice is one IOC.
        if value not in best or rank < best[value][0]:
            best[value] = (rank, key, severity,
                           finding.get("rule_id") or finding.get("category", ""),
                           str(finding.get("summary", ""))[:70])

    return [(v, *rest) for v, rest in sorted(best.items(), key=lambda kv: kv[1][0])]


def main():
    ap = argparse.ArgumentParser(
        description="Export flagged IOCs from an analyzer report.json for threat matching")
    ap.add_argument("report", help="Path to the analyzer's report .json")
    ap.add_argument("--ips-only", action="store_true",
                    help="Emit only network indicators (ip/dest_ip), omitting internal "
                         "hostnames. Use this when sending to a live/third-party feed.")
    ap.add_argument("--min-severity", default="info",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="Only export findings at or above this severity (default: all)")
    args = ap.parse_args()

    path = Path(args.report)
    if not path.exists():
        print(f"ERROR: report not found: {args.report}", file=sys.stderr)
        return 1
    try:
        report = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: {args.report} is not valid JSON ({e})", file=sys.stderr)
        return 1

    rows = iocs_from_report(report, ips_only=args.ips_only, min_severity=args.min_severity)
    if not rows:
        print(f"# no flagged IOCs in {args.report}", file=sys.stderr)

    print(f"# IOCs exported from {args.report} — {len(rows)} indicator(s)")
    for value, _rank, key, severity, rule, summary in rows:
        marker = "" if key in NETWORK_KEYS else "  [internal asset]"
        print(f"{value}  # {severity} {rule}: {summary}{marker}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
