#!/usr/bin/env python3
"""
adapter.py — turn an analyzer report.json into the console's state shape.

The console renders state, not reports. Everything it shows must trace to
something the analyzer actually produced; where a field has no source, the
adapter says so rather than inventing a plausible value.

Two things the report cannot carry on its own:

  - Evidence TEXT. The report records line *numbers* (timeline) and one evidence
    string, but not the log lines themselves. They are read back from
    `source_file` through normalize.py — the project's own parser — so the
    console shows the real line, and the host column is the host that parser
    found on that line rather than a guess.

  - Match offsets. Nothing records where inside a line a rule matched, so the
    highlight is placed on the most specific entity present (dest_ip:port, then
    ip). That is an approximation and is the only inferred thing here.

Stdlib only. Read-only: reads a report, a log, optionally a threat-intel report.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import normalize  # noqa: E402

SEV_COLOR = {
    "CRITICAL": "#e2807f", "HIGH": "#d8a35e", "MEDIUM": "#c9c07a",
    "LOW": "#9397ab", "INFO": "#75798c",
}
LINE_RANGE_RE = re.compile(r"lines (\d+)-(\d+)")

# rule_id -> the detector function that owns it, for the "rule predicate" panel.
RULE_REF = {
    "auth_bruteforce": "anomaly_detector.py · detect_auth_bruteforce()",
    "auth_bruteforce_success": "anomaly_detector.py · detect_auth_bruteforce()",
    "suspicious_outbound": "anomaly_detector.py · detect_suspicious_ports()",
    "critical_service_event": "anomaly_detector.py · detect_critical_and_resource()",
    "disk_pressure": "anomaly_detector.py · detect_critical_and_resource()",
    "error_rate_spike": "anomaly_detector.py · detect_error_bursts()",
    "possible_break_in": "rules_syslog.py · detect_break_in_attempts()",
}


def _load_records(source_file):
    """Index the source log by line number, using the project's own parser."""
    path = Path(source_file)
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        return {}, False
    records, _stats = normalize.load(path)
    return {r["n"]: r for r in records}, True


def _line_numbers(finding):
    nums = {e["line"] for e in finding.get("timeline", []) if e.get("line")}
    m = LINE_RANGE_RE.search(finding.get("evidence") or "")
    if m:
        nums |= {int(m.group(1)), int(m.group(2))}
    return sorted(nums)


def _highlight(raw, entities):
    """Split a line into (before, hit, after). No offsets are recorded anywhere,
    so the most specific entity present is used; no match means no highlight."""
    marks = []
    if entities.get("dest_ip") and entities.get("port"):
        marks.append(f"{entities['dest_ip']}:{entities['port']}")
    marks += [str(entities[k]) for k in ("ip", "dest_ip") if entities.get(k)]
    for mark in marks:
        i = raw.find(mark)
        if i >= 0:
            return raw[:i], mark, raw[i + len(mark):]
    return raw, "", ""


def _evidence_lines(finding, by_line, have_log):
    """Real log lines for the evidence pane, hydrated by line number."""
    entities = finding.get("entities") or {}
    is_crit = str(finding.get("severity", "")).upper() == "CRITICAL"
    out = []
    for n in _line_numbers(finding):
        record = by_line.get(n)
        if not record:
            continue
        a, hit, b = _highlight(record["raw"], entities)
        out.append({"n": n, "a": a, "hit": hit, "b": b, "crit": is_crit})

    if out:
        return out, None
    # No log available (or no line numbers): show the evidence string verbatim,
    # and say why it is not a line-numbered excerpt.
    ev = finding.get("evidence") or ""
    note = ("source log not readable — showing the recorded evidence string"
            if not have_log else "this rule records a summary, not a line excerpt")
    return ([{"n": "", "a": ev, "hit": "", "b": "", "crit": is_crit}] if ev else []), note


def _target_host(finding, lines, by_line):
    """The host the finding is ABOUT, taken from the parsed log line.

    Auth rules key on the source IP and carry no host, so the design's "host"
    column would otherwise show the attacker's address. Deriving it from the
    hydrated line gives the machine that was attacked; when nothing can be
    derived the caller labels the value as a source IP instead of pretending.
    """
    for line in lines:
        record = by_line.get(line.get("n"))
        if record and record.get("host"):
            return record["host"], True
    entities = finding.get("entities") or {}
    if entities.get("host"):
        return entities["host"], True
    for key in ("ip", "dest_ip"):
        if entities.get(key):
            return entities[key], False
    return "—", False


def _threat_chips(finding, threat_report):
    """Optional: MITRE / threat-intel context, matched by IP. Omitted if absent."""
    if not threat_report:
        return []
    entities = finding.get("entities") or {}
    ips = {str(entities[k]) for k in ("ip", "dest_ip") if entities.get(k)}
    chips = []
    for match in threat_report.get("findings", []):
        if match.get("observed_value") not in ips:
            continue
        for technique in match.get("mitre_techniques", []):
            chips.append({"text": f"{technique['technique_id']} · {technique['name']}"})
        if not match.get("mitre_techniques"):
            chips.append({"text": match.get("threat_intel_name", "threat-intel match")})
    return chips


def adapt(report, threat_report=None):
    by_line, have_log = _load_records(report.get("source_file", ""))
    compare = report.get("compare")
    compare_run = compare is not None

    findings = []
    for f in report.get("findings", []):
        source = f.get("source", "llm")
        is_detector = source == "detector"
        sev = str(f.get("severity", "info")).upper()
        timeline = f.get("timeline", [])
        lines, lines_note = _evidence_lines(f, by_line, have_log)
        host, host_derived = _target_host(f, lines, by_line)
        entities = f.get("entities") or {}

        chips = _threat_chips(f, threat_report)
        if not is_detector and source != "analyzer":
            chips.append({"text": "no rule fired"})
        for key in ("ip", "dest_ip"):
            if entities.get(key):
                chips.append({"text": str(entities[key])})

        findings.append({
            "id": f"{source}-{len(findings)}",
            "sev": sev,
            "sevColor": SEV_COLOR.get(sev, "#9397ab"),
            "ruleSev": sev if is_detector else "— below threshold",
            "llmSev": f.get("llm_alone_severity"),
            "llmWhy": f.get("llm_alone_why"),
            "delta": f.get("llm_alone_delta"),
            "prov": {"detector": "RULE-CAUGHT", "analyzer": "ANALYZER"}.get(source, "LLM-SURFACED"),
            "type": f.get("rule_id") or f.get("category") or "finding",
            "host": host,
            "hostDerived": host_derived,
            "time": timeline[-1]["t"] if timeline else "",
            "stamp": (timeline[-1].get("ts") or "") if timeline else "",
            "title": f.get("summary", ""),
            "ruleWhy": f.get("rationale", ""),
            "explanation": f.get("recommended_action", ""),
            "predicate": f.get("predicate", ""),
            "ruleRef": RULE_REF.get(f.get("rule_id"), ""),
            "occurrences": f.get("occurrences", 1),
            "chips": chips,
            "lines": lines,
            "linesNote": lines_note,
            "timeline": [{"t": e.get("t", ""), "label": e.get("label", ""),
                          "dot": SEV_COLOR.get(sev, "#9397ab")} for e in timeline],
        })

    stamps = [f["stamp"] for f in findings if f["stamp"]]
    window = (f"{min(stamps)[11:16]}–{max(stamps)[11:16]} UTC" if stamps else "")
    hosts = sorted({f["host"] for f in findings if f["hostDerived"]})
    degraded = bool(compare) and compare.get("chunks_usable", 0) < compare.get("chunks_total", 0)
    analyzer_errors = [f for f in report.get("findings", []) if f.get("source") == "analyzer"]

    source_name = Path(report.get("source_file", "run")).stem
    return {
        "live": True,
        "runId": f"{source_name}-{report.get('generated_at', '')[:10]}",
        "runWindow": window,
        "runHosts": ", ".join(hosts) if hosts else "—",
        "runParsed": _parsed_label(report),
        "generatedAt": report.get("generated_at", ""),

        # Integrity, not provenance: every value here is recomputable from the
        # files on disk. Nothing signs this run and the UI must not imply it does.
        "manifest": {
            "input_sha256": report.get("input_sha256"),
            "detector_sha256": report.get("detector_sha256"),
            "model": report.get("model"),
            "temperature": report.get("temperature"),
            "ruleset": report.get("ruleset"),
            "endpoint": report.get("endpoint"),
        },

        "compareRun": compare_run,
        "underratedCount": (compare or {}).get("underrated_count"),
        "chunksUsable": (compare or {}).get("chunks_usable"),
        "chunksTotal": (compare or {}).get("chunks_total"),
        "degraded": degraded,
        "analyzerErrors": len(analyzer_errors),
        "findings": findings,
    }


def _parsed_label(report):
    parsed = report.get("lines_parsed")
    if parsed is None:
        return f"{report.get('total_chunks_analyzed', '?')} chunk(s) analyzed"
    unparsed = report.get("lines_unparsed", 0)
    label = f"{parsed:,} lines parsed"
    return label + (f" · {unparsed:,} unparsed" if unparsed else " · 0 unparsed")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Adapt an analyzer report.json into console state")
    ap.add_argument("report")
    ap.add_argument("--threat-intel", default=None,
                    help="Optional threat_detector.py report.json, for MITRE chips")
    ap.add_argument("-o", "--output", default=None, help="Write state JSON here (default: stdout)")
    args = ap.parse_args()

    report = json.loads(Path(args.report).read_text())
    threat = json.loads(Path(args.threat_intel).read_text()) if args.threat_intel else None
    state = adapt(report, threat)
    text = json.dumps(state, indent=2)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output} ({len(state['findings'])} finding(s))")
    else:
        print(text)


if __name__ == "__main__":
    main()
