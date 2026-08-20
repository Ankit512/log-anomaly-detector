#!/usr/bin/env python3
"""
validate_real.py — measure the FROZEN detector's real-world detection quality.

Unlike run_eval.py (which scores against a synthetic corpus with injected
attacks), this harness scores the detector's output on a REAL log file against a
hand-labeled GROUND-TRUTH file. It computes NO verdicts of its own: it runs the
existing deterministic analyze path — normalize (envelope) -> rules_syslog
(vocabulary + dedupe) -> anomaly_detector.detect (correlation) — exactly as
run_eval.py does, then SCORES that output against the labels.

What it reports:
  * precision / recall / F1 (from real label comparisons — never asserted)
  * the false-positive list (detector fired, human did not label it)
  * the missed-detection / false-negative list (labeled, detector did not fire)
  * severity mismatches (right attack + entity, wrong rule-owned severity)
  * per-format PARSE COVERAGE (lines parsed vs unrecognized %)

Honesty (the whole point):
  * Severity is rule-owned. This harness reads the detector's severity; it never
    guesses one. A label's `severity` is the analyst's EXPECTED severity, and a
    disagreement is surfaced honestly as a severity mismatch, not hidden.
  * Unrecognized format -> honest banner ("0 lines parsed"), never a fake
    all-clear. If parsed == 0, precision is reported n/a (the detector was never
    given anything it could read).
  * No fabricated metrics. If a value cannot be computed, it is printed as n/a.

Usage:
  python3 validate_real.py --log <path> --labels <path.json>
  python3 validate_real.py --log <path> --labels <path.json> --report out.md
  python3 validate_real.py --log <path> --labels <path.json> --json
  python3 validate_real.py --selftest      # prove FP/FN/severity rendering (synthetic)

Ground-truth label file (JSON) — see tests/eval/VALIDATION.md for the full spec:
  {
    "log": "tests/eval/fixtures/Linux_bruteforce_slice.log",
    "note": "hand-labeled 2026-08-20; brute-force IPs read from raw failed-password lines",
    "expected": [
      {"rule_id": "auth_bruteforce", "severity": "high",
       "entity": "218.188.2.4", "evidence_lines": [1, 42],
       "note": "14 failed passwords for 'unknown'"}
    ]
  }

Scoring unit = (rule_id, severity, entity) — the detector emits CORRELATED
findings (one per attacker/entity), not per-line verdicts, so the finding is the
unit that can be scored. `evidence_lines` and `note` are human traceability and
are NOT scored.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

import normalize            # noqa: E402
import rules_syslog         # noqa: E402
from anomaly_detector import detect  # noqa: E402

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def entity_of(anomaly):
    """The principal a finding is about: IP for auth/network, host for resources.

    Identical to run_eval.entity_of so both harnesses agree on the scored unit.
    """
    ents = anomaly.get("entities", {})
    for key in ("ip", "dest_ip", "host"):
        if ents.get(key):
            return str(ents[key])
    return None


def analyze(path):
    """Run one file through the full deterministic path. Returns (findings, meta).

    Mirrors run_eval.analyze: rfc3164 gets the syslog vocabulary + extra rules +
    auth dedupe; every other recognized format goes straight to detect(). No
    verdict is computed here — detect() (frozen) owns severity and correlation.
    """
    records, stats = normalize.load(path)
    extra = []
    if stats["format"] == "rfc3164":
        records, _ = rules_syslog.canonicalize(records)
        extra = rules_syslog.detect_extra(records)
        records, _ = rules_syslog.dedupe_auth_attempts(records)

    anomalies = detect(records) + extra
    findings = []
    for a in anomalies:
        findings.append({
            "rule_id": a["type"],
            "severity": a["severity"],
            "entity": entity_of(a),
            "evidence": a.get("evidence", ""),
            "summary": a.get("summary", ""),
        })
    total = stats["parsed"] + stats["unparsed"]
    meta = {
        "format": stats["format"],
        "total_lines": stats.get("total_lines", total),
        "parsed": stats["parsed"],
        "unparsed": stats["unparsed"],
        "unparsed_examples": stats.get("unparsed_examples", []),
    }
    return findings, meta


def _key(d):
    """Scoring key: (rule_id, severity, entity)."""
    return (d["rule_id"], d["severity"], d.get("entity"))


def _load_labels(path):
    obj = json.loads(Path(path).read_text())
    expected = obj.get("expected", [])
    normed = []
    for e in expected:
        if "rule_id" not in e:
            raise ValueError(f"label missing rule_id: {e!r}")
        normed.append({
            "rule_id": e["rule_id"],
            "severity": e.get("severity", ""),
            "entity": e.get("entity"),
            "evidence_lines": e.get("evidence_lines", []),
            "note": e.get("note", ""),
        })
    return obj, normed


def score(findings, labels):
    """Compare detector findings to labels. Returns a scorecard dict.

    Precision/recall/F1 come only from these real set comparisons. When the two
    disagree on severity alone (same rule_id + entity), the pair is also surfaced
    as a `severity_mismatch` so an operator is not misled into reading one real
    attack as an unrelated FP plus an unrelated FN.
    """
    fset = {_key(f): f for f in findings}
    lset = {_key(l): l for l in labels}

    tp_keys = fset.keys() & lset.keys()
    fp_keys = fset.keys() - lset.keys()
    fn_keys = lset.keys() - fset.keys()

    # Severity-only disagreements: same (rule_id, entity) on both sides.
    fp_re = {(k[0], k[2]): k for k in fp_keys}
    fn_re = {(k[0], k[2]): k for k in fn_keys}
    mismatches = []
    for re_key in fp_re.keys() & fn_re.keys():
        fk, lk = fp_re[re_key], fn_re[re_key]
        mismatches.append({
            "rule_id": re_key[0], "entity": re_key[1],
            "detector_severity": fk[1], "labeled_severity": lk[1],
        })

    tp, fp, fn = len(tp_keys), len(fp_keys), len(fn_keys)
    # precision is n/a when the detector produced nothing to be right or wrong about
    precision = (tp / (tp + fp)) if (tp + fp) else None
    recall = (tp / (tp + fn)) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positives": [fset[k] for k in sorted(fp_keys, key=lambda x: (x[0], str(x[2])))],
        "false_negatives": [lset[k] for k in sorted(fn_keys, key=lambda x: (x[0], str(x[2])))],
        "true_positives": [fset[k] for k in sorted(tp_keys, key=lambda x: (x[0], str(x[2])))],
        "severity_mismatches": mismatches,
        "fp_by_rule": dict(Counter(k[0] for k in fp_keys)),
        "fn_by_rule": dict(Counter(k[0] for k in fn_keys)),
    }


def _pct(part, whole):
    return (100.0 * part / whole) if whole else 0.0


def _fmt_metric(v):
    return "n/a" if v is None else f"{v:.3f}"


def coverage_banner(meta):
    """Honest parse-coverage line; flags an unrecognized format instead of hiding it."""
    total = meta["total_lines"]
    parsed, unparsed = meta["parsed"], meta["unparsed"]
    unrec = _pct(unparsed, total)
    line = (f"format={meta['format']!r}  parsed={parsed}/{total}  "
            f"unparsed={unparsed} ({unrec:.1f}% unrecognized)")
    honest = None
    if parsed == 0:
        honest = ("UNRECOGNIZED FORMAT — 0 lines parsed. The detector was given "
                  "nothing it could read; this is NOT an all-clear.")
    return line, honest, unrec


def render_report(log_path, labels_obj, meta, sc):
    """Produce the markdown validation report (also used as the filled example)."""
    cov_line, honest, unrec = coverage_banner(meta)
    L = []
    L.append(f"# Detection Validation Report — `{Path(log_path).name}`")
    L.append("")
    L.append(f"- **Log file:** `{log_path}`")
    L.append(f"- **Labels:** ground-truth `expected` findings, hand-labeled")
    if labels_obj.get("note"):
        L.append(f"- **Label note:** {labels_obj['note']}")
    L.append(f"- **Detector:** frozen `anomaly_detector.py` "
             f"(sha256 43f0560f…312d05); severity is rule-owned, never guessed here")
    L.append("")
    L.append("## Parse coverage")
    L.append("")
    L.append(f"```\n{cov_line}\n```")
    if honest:
        L.append("")
        L.append(f"> ⚠️ **{honest}**")
    if meta["unparsed"] and meta.get("unparsed_examples"):
        L.append("")
        L.append("Unparsed examples (verbatim):")
        L.append("```")
        for ex in meta["unparsed_examples"][:3]:
            L.append(str(ex))
        L.append("```")
    L.append("")
    L.append("## Scorecard")
    L.append("")
    L.append("| metric | value |")
    L.append("|---|---|")
    L.append(f"| true positives | {sc['tp']} |")
    L.append(f"| false positives | {sc['fp']} |")
    L.append(f"| false negatives (missed) | {sc['fn']} |")
    L.append(f"| precision | {_fmt_metric(sc['precision'])} |")
    L.append(f"| recall | {_fmt_metric(sc['recall'])} |")
    L.append(f"| F1 | {_fmt_metric(sc['f1'])} |")
    if sc["precision"] is None:
        L.append("")
        L.append("> precision = **n/a** — the detector produced no findings to be "
                 "right or wrong about.")
    L.append("")
    L.append("## False positives (detector fired, not labeled)")
    L.append("")
    if sc["false_positives"]:
        for f in sc["false_positives"]:
            L.append(f"- `{f['rule_id']}` **{f['severity']}** `{f['entity']}` — {f['evidence']}")
    else:
        L.append("_None._")
    L.append("")
    L.append("## Missed detections / false negatives (labeled, detector silent)")
    L.append("")
    if sc["false_negatives"]:
        for f in sc["false_negatives"]:
            ln = f.get("evidence_lines")
            where = f" (lines {ln})" if ln else ""
            note = f" — {f['note']}" if f.get("note") else ""
            L.append(f"- `{f['rule_id']}` **{f['severity']}** `{f['entity']}`{where}{note}")
    else:
        L.append("_None._")
    L.append("")
    L.append("## Severity mismatches (right attack + entity, wrong severity)")
    L.append("")
    if sc["severity_mismatches"]:
        for m in sc["severity_mismatches"]:
            L.append(f"- `{m['rule_id']}` `{m['entity']}` — detector said "
                     f"**{m['detector_severity']}**, labeled **{m['labeled_severity']}**")
        L.append("")
        L.append("> Severity is rule-owned. A mismatch means the rule and the analyst "
                 "disagree on criticality — a finding to review, not a harness bug.")
    else:
        L.append("_None._")
    L.append("")
    L.append("## Confirmed detections (true positives)")
    L.append("")
    if sc["true_positives"]:
        for f in sc["true_positives"]:
            L.append(f"- `{f['rule_id']}` **{f['severity']}** `{f['entity']}` — {f['evidence']}")
    else:
        L.append("_None._")
    L.append("")
    return "\n".join(L)


def print_console(log_path, meta, sc):
    cov_line, honest, _ = coverage_banner(meta)
    print("=" * 78)
    print(f"REAL-LOG VALIDATION — {Path(log_path).name}")
    print("=" * 78)
    print(f"  parse coverage : {cov_line}")
    if honest:
        print(f"  !! {honest}")
    print(f"  true positives : {sc['tp']}")
    print(f"  false positives: {sc['fp']}   {sc['fp_by_rule'] or ''}")
    print(f"  false negatives: {sc['fn']}   {sc['fn_by_rule'] or ''}")
    print(f"  precision      : {_fmt_metric(sc['precision'])}")
    print(f"  recall         : {_fmt_metric(sc['recall'])}")
    print(f"  f1             : {_fmt_metric(sc['f1'])}")
    if sc["false_positives"]:
        print("\n  FALSE POSITIVES (detector fired, not labeled):")
        for f in sc["false_positives"]:
            print(f"    + {f['rule_id']:18} {f['severity']:8} {f['entity']}  | {f['evidence']}")
    if sc["false_negatives"]:
        print("\n  MISSED DETECTIONS (labeled, detector silent):")
        for f in sc["false_negatives"]:
            print(f"    - {f['rule_id']:18} {f['severity']:8} {f['entity']}  {f.get('note','')}")
    if sc["severity_mismatches"]:
        print("\n  SEVERITY MISMATCHES (right attack, wrong severity):")
        for m in sc["severity_mismatches"]:
            print(f"    ~ {m['rule_id']:18} {m['entity']}  detector={m['detector_severity']} "
                  f"labeled={m['labeled_severity']}")


# ---------------------------------------------------------------------------
# Self-test: proves the scorer + report render FP / FN / severity-mismatch
# without fabricating any real metric. Uses obviously-synthetic data.
# ---------------------------------------------------------------------------
def selftest():
    findings = [
        {"rule_id": "auth_bruteforce", "severity": "high", "entity": "10.0.0.1",
         "evidence": "synthetic", "summary": ""},   # TP
        {"rule_id": "port_scan", "severity": "medium", "entity": "10.0.0.9",
         "evidence": "synthetic", "summary": ""},    # FP (not labeled)
        {"rule_id": "error_rate_spike", "severity": "low", "entity": "hostA",
         "evidence": "synthetic", "summary": ""},     # severity mismatch vs label
    ]
    labels = [
        {"rule_id": "auth_bruteforce", "severity": "high", "entity": "10.0.0.1",
         "evidence_lines": [1, 5], "note": "synthetic TP"},
        {"rule_id": "data_exfil", "severity": "critical", "entity": "10.0.0.2",
         "evidence_lines": [9], "note": "synthetic FN"},                       # FN
        {"rule_id": "error_rate_spike", "severity": "high", "entity": "hostA",
         "evidence_lines": [12], "note": "synthetic severity mismatch"},        # mismatch
    ]
    sc = score(findings, labels)
    ok = True
    checks = [
        ("tp == 1", sc["tp"] == 1),
        ("fp == 2", sc["fp"] == 2),          # port_scan + error_rate_spike/low
        ("fn == 2", sc["fn"] == 2),          # data_exfil + error_rate_spike/high
        ("one severity mismatch", len(sc["severity_mismatches"]) == 1),
        ("mismatch is error_rate_spike",
         sc["severity_mismatches"] and sc["severity_mismatches"][0]["rule_id"] == "error_rate_spike"),
        ("precision == 1/3", abs(sc["precision"] - 1/3) < 1e-9),
        ("recall == 1/3", abs(sc["recall"] - 1/3) < 1e-9),
        ("f1 computed", sc["f1"] is not None),
    ]
    print("SELFTEST (synthetic data — proves FP/FN/severity rendering):")
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    # n/a path: no findings at all -> precision n/a
    empty = score([], labels)
    na_ok = empty["precision"] is None and empty["recall"] == 0.0
    print(f"  [{'PASS' if na_ok else 'FAIL'}] empty findings -> precision n/a, recall 0.0")
    ok = ok and na_ok
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Score the FROZEN detector on a real log vs ground-truth labels")
    ap.add_argument("--log", help="path to the real log file")
    ap.add_argument("--labels", help="path to the ground-truth label JSON")
    ap.add_argument("--report", help="write a markdown report to this path")
    ap.add_argument("--json", action="store_true", help="print the scorecard as JSON")
    ap.add_argument("--selftest", action="store_true", help="prove scorer/report on synthetic data")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.log or not args.labels:
        ap.error("--log and --labels are required (or use --selftest)")

    labels_obj, labels = _load_labels(args.labels)
    findings, meta = analyze(args.log)
    sc = score(findings, labels)

    if args.json:
        out = {"log": args.log, "coverage": meta,
               "precision": sc["precision"], "recall": sc["recall"], "f1": sc["f1"],
               "tp": sc["tp"], "fp": sc["fp"], "fn": sc["fn"],
               "false_positives": sc["false_positives"],
               "false_negatives": sc["false_negatives"],
               "severity_mismatches": sc["severity_mismatches"]}
        print(json.dumps(out, indent=2, default=str))
    else:
        print_console(args.log, meta, sc)

    if args.report:
        Path(args.report).write_text(render_report(args.log, labels_obj, meta, sc))
        print(f"\n  report written: {args.report}")

    # Exit non-zero only on a hard failure (unreadable format with labels present),
    # so this can gate CI without conflating "detector disagrees" with "harness broke".
    _, honest, _ = coverage_banner(meta)
    if honest and labels:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
