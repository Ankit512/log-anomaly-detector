#!/usr/bin/env python3
"""
run_eval.py — score the deterministic detector against the labeled corpus.

The corpus injects known attacks into small log files, so ground truth is exact
and repeatable. This is the regression backbone: a change that improves one rule
and quietly breaks another shows up here as a failed case, not as a surprise in
production output.

Each case runs the FULL deterministic path — normalize (envelope) -> rules_syslog
(vocabulary + dedupe) -> anomaly_detector.detect (correlation) — so format
variants exercise the whole chain, not just the correlator.

What is scored: the deterministic detector only.
What is not scored: the LLM half. It is non-deterministic, so --llm runs a single
spot-check that the model returns schema-valid output and reports it separately.

Usage:
  python3 run_eval.py              # score the detector
  python3 run_eval.py --llm        # also spot-check the model (needs Ollama)
  python3 run_eval.py --verbose    # per-case finding detail
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
AUTH_SOURCES = ("failed_password", "invalid_user", "pam_failure")


def entity_of(anomaly):
    """The principal a finding is about: IP for auth/network, host for resources."""
    ents = anomaly.get("entities", {})
    for key in ("ip", "dest_ip", "host"):
        if ents.get(key):
            return str(ents[key])
    return None


def analyze(path):
    """Run one file through the full deterministic path. Returns (findings, meta)."""
    records, stats = normalize.load(path)
    extra = []
    auth_events = 0
    if stats["format"] == "rfc3164":
        records, _ = rules_syslog.canonicalize(records)
        extra = rules_syslog.detect_extra(records)
        records, _ = rules_syslog.dedupe_auth_attempts(records)
        auth_events = sum(1 for r in records if r.get("auth_source") in AUTH_SOURCES)
    else:
        auth_events = sum(1 for r in records
                          if rules_syslog.CANON_FAIL.split("{")[0] in r.get("msg", ""))

    anomalies = detect(records) + extra
    findings = {(a["type"], a["severity"], entity_of(a)) for a in anomalies}
    meta = {"format": stats["format"], "parsed": stats["parsed"],
            "unparsed": stats["unparsed"], "auth_events": auth_events,
            "anomalies": anomalies}
    return findings, meta


def check_assertions(case, findings, meta, all_results):
    """Assertions beyond exact-set matching. Returns a list of failure strings."""
    failures = []
    for a in case.get("assertions", []):
        kind = a["kind"]

        if kind == "severity_ceiling":
            worst = [f for f in findings if f[0] == a["type"]]
            for t, sev, _ in worst:
                if SEVERITY_RANK.get(sev, 9) < SEVERITY_RANK[a["max"]]:
                    failures.append(f"{t} rated {sev}, exceeds ceiling {a['max']}")

        elif kind == "absent_type":
            hits = [f for f in findings if f[0] == a["type"]]
            if hits:
                failures.append(f"{a['type']} must not fire, but did: {hits}")

        elif kind == "parse_stats":
            # Rejection is behaviour too: an unparseable input must report what it
            # could not read rather than crash or quietly return nothing.
            for key in ("format", "parsed", "unparsed"):
                if key in a and meta.get(key) != a[key]:
                    failures.append(f"{key} = {meta.get(key)!r}, expected {a[key]!r}")

        elif kind == "auth_event_count":
            if meta["auth_events"] != a["expected"]:
                failures.append(
                    f"auth events = {meta['auth_events']}, expected {a['expected']} "
                    f"(dedupe did not collapse companion lines as intended)")

        elif kind == "same_findings_as":
            other = all_results.get(a["case"])
            if other is None:
                failures.append(f"cannot compare: case {a['case']} not evaluated")
            elif other["findings"] != findings:
                failures.append(
                    f"findings differ from {a['case']}: "
                    f"only-here={sorted(findings - other['findings'])} "
                    f"only-there={sorted(other['findings'] - findings)}")

        else:
            failures.append(f"unknown assertion kind {kind!r}")
    return failures


def llm_spot_check(path):
    """Not scored. Does the model return schema-valid output for one chunk?"""
    import log_analyzer as la
    records, stats = normalize.load(path)
    if stats["format"] == "rfc3164":
        records, _ = rules_syslog.canonicalize(records)
    ctx = la.to_llm_context(la.dedupe_anomalies(detect(records)))
    chunk = open(path, errors="replace").readlines()
    try:
        raw = la.chat_completion(la.LLM_BASE_URL, la.LLM_API_KEY, la.LLM_MODEL,
                                 la.SYSTEM_PROMPT, la.build_user_prompt("".join(chunk), ctx))
    except Exception as e:
        return {"reached": False, "detail": str(e)[:80]}
    try:
        obj = json.loads(la.strip_fences(raw))
    except json.JSONDecodeError:
        return {"reached": True, "valid": False, "detail": "unparseable JSON"}
    return {"reached": True, "valid": la.validate_response(obj),
            "detail": f"top-level keys: {sorted(obj.keys()) if isinstance(obj, dict) else type(obj).__name__}"}


def main():
    ap = argparse.ArgumentParser(description="Score the detector against the labeled corpus")
    ap.add_argument("--manifest", default=str(HERE / "manifest.json"))
    ap.add_argument("--llm", action="store_true", help="also spot-check the model (not scored)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    cases = manifest["cases"]

    results = {}
    # First pass: evaluate every case so cross-case assertions have data.
    for case in cases:
        findings, meta = analyze(str(HERE / case["file"]))
        expected = {(e["type"], e["severity"], e["entity"]) for e in case["expected"]}
        results[case["id"]] = {"case": case, "findings": findings, "expected": expected,
                               "meta": meta}

    tp = fp = fn = 0
    fp_by_rule = Counter()
    fn_by_rule = Counter()
    passed = failed = 0
    failures_detail = []

    print("=" * 78)
    print("DETERMINISTIC DETECTOR — per-case results")
    print("=" * 78)

    for case in cases:
        r = results[case["id"]]
        findings, expected, meta = r["findings"], r["expected"], r["meta"]
        missing = expected - findings
        unexpected = findings - expected
        assert_fails = check_assertions(case, findings, meta, results)

        tp += len(expected & findings)
        fp += len(unexpected)
        fn += len(missing)
        for t, _, _ in unexpected:
            fp_by_rule[t] += 1
        for t, _, _ in missing:
            fn_by_rule[t] += 1

        ok = not missing and not unexpected and not assert_fails
        passed += ok
        failed += not ok
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {case['id']:3} {Path(case['file']).name:36} "
              f"{meta['format']:9} {len(findings)} finding(s)")

        if args.verbose and findings:
            for f in sorted(findings, key=lambda x: SEVERITY_RANK.get(x[1], 9)):
                print(f"           - {f[1]:8} {f[0]:24} {f[2]}")
        if not ok:
            detail = []
            for m in sorted(missing):
                detail.append(f"MISSING  (false negative): {m}")
            for u in sorted(unexpected):
                detail.append(f"UNEXPECTED (false positive): {u}")
            detail += [f"ASSERTION: {a}" for a in assert_fails]
            failures_detail.append((case["id"], case["description"], detail))
            for d in detail:
                print(f"           ! {d}")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print("\n" + "=" * 78)
    print("SCORECARD")
    print("=" * 78)
    print(f"  cases           : {passed} passed, {failed} failed, {len(cases)} total")
    print(f"  true positives  : {tp}")
    print(f"  false positives : {fp}   {dict(fp_by_rule) if fp_by_rule else ''}")
    print(f"  false negatives : {fn}   {dict(fn_by_rule) if fn_by_rule else ''}")
    print(f"  precision       : {precision:.3f}")
    print(f"  recall          : {recall:.3f}")
    print(f"  f1              : {f1:.3f}")

    print("\n  false positives by rule type:")
    if fp_by_rule:
        for rule, n in fp_by_rule.most_common():
            print(f"    {rule:26} {n}")
    else:
        print("    (none)")

    if args.llm:
        print("\n" + "=" * 78)
        print("LLM SPOT-CHECK — reported, NOT scored (non-deterministic)")
        print("=" * 78)
        for cid in ("P1", "P2"):
            case = results[cid]["case"]
            out = llm_spot_check(str(HERE / case["file"]))
            if not out.get("reached"):
                verdict = f"endpoint unreachable ({out['detail']})"
            else:
                verdict = f"schema-valid={out.get('valid')}  {out['detail']}"
            print(f"  {cid}: {verdict}")

    if failed:
        print("\n" + "=" * 78)
        print("FAILURES — decide per case: corpus bug, or a real detector finding?")
        print("=" * 78)
        for cid, desc, detail in failures_detail:
            print(f"\n  {cid}: {desc}")
            for d in detail:
                print(f"    {d}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
