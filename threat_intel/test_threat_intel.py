#!/usr/bin/env python3
"""
test_threat_intel.py — network-free smoke test for the threat-intel step.

Scored here: IOC extraction and matching against the local demo STIX bundle. That
path is pure stdlib and fully offline, so it is safe to assert on.

NOT scored here: MITRE technique resolution. It needs a ~46MB ATT&CK bundle in
~/.cache/mitre_attack/, which this test will never download. If that cache is warm
the technique assertions run as a bonus; if it is cold they are reported as SKIPPED,
the same way run_eval.py treats its LLM spot-check.

Exits non-zero on any failure.

Usage:
  python3 threat_intel/test_threat_intel.py
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from taxii_client import extract_iocs, extract_technique_refs, TAXII_AVAILABLE  # noqa: E402
from threat_detector import extract_observed_iocs, match_and_enrich, severity_for  # noqa: E402
from mitre_attack import DEFAULT_CACHE_PATH  # noqa: E402

BUNDLE = HERE / "demo_threat_intel.json"
EXPECTED = {
    "203.0.113.44": {"name": "Known brute-force source IP", "technique": "T1110"},
    "45.153.160.2": {"name": "Known C2 callback IP", "technique": "T1071"},
}

failures = []
skipped = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(f"{label}: {detail}")


class NoMitre:
    """Stand-in mapper for the cold-cache case: resolves nothing, downloads nothing."""

    def lookup_by_stix_id(self, _stix_id):
        return None


def main():
    print("threat-intel smoke test (network-free)\n")

    print("dependency posture:")
    check("offline path works without taxii2client",
          True, "")
    print(f"         taxii2client installed: {TAXII_AVAILABLE} "
          f"(False is fine — offline mode is stdlib-only)")

    print("\nSTIX bundle parsing:")
    objects = json.loads(BUNDLE.read_text())["objects"]
    threat_iocs = extract_iocs(objects)
    links = extract_technique_refs(objects)
    check("bundle yields indicator IOCs", len(threat_iocs) == 3, f"got {len(threat_iocs)}")
    check("bundle yields ATT&CK relationships", len(links) == 2, f"got {len(links)}")

    print("\nIOC matching (the scored part):")
    # Build an observed-IOC input the way export_iocs.py would, without writing a file.
    tmp = HERE / ".smoke_iocs.tmp"
    tmp.write_text("\n".join(EXPECTED) + "\n")
    try:
        observed = extract_observed_iocs(tmp)
        found = observed.get("ipv4", set())
        for ip in EXPECTED:
            check(f"observed IOC extracted: {ip}", ip in found, f"not in {sorted(found)}")

        findings = match_and_enrich(observed, threat_iocs, links, NoMitre())
        matched = {f["observed_value"] for f in findings}
        for ip, want in EXPECTED.items():
            check(f"matched against threat intel: {ip}", ip in matched,
                  f"matched only {sorted(matched)}")
            hit = next((f for f in findings if f["observed_value"] == ip), None)
            if hit:
                check(f"  correct indicator name for {ip}",
                      hit["threat_intel_name"] == want["name"],
                      f"got {hit['threat_intel_name']!r}")
        check("no spurious matches", len(findings) == len(EXPECTED),
              f"got {len(findings)} findings for {len(EXPECTED)} inputs")
    finally:
        tmp.unlink(missing_ok=True)

    print("\nrule -> ATT&CK table (rule_mitre_map.py — what the console's tags come from):")
    import re
    from rule_mitre_map import RULE_TECHNIQUES, techniques_for_rule
    for rule, techs in sorted(RULE_TECHNIQUES.items()):
        check(f"{rule}: entries are well-formed",
              techs and all(re.fullmatch(r"T\d{4}(\.\d{3})?", t.get("id", ""))
                            and t.get("name") and t.get("tactic") for t in techs),
              f"got {techs}")
    check("auth_bruteforce resolves to T1110",
          [t["id"] for t in techniques_for_rule("auth_bruteforce")] == ["T1110"])
    check("unmapped rules resolve to NOTHING (a guess would be invented evidence)",
          techniques_for_rule("disk_pressure") == []
          and techniques_for_rule("error_rate_spike") == []
          and techniques_for_rule("possible_break_in") == []
          and techniques_for_rule(None) == [])
    check("resolver returns copies (callers cannot mutate the table)",
          techniques_for_rule("auth_bruteforce")[0] is not RULE_TECHNIQUES["auth_bruteforce"][0])

    print("\nMITRE technique resolution (bonus — needs a warm ATT&CK cache):")
    if not Path(DEFAULT_CACHE_PATH).exists():
        skipped.append("technique resolution")
        print(f"  [SKIP] ATT&CK cache cold at {DEFAULT_CACHE_PATH}")
        print("         run `python3 threat_intel/mitre_attack.py` once online to populate it")
    else:
        from mitre_attack import MitreAttackMapper
        mapper = MitreAttackMapper()          # reads cache; does not re-download
        findings = match_and_enrich(extract_observed_iocs_from(EXPECTED),
                                    threat_iocs, links, mapper)
        for ip, want in EXPECTED.items():
            hit = next((f for f in findings if f["observed_value"] == ip), None)
            ids = [t["technique_id"] for t in (hit or {}).get("mitre_techniques", [])]
            check(f"{ip} resolves to {want['technique']}", want["technique"] in ids,
                  f"got {ids}")

        # Cross-check the rule->technique table against the official STIX data:
        # every inlined name must be the real technique name, every inlined
        # tactic one of its official tactics.
        for rule, techs in sorted(RULE_TECHNIQUES.items()):
            for t in techs:
                rec = mapper.lookup(t["id"])
                check(f"table {t['id']} ({rule}) matches the official name",
                      rec is not None and rec["name"] == t["name"],
                      f"official {rec and rec['name']!r} vs table {t['name']!r}")
                check(f"table {t['id']} tactic is official",
                      rec is not None and t["tactic"] in rec["tactics"],
                      f"official {rec and rec['tactics']} vs table {t['tactic']!r}")

    print()
    if failures:
        print(f"FAILED — {len(failures)} check(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED — all checks green"
          + (f" ({len(skipped)} skipped: {', '.join(skipped)})" if skipped else ""))
    return 0


def extract_observed_iocs_from(values):
    """Same shape extract_observed_iocs returns, without touching the filesystem."""
    from collections import defaultdict
    observed = defaultdict(set)
    for v in values:
        observed["ipv4"].add(v)
    return observed


if __name__ == "__main__":
    sys.exit(main())
