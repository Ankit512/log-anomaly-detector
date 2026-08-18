#!/usr/bin/env python3
"""
rule_mitre_map.py — the explicit rule_id -> MITRE ATT&CK technique table.

This file is the SOURCE OF TRUTH for which detector rule maps to which ATT&CK
technique. It lives in threat_intel/ deliberately: the detector never knows
about ATT&CK, and the console never hardcodes a mapping — both sides come here.

The mapping is a derived, read-only annotation. It never changes, suppresses,
escalates, or reorders a finding's severity or verdict — rules own severity.

Entries carry the technique name and tactic INLINE so resolution is fully
offline: no ATT&CK bundle download, no warm cache required. When the cache in
~/.cache/mitre_attack/ happens to be warm, test_threat_intel.py cross-checks
these entries against the official STIX data as a bonus.

A rule with no entry here gets NO tag. That is a statement, not an omission:
ops signals (disk pressure, error bursts, service crashes) are not attacker
behaviours, and guessing a technique would put invented evidence on an audit
surface. The same goes for possible_break_in: sshd's reverse-DNS warning fires
on probing whose method the rule does not verify, so no technique is claimed.
"""

# rule_id (the detector anomaly "type", carried as the report's rule_id)
#   -> list of {"id", "name", "tactic"}; [] / absent -> no tag, never guessed.
RULE_TECHNIQUES = {
    # >=5 failed logins from one source IP: password guessing, by definition.
    "auth_bruteforce": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    # The guessing worked: brute force plus use of the now-valid account.
    "auth_bruteforce_success": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    # Outbound to a known C2/backdoor port (4444, 31337, ...) — exactly T1571.
    "suspicious_outbound": [
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    ],
    # Deliberately unmapped — not attacker techniques, or method unverified:
    #   critical_service_event, disk_pressure, error_rate_spike, possible_break_in
}


def techniques_for_rule(rule_id):
    """Resolve a finding's rule_id to its ATT&CK techniques. Unknown -> []."""
    return [dict(t) for t in RULE_TECHNIQUES.get(rule_id or "", [])]
