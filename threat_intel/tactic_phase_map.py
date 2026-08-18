#!/usr/bin/env python3
"""
tactic_phase_map.py — MITRE ATT&CK tactic -> plain-language kill-chain phase.

Companion to rule_mitre_map.py and governed by the same rule: this is a
DERIVED, read-only display grouping for the SOC Overview's "attacker status"
column. It never changes, suppresses, escalates, or reorders a finding's
severity or verdict — rules own severity, and a phase label is not a verdict.

The four phases, in attack-progression order:

    Planning / Probing    Reconnaissance, Resource Development
    Breaking In           Initial Access, Execution
    Spreading Inside      Persistence, Privilege Escalation, Defense Evasion,
                          Credential Access, Discovery, Lateral Movement,
                          Collection
    Damaging / Stealing   Command and Control, Exfiltration, Impact

A finding whose tactics include several phases is labeled with the DEEPEST
one (furthest along the progression) — deterministic, and it errs toward
telling the reviewer how far things may have gone. A tactic not in the table,
or a finding with no mapped tactic at all, yields "" — blank, never guessed.
"""

# Progression order matters: index = how far along the attack is.
PHASES = ["Planning / Probing", "Breaking In", "Spreading Inside", "Damaging / Stealing"]

TACTIC_PHASE = {
    "Reconnaissance": "Planning / Probing",
    "Resource Development": "Planning / Probing",
    "Initial Access": "Breaking In",
    "Execution": "Breaking In",
    "Persistence": "Spreading Inside",
    "Privilege Escalation": "Spreading Inside",
    "Defense Evasion": "Spreading Inside",
    "Credential Access": "Spreading Inside",
    "Discovery": "Spreading Inside",
    "Lateral Movement": "Spreading Inside",
    "Collection": "Spreading Inside",
    "Command and Control": "Damaging / Stealing",
    "Exfiltration": "Damaging / Stealing",
    "Impact": "Damaging / Stealing",
}


def phase_for_tactics(tactics):
    """The deepest kill-chain phase among a finding's tactics; "" if none map."""
    hits = [TACTIC_PHASE[t] for t in (tactics or []) if t in TACTIC_PHASE]
    if not hits:
        return ""
    return max(hits, key=PHASES.index)
