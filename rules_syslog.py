#!/usr/bin/env python3
"""
rules_syslog.py — vocabulary translation for real sshd/PAM phrasing (Phase 3).

anomaly_detector.py (v1) owns the correlation logic — per-IP failure clustering,
the failure-then-success compromise check, error bursts — and it is the validated
original, never modified. But its message regexes only understand the synthetic
phrasing "auth failed for user 'x' from IP". Real sshd says something else
entirely, so on real logs those rules never fire.

This module is the translator. It rewrites the `msg` field of normalized records
into v1's canonical phrasing, so v1's own regexes match and its correlation runs
untouched. The `raw` field always keeps the real log line, so every piece of
evidence a human reads is the genuine text, never the rewrite.

It also emits anomalies for events v1 has no rule for (sshd's break-in warning),
rather than mislabelling them as something v1 does understand.

Handled phrasings:
  Failed password for [invalid user] X from IP [port N]  -> auth failure
  Invalid user X from IP                                 -> auth failure
  authentication failure; ... rhost=IP [user=X]          -> auth failure
  Accepted password for X from IP                        -> auth success
  ... POSSIBLE BREAK-IN ATTEMPT (with IP)                -> own anomaly

No third-party dependencies. anomaly_detector.py is never modified.
"""

import re
from collections import defaultdict

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

FAILED_PASSWORD = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP)
INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from " + IP)
PAM_FAILURE = re.compile(r"authentication failure;.*?rhost=" + IP + r"(?:\s+user=(?P<user>\S+))?")
ACCEPTED_PASSWORD = re.compile(r"Accepted password for (?P<user>\S+) from " + IP)
BREAK_IN = re.compile(r"POSSIBLE BREAK-IN ATTEMPT")
BRACKETED_IP = re.compile(r"\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]")

# v1's canonical phrasing. AUTH_FAIL_RE/AUTH_OK_RE require the quotes.
CANON_FAIL = "auth failed for user '{user}' from {ip}"
CANON_OK = "auth success for user '{user}' from {ip}"


def canonical_form(msg):
    """Translate one real message into v1's phrasing.

    Returns (canonical_msg, kind) where kind is "auth_fail", "auth_ok" or None.
    Returns the message unchanged when no rule applies.
    """
    m = FAILED_PASSWORD.search(msg) or INVALID_USER.search(msg)
    if m:
        return CANON_FAIL.format(user=m.group("user"), ip=m.group("ip")), "auth_fail"

    m = PAM_FAILURE.search(msg)
    if m:
        user = m.group("user") or "unknown"
        return CANON_FAIL.format(user=user, ip=m.group("ip")), "auth_fail"

    m = ACCEPTED_PASSWORD.search(msg)
    if m:
        return CANON_OK.format(user=m.group("user"), ip=m.group("ip")), "auth_ok"

    return msg, None


def canonicalize(records):
    """Rewrite msg in place-safe copies. `raw` is never touched.

    Returns (records, counts) where counts reports how many of each kind were
    translated — so a caller can tell whether the vocabulary layer did anything.
    """
    out = []
    counts = {"auth_fail": 0, "auth_ok": 0, "untouched": 0}
    for r in records:
        canon, kind = canonical_form(r["msg"])
        copy = dict(r)
        if kind:
            copy["msg"] = canon
            copy["original_msg"] = r["msg"]
            counts[kind] += 1
        else:
            counts["untouched"] += 1
        out.append(copy)
    return out, counts


def detect_break_in_attempts(records):
    """sshd's reverse-DNS mismatch warning. v1 has no rule for this shape.

    Aggregated per source IP — 85 individual lines would drown the report, and
    the analyst question is "which host is probing us", not "which line".
    """
    by_ip = defaultdict(list)
    for r in records:
        text = r.get("original_msg") or r["msg"]
        if not BREAK_IN.search(text) and not BREAK_IN.search(r["raw"]):
            continue
        m = BRACKETED_IP.search(r["raw"])
        if m:
            by_ip[m.group("ip")].append(r)

    anomalies = []
    for ip, hits in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
        first, last = hits[0]["n"], hits[-1]["n"]
        anomalies.append({
            "severity": "medium",
            "type": "possible_break_in",
            "summary": f"{len(hits)}x reverse-DNS mismatch flagged as POSSIBLE BREAK-IN from {ip}",
            "evidence": hits[0]["raw"],
            "rationale": (
                "sshd could not reverse-resolve the client address consistently, which it reports "
                "as a possible break-in attempt. Common with misconfigured DNS, but repeated "
                f"occurrences from one source ({len(hits)} here, lines {first}-{last}) are typical "
                "of scanning infrastructure."
            ),
            "entities": {"ip": ip, "occurrences": len(hits)},
        })
    return anomalies


def detect_extra(records):
    """Anomalies for syslog-specific events v1 has no rule for."""
    return detect_break_in_attempts(records)
