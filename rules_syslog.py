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

    Returns (canonical_msg, kind, source, ip) where kind is "auth_fail", "auth_ok"
    or None, and source names the exact sshd phrasing that matched — which the
    dedupe pass needs to tell an attempt's anchor line from its companions.
    Returns the message unchanged when no rule applies.
    """
    m = FAILED_PASSWORD.search(msg)
    if m:
        return (CANON_FAIL.format(user=m.group("user"), ip=m.group("ip")),
                "auth_fail", "failed_password", m.group("ip"))

    m = INVALID_USER.search(msg)
    if m:
        return (CANON_FAIL.format(user=m.group("user"), ip=m.group("ip")),
                "auth_fail", "invalid_user", m.group("ip"))

    m = PAM_FAILURE.search(msg)
    if m:
        user = m.group("user") or "unknown"
        return (CANON_FAIL.format(user=user, ip=m.group("ip")),
                "auth_fail", "pam_failure", m.group("ip"))

    m = ACCEPTED_PASSWORD.search(msg)
    if m:
        return (CANON_OK.format(user=m.group("user"), ip=m.group("ip")),
                "auth_ok", "accepted_password", m.group("ip"))

    return msg, None, None, None


def canonicalize(records):
    """Rewrite msg in place-safe copies. `raw` is never touched.

    Returns (records, counts) where counts reports how many of each kind were
    translated — so a caller can tell whether the vocabulary layer did anything.
    """
    out = []
    counts = {"auth_fail": 0, "auth_ok": 0, "untouched": 0}
    for r in records:
        canon, kind, source, ip = canonical_form(r["msg"])
        copy = dict(r)
        if kind:
            copy["msg"] = canon
            copy["original_msg"] = r["msg"]
            copy["auth_source"] = source
            copy["auth_ip"] = ip
            counts[kind] += 1
        else:
            counts["untouched"] += 1
        out.append(copy)
    return out, counts


# Companion lines sshd emits for an attempt that also produced a Failed password.
COMPANION_SOURCES = ("invalid_user", "pam_failure")


def dedupe_auth_attempts(records):
    """Variant A: collapse sshd's multiple lines per attempt down to one event.

    sshd logs one line per protocol event, not per attempt: an "Invalid user" line,
    a pam_unix "authentication failure" line, and a "Failed password" line can all
    describe a single guess. Counting all three inflates failure counts ~2x and
    pushes IPs over the brute-force threshold on attempts they never made.

    The rule is structural, not time-based. Every attempt that reached password
    verification is anchored by exactly one "Failed password" line, and all lines of
    one connection share a pid. So for a given (ip, pid):

      - keep EVERY Failed-password line — never merge two of them, so a connection
        that retried 5 times still counts as 5 attempts;
      - drop the Invalid-user and PAM lines, which are that same attempt announcing
        itself earlier in the connection;
      - if a connection has NO Failed-password line, keep its lines untouched —
        nothing would be left to represent it otherwise.

    Formats without Failed-password lines at all (e.g. bare PAM syslog) are
    unaffected by construction. Returns (records, dropped_count).
    """
    anchored = {(r.get("auth_ip"), r.get("pid")) for r in records
                if r.get("auth_source") == "failed_password"}

    kept = []
    dropped = 0
    for r in records:
        if (r.get("auth_source") in COMPANION_SOURCES
                and (r.get("auth_ip"), r.get("pid")) in anchored):
            dropped += 1
            continue
        kept.append(r)
    return kept, dropped


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
