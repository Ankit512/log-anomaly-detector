#!/usr/bin/env python3
"""
rule_context.py — derive a readable rule predicate and an event timeline for
each finding, from data the detector already produced.

Both fields answer the same question a reviewer asks of any automated finding:
*why did this fire, and in what order did it happen?* Neither needs a model
call — the predicate is the rule restated from its own constants, and the
timeline is the supporting log records put back in order.

Deriving the predicate from the live constants (rather than hardcoding prose)
means retuning a threshold in anomaly_detector.py updates what the report says
about itself. A predicate that drifts from the rule it describes is worse than
no predicate at all.

anomaly_detector.py is the validated core and is never modified; this module
only reads its constants, regexes, and output.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from anomaly_detector import (  # noqa: E402
    AUTH_FAIL_RE,
    AUTH_OK_RE,
    BRUTE_FORCE_MIN_FAILURES,
    BRUTE_FORCE_WINDOW_SEC,
    COMPROMISE_SUCCESS_WINDOW_SEC,
    DISK_CRIT_PCT,
    DISK_WARN_PCT,
    ERROR_BURST_MIN,
    ERROR_BURST_WINDOW_SEC,
    SUSPICIOUS_PORTS,
)

# "7x auth failed for 'admin' from 1.2.3.4 (lines 842-848)" / "lines 5-11"
LINE_RANGE_RE = re.compile(r"lines (\d+)-(\d+)")
BREAK_IN_RE = re.compile(r"POSSIBLE BREAK-IN ATTEMPT")


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------

def predicate_for(anomaly):
    """Restate the rule that fired, in its own current constants.

    Returns "" for a type with no registered predicate, so a caller can simply
    omit the field rather than print something invented.
    """
    atype = anomaly.get("type")
    ents = anomaly.get("entities", {})

    if atype == "auth_bruteforce_success":
        return (f"failures_from(ip) >= {BRUTE_FORCE_MIN_FAILURES}\n"
                f"  AND auth_success(same ip) <= {COMPROMISE_SUCCESS_WINDOW_SEC}s "
                f"after the last failure\n"
                f"-> severity = critical")

    if atype == "auth_bruteforce":
        # Pad against the rendered line, not a guessed width, so the arrows stay
        # aligned when the thresholds are retuned.
        cond = (f"  AND peak_within({BRUTE_FORCE_WINDOW_SEC}s) "
                f">= {BRUTE_FORCE_MIN_FAILURES}")
        alt = "  otherwise"
        width = max(len(cond), len(alt))
        return (f"failures_from(ip) >= {BRUTE_FORCE_MIN_FAILURES}\n"
                f"{cond.ljust(width)}  -> high\n"
                f"{alt.ljust(width)}  -> medium\n"
                f"\nobserved: {ents.get('failures', '?')} failures")

    if atype == "suspicious_outbound":
        port = ents.get("port")
        note = SUSPICIOUS_PORTS.get(port, "known-bad port")
        return (f"dest_port in SUSPICIOUS_PORTS\n"
                f"  # {port} -> {note}\n"
                f"-> severity = high  (blocked == true does not downgrade)")

    if atype == "critical_service_event":
        return ("level == CRIT\n"
                "  AND msg contains ('exhaust' | 'pool' | 'down')  -> critical\n"
                "  else                                            -> high")

    if atype == "disk_pressure":
        pct = ents.get("pct")
        observed = f"\n\nobserved: {pct}%" if pct is not None else ""
        return (f"disk_pct >= {DISK_WARN_PCT}  ->  medium\n"
                f"disk_pct >= {DISK_CRIT_PCT}  ->  high{observed}")

    if atype == "error_rate_spike":
        return (f"count(level in [ERROR, CRIT]) within {ERROR_BURST_WINDOW_SEC}s "
                f">= {ERROR_BURST_MIN}\n"
                f"-> severity = medium\n"
                f"\nobserved: {anomaly.get('entities', {}).get('count', '?')} events")

    if atype == "possible_break_in":
        return ("sshd could not reverse-resolve the client address\n"
                "  (POSSIBLE BREAK-IN ATTEMPT), grouped per source IP\n"
                "-> severity = medium")

    return ""


# ---------------------------------------------------------------------------
# Timelines
# ---------------------------------------------------------------------------

def _event(record, label):
    ts = record.get("ts")
    return {
        "t": ts.strftime("%H:%M:%S") if ts else "",
        "ts": ts.isoformat() if ts else None,
        "label": label,
        "line": record.get("n"),
    }


def _auth_events(records, ip, want_success):
    """First failure, threshold crossing, final failure, and the success."""
    fails, oks = [], []
    for r in records:
        if not r.get("ts"):
            continue
        m = AUTH_FAIL_RE.search(r.get("msg", ""))
        if m and m.group("ip") == ip:
            fails.append((r, m.group("user")))
            continue
        m = AUTH_OK_RE.search(r.get("msg", ""))
        if m and m.group("ip") == ip:
            oks.append((r, m.group("user")))

    fails.sort(key=lambda pair: pair[0]["ts"])
    if not fails:
        return []

    total = len(fails)
    out = [_event(fails[0][0], f"First failed login for '{fails[0][1]}' from {ip}")]

    if total >= BRUTE_FORCE_MIN_FAILURES:
        crossing = fails[BRUTE_FORCE_MIN_FAILURES - 1][0]
        out.append(_event(
            crossing,
            f"Failure {BRUTE_FORCE_MIN_FAILURES} — brute-force threshold "
            f"({BRUTE_FORCE_MIN_FAILURES} / {BRUTE_FORCE_WINDOW_SEC}s) crossed"))

    if total > BRUTE_FORCE_MIN_FAILURES:
        out.append(_event(fails[-1][0], f"Final failure — {total} attempts from this source"))

    if want_success:
        last_fail_ts = fails[-1][0]["ts"]
        for r, user in sorted(oks, key=lambda pair: pair[0]["ts"]):
            gap = (r["ts"] - last_fail_ts).total_seconds()
            if 0 <= gap <= COMPROMISE_SUCCESS_WINDOW_SEC:
                out.append(_event(
                    r, f"Successful login for '{user}', same source, {int(gap)}s "
                       f"after the last failure"))
                break
    return out


def timeline_for(anomaly, records, by_raw, by_line):
    """Ordered supporting events for one finding. Empty when none can be tied."""
    atype = anomaly.get("type")
    ents = anomaly.get("entities", {})
    evidence = anomaly.get("evidence", "")

    if atype in ("auth_bruteforce", "auth_bruteforce_success"):
        return _auth_events(records, ents.get("ip"), atype.endswith("_success"))

    if atype == "error_rate_spike":
        m = LINE_RANGE_RE.search(evidence)
        if not m:
            return []
        first, last = by_line.get(int(m.group(1))), by_line.get(int(m.group(2)))
        out = []
        if first:
            out.append(_event(first, "Burst window opens"))
        if last and last is not first:
            out.append(_event(
                last, f"Event {ents.get('count', '?')} closes the "
                      f"{ERROR_BURST_WINDOW_SEC}s window"))
        return out

    if atype == "possible_break_in":
        ip = ents.get("ip")
        hits = [r for r in records
                if BREAK_IN_RE.search(r.get("raw", "")) and ip and ip in r.get("raw", "")]
        hits.sort(key=lambda r: (r.get("ts") is None, r.get("ts"), r.get("n")))
        if not hits:
            return []
        out = [_event(hits[0], f"First reverse-DNS mismatch flagged from {ip}")]
        if len(hits) > 1:
            out.append(_event(hits[-1], f"Mismatch {len(hits)} from the same source"))
        return out

    # Single-record rules: the detector stored the raw line as its evidence.
    record = by_raw.get(evidence)
    if record is None:
        return []

    if atype == "suspicious_outbound":
        state = "blocked" if ents.get("blocked") else "ALLOWED"
        return [_event(record, f"{ents.get('host', 'host')} outbound to "
                               f"{ents.get('dest_ip')}:{ents.get('port')} — {state}")]

    if atype == "disk_pressure":
        return [_event(record, f"Disk at {ents.get('pct')}% on {ents.get('host')}")]

    if atype == "critical_service_event":
        return [_event(record, record.get("msg", "")[:110])]

    return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def enrich(anomalies, records):
    """Attach `predicate` and `timeline` to each anomaly, in place."""
    by_raw, by_line = {}, {}
    for r in records:
        by_raw.setdefault(r.get("raw"), r)
        by_line.setdefault(r.get("n"), r)

    for a in anomalies:
        a["predicate"] = predicate_for(a)
        a["timeline"] = timeline_for(a, records, by_raw, by_line)
    return anomalies
