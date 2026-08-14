# ARCHIVED PRISTINE REFERENCE — validated original anomaly_detector.py
# sha256: d1b2ae801fbc554915b74ca0bd3a67d953e8fb6b44ab6303c6e83a785b96d936
# Preserved before T4 edited the working copy. Do not modify.
#!/usr/bin/env python3
"""
anomaly_detector.py — Phase 2: deterministic + statistical anomaly detection.

Runs BEFORE the LLM. Scans raw log lines with cheap, explainable rules and
pre-flags suspicious events with reliable severities and cross-line correlation
(the things a small LLM gets wrong or inconsistent on). Output can be:
  - read on its own (JSON / console summary), or
  - fed into log_analyzer.py as pre-flagged context for the model to explain.

No model, no network, no dependencies — standard library only. Read-only.

Usage:
  python3 anomaly_detector.py --input sample-2.log --output anomalies
  python3 anomaly_detector.py --input sample-2.log            # console only
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# --- Tunable thresholds ----------------------------------------------------
BRUTE_FORCE_MIN_FAILURES = 5      # failures from one source to call it brute-force
BRUTE_FORCE_WINDOW_SEC = 120      # ...within this many seconds
COMPROMISE_SUCCESS_WINDOW_SEC = 120  # a success this soon after failures = likely compromise
ERROR_BURST_MIN = 5              # ERROR/CRIT count...
ERROR_BURST_WINDOW_SEC = 60       # ...within this window = error-rate spike
DISK_WARN_PCT = 80
DISK_CRIT_PCT = 90

# Ports commonly associated with C2 / backdoors / malware.
SUSPICIOUS_PORTS = {
    4444: "Metasploit / common reverse-shell & C2 port",
    1337: "elite/backdoor convention port",
    31337: "classic backdoor (Back Orifice) port",
    6667: "IRC — common botnet C2 channel",
    5555: "Android ADB / common backdoor port",
    9001: "Tor / C2 relay port",
}

LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<level>INFO|WARN|WARNING|ERROR|CRIT|CRITICAL|DEBUG)\s+"
    r"(?P<host>\S+)\s+(?P<msg>.*)$"
)
IP_RE = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
AUTH_FAIL_RE = re.compile(r"auth failed for user '(?P<user>[^']+)' from " + IP_RE)
AUTH_OK_RE = re.compile(r"auth success for user '(?P<user>[^']+)' from " + IP_RE)
DEST_RE = re.compile(r"to " + IP_RE + r":(?P<port>\d+)")
DISK_RE = re.compile(r"disk usage at (?P<pct>\d+)%")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def parse_ts(raw: str):
    """Parse an ISO-8601 timestamp (tolerating a trailing Z)."""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_lines(path: Path):
    """Return a list of structured records: {n, ts, level, host, msg, raw}."""
    records = []
    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            m = LINE_RE.match(raw)
            if not m:
                continue
            records.append({
                "n": n,
                "ts": parse_ts(m.group("ts")),
                "level": m.group("level").upper(),
                "host": m.group("host"),
                "msg": m.group("msg"),
                "raw": raw,
            })
    return records


def _anomaly(severity, atype, summary, evidence, rationale, entities=None):
    return {
        "severity": severity,
        "type": atype,
        "summary": summary,
        "evidence": evidence,
        "rationale": rationale,
        "entities": entities or {},
    }


def detect_auth_bruteforce(records):
    """Failed-auth bursts per source IP, and failure-then-success = compromise."""
    out = []
    fails = defaultdict(list)   # ip -> [record, ...]
    successes = defaultdict(list)
    for r in records:
        mf = AUTH_FAIL_RE.search(r["msg"])
        if mf:
            fails[mf.group("ip")].append((r, mf.group("user")))
        ms = AUTH_OK_RE.search(r["msg"])
        if ms:
            successes[ms.group("ip")].append((r, ms.group("user")))

    for ip, events in fails.items():
        if len(events) < BRUTE_FORCE_MIN_FAILURES:
            continue
        times = [r["ts"] for r, _ in events if r["ts"]]
        span = (max(times) - min(times)).total_seconds() if len(times) >= 2 else 0
        within = (not times) or span <= BRUTE_FORCE_WINDOW_SEC
        user = events[0][1]
        first_line, last_line = events[0][0]["n"], events[-1][0]["n"]
        ev = f"{len(events)}x auth failed for '{user}' from {ip} (lines {first_line}-{last_line})"

        # Compromise check: a success from the same IP shortly after the failures.
        compromised = None
        if times:
            last_fail = max(times)
            for sr, su in successes.get(ip, []):
                if sr["ts"] and 0 <= (sr["ts"] - last_fail).total_seconds() <= COMPROMISE_SUCCESS_WINDOW_SEC:
                    compromised = sr
                    break

        if compromised:
            out.append(_anomaly(
                "critical", "auth_bruteforce_success",
                f"Brute-force then SUCCESSFUL login for '{user}' from {ip} — likely account compromise",
                ev + f"; then auth SUCCESS at line {compromised['n']}",
                "Multiple failed logins immediately followed by a success from the same source strongly "
                "indicates a successful brute-force / credential-stuffing compromise.",
                {"ip": ip, "user": user, "failures": len(events)},
            ))
        else:
            out.append(_anomaly(
                "high" if within else "medium", "auth_bruteforce",
                f"Brute-force login attempts for '{user}' from {ip}",
                ev,
                f"{len(events)} failures (>= {BRUTE_FORCE_MIN_FAILURES}) from one source"
                + (f" within {int(span)}s" if times else "") + " indicates a brute-force attempt.",
                {"ip": ip, "user": user, "failures": len(events)},
            ))
    return out


def detect_suspicious_ports(records):
    """Outbound connections to known-bad ports (flag even if the firewall blocked them)."""
    out = []
    for r in records:
        m = DEST_RE.search(r["msg"])
        if not m:
            continue
        port = int(m.group("port"))
        if port in SUSPICIOUS_PORTS:
            blocked = "block" in r["msg"].lower()
            out.append(_anomaly(
                "high", "suspicious_outbound",
                f"Outbound connection to {m.group('ip')}:{port} ({'blocked' if blocked else 'ALLOWED'})",
                r["raw"],
                f"Port {port}: {SUSPICIOUS_PORTS[port]}. An internal host contacting this port suggests "
                "possible malware/C2 activity" + (
                    "; the block is good but the source host should still be investigated." if blocked
                    else " and this one was NOT blocked."),
                {"dest_ip": m.group("ip"), "port": port, "host": r["host"], "blocked": blocked},
            ))
    return out


def detect_critical_and_resource(records):
    """CRIT-level events, resource exhaustion, and disk thresholds."""
    out = []
    for r in records:
        low = r["msg"].lower()
        if r["level"] in ("CRIT", "CRITICAL"):
            sev = "critical" if ("exhaust" in low or "pool" in low or "down" in low) else "high"
            out.append(_anomaly(
                sev, "critical_service_event",
                f"Critical event on {r['host']}: {r['msg'][:80]}",
                r["raw"],
                "Line logged at CRIT level indicating a service-impacting failure.",
                {"host": r["host"]},
            ))
        md = DISK_RE.search(r["msg"])
        if md:
            pct = int(md.group("pct"))
            if pct >= DISK_CRIT_PCT:
                sev = "high"
            elif pct >= DISK_WARN_PCT:
                sev = "medium"
            else:
                continue
            out.append(_anomaly(
                sev, "disk_pressure",
                f"Disk usage at {pct}% on {r['host']}",
                r["raw"],
                f"Disk at {pct}% (>= {DISK_WARN_PCT}% warn / {DISK_CRIT_PCT}% crit threshold).",
                {"host": r["host"], "pct": pct},
            ))
    return out


def detect_error_bursts(records):
    """Sliding-window spike in ERROR/CRIT lines."""
    errs = [r for r in records if r["level"] in ("ERROR", "CRIT", "CRITICAL") and r["ts"]]
    errs.sort(key=lambda r: r["ts"])
    out = []
    flagged_upto = None
    for i, r in enumerate(errs):
        window = [e for e in errs[i:] if (e["ts"] - r["ts"]).total_seconds() <= ERROR_BURST_WINDOW_SEC]
        if len(window) >= ERROR_BURST_MIN:
            start_n, end_n = window[0]["n"], window[-1]["n"]
            if flagged_upto and start_n <= flagged_upto:
                continue
            flagged_upto = end_n
            out.append(_anomaly(
                "medium", "error_rate_spike",
                f"{len(window)} ERROR/CRIT events within {ERROR_BURST_WINDOW_SEC}s",
                f"lines {start_n}-{end_n}",
                f"A burst of {len(window)} error-level events (>= {ERROR_BURST_MIN}) in a short window "
                "suggests a developing incident rather than isolated noise.",
                {"count": len(window)},
            ))
    return out


def detect(records):
    anomalies = []
    anomalies += detect_auth_bruteforce(records)
    anomalies += detect_suspicious_ports(records)
    anomalies += detect_critical_and_resource(records)
    anomalies += detect_error_bursts(records)
    anomalies.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 5))
    return anomalies


def to_llm_context(anomalies):
    """Compact text block to prepend to the LLM prompt as pre-flagged evidence."""
    if not anomalies:
        return "No rule-based anomalies were pre-flagged for this log."
    lines = ["Pre-flagged anomalies (from deterministic detectors — treat severities as authoritative):"]
    for a in anomalies:
        lines.append(f"- [{a['severity'].upper()}] {a['type']}: {a['summary']}")
    return "\n".join(lines)


def run(input_path, output_prefix):
    path = Path(input_path)
    if not path.exists():
        print(f"ERROR: file not found: {input_path}")
        sys.exit(1)

    records = parse_lines(path)
    anomalies = detect(records)

    print(f"Parsed {len(records)} log line(s) from {path.name}")
    print(f"Detected {len(anomalies)} anomaly(ies):\n")
    for a in anomalies:
        print(f"  [{a['severity'].upper():8}] {a['type']}")
        print(f"             {a['summary']}")
    if not anomalies:
        print("  (none)")

    if output_prefix:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_file": str(path),
            "lines_parsed": len(records),
            "total_anomalies": len(anomalies),
            "anomalies": anomalies,
        }
        with open(f"{output_prefix}.json", "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nWrote {output_prefix}.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deterministic log anomaly detection (Phase 2, read-only)")
    parser.add_argument("--input", required=True, help="Path to log file")
    parser.add_argument("--output", default=None, help="Output prefix for a JSON report (optional)")
    args = parser.parse_args()
    run(args.input, args.output)
