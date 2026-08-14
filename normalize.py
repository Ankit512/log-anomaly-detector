#!/usr/bin/env python3
"""
normalize.py — envelope normalization (Phase 3).

Turns varied log formats into the canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

ENVELOPE ONLY. This module decides where the timestamp/level/host/message
boundaries are; it never rewrites message wording. Vocabulary translation is
rules_syslog.py's job. Keeping the two apart matters because they fail
differently: a new log *source* breaks the envelope, a new log *phrasing*
breaks the vocabulary.

Formats handled:
  - canonical  "2026-08-13T02:16:44Z ERROR host message"  -> passed through to
               anomaly_detector.parse_lines() unchanged, so existing behaviour
               is bit-for-bit what it was before this module existed.
  - rfc3164    "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: message"
               (space-padded day, no year, no timezone, no level)

Lines that match neither are counted and surfaced — never silently dropped.

No third-party dependencies. anomaly_detector.py is never modified.
"""

import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import anomaly_detector as ad  # noqa: E402


# "Mon DD HH:MM:SS host proc[pid]: message" — day may be space-padded ("Jul  3").
RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)

# "sshd[24200]: msg" / "sshd(pam_unix)[19939]: msg" / "syslogd 1.4.1: restart."
PROC_RE = re.compile(r"^(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Syslog carries no level field. Infer one from content, most severe first.
# Levels are restricted to the vocabulary anomaly_detector.LINE_RE already knows.
LEVEL_HINTS = [
    (re.compile(r"\b(kernel panic|fatal|segfault|out of memory|oom-killer)\b", re.I), "CRIT"),
    (re.compile(r"(failed password|authentication failure|invalid user|break-in|"
                r"\berror\b|\bdenied\b|\brefused\b|\bfailure\b|\bfailed\b)", re.I), "ERROR"),
    (re.compile(r"\b(warn|warning|deprecated|retry|retrying)\b", re.I), "WARN"),
]

DEFAULT_LEVEL = "INFO"


def synthesize_level(msg):
    """Infer a syslog line's level from its content. Defaults to INFO."""
    for pattern, level in LEVEL_HINTS:
        if pattern.search(msg):
            return level
    return DEFAULT_LEVEL


def infer_base_year(path):
    """RFC 3164 omits the year. Take it from the file's mtime.

    If the log's newest month is ahead of the mtime month, the log must have been
    written the previous calendar year (e.g. a December log touched in January).
    """
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return mtime.year, mtime.month


def _first_month(path):
    """Month of the first RFC 3164 line, for the year-rollover comparison."""
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = RFC3164_RE.match(line.rstrip("\n"))
            if m:
                return MONTHS[m.group("mon")]
    return None


def sniff_format(path, probe_lines=50):
    """Decide the format from the first non-blank lines. Ties go to canonical."""
    canonical = rfc3164 = seen = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            seen += 1
            if ad.LINE_RE.match(raw):
                canonical += 1
            elif RFC3164_RE.match(raw):
                rfc3164 += 1
            if seen >= probe_lines:
                break
    if not seen:
        return "empty"
    if canonical >= rfc3164 and canonical:
        return "canonical"
    if rfc3164:
        return "rfc3164"
    return "unknown"


def _parse_rfc3164(path, base_year):
    """Parse RFC 3164 lines into canonical records, handling Dec->Jan rollover."""
    records = []
    unparsed = []
    total = 0
    year = base_year
    prev_month = None

    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1

            m = RFC3164_RE.match(raw)
            if not m:
                unparsed.append((n, raw))
                continue

            month = MONTHS[m.group("mon")]
            # A month that jumps backwards mid-file means the year rolled over.
            if prev_month is not None and month < prev_month - 6:
                year += 1
            prev_month = month

            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            try:
                ts = datetime(year, month, int(m.group("day")), hh, mm, ss, tzinfo=timezone.utc)
            except ValueError:      # e.g. Feb 30 in a malformed line
                ts = None

            rest = m.group("rest")
            pm = PROC_RE.match(rest)
            if pm:
                proc, pid, msg = pm.group("proc"), pm.group("pid"), pm.group("msg")
            else:
                # Sub-formats like "combo  -- root[2421]: ROOT LOGIN ON tty2"
                proc, pid, msg = None, None, rest

            records.append({
                "n": n,
                "ts": ts,
                "level": synthesize_level(msg),
                "host": m.group("host"),
                "msg": msg,             # ORIGINAL wording — vocabulary is not this module's job
                "raw": raw,
                "proc": proc,
                "pid": pid,
            })

    return records, unparsed, total


def load(path):
    """Return (records, stats). Records are ready for anomaly_detector.detect()."""
    path = Path(path)
    fmt = sniff_format(path)

    if fmt == "canonical":
        # Delegate to v1 so canonical logs behave exactly as they always have.
        records = ad.parse_lines(path)
        total = sum(1 for line in open(path, errors="replace") if line.strip())
        matched = {r["n"] for r in records}
        unparsed = [(n, line.rstrip("\n"))
                    for n, line in enumerate(open(path, errors="replace"), start=1)
                    if line.strip() and n not in matched]
        base_year = None
    elif fmt == "rfc3164":
        year, mtime_month = infer_base_year(path)
        first_month = _first_month(path)
        if first_month and first_month > mtime_month:
            year -= 1               # log predates the mtime calendar year
        base_year = year
        records, unparsed, total = _parse_rfc3164(path, year)
    else:
        records, unparsed, total = [], [], sum(
            1 for line in open(path, errors="replace") if line.strip())
        unparsed = [(n, line.rstrip("\n"))
                    for n, line in enumerate(open(path, errors="replace"), start=1)
                    if line.strip()]

    stats = {
        "format": fmt,
        "total_lines": total,
        "parsed": len(records),
        "unparsed": len(unparsed),
        "unparsed_examples": [raw for _, raw in unparsed[:5]],
        "base_year": base_year,
    }
    return records, stats


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Inspect envelope normalization for a log file")
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    records, stats = load(args.input)
    print(f"format        : {stats['format']}")
    print(f"total lines   : {stats['total_lines']}")
    print(f"parsed        : {stats['parsed']}")
    print(f"unparsed      : {stats['unparsed']}")
    if stats["base_year"]:
        print(f"inferred year : {stats['base_year']}")
    for raw in stats["unparsed_examples"]:
        print(f"  unparsed: {raw[:100]}")
    if records:
        r = records[0]
        print(f"\nfirst record  : ts={r['ts']} level={r['level']} host={r['host']}")
        print(f"  msg : {r['msg'][:90]}")
