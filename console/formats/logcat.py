#!/usr/bin/env python3
"""
logcat.py — sibling parser for Android logcat output (Phase: feat/android-logcat-format).

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

ENVELOPE ONLY, exactly like normalize.py's other formats: this module decides
where the timestamp / level / tag / message boundaries are; it never rewrites
message wording, and it never touches rules, severities, or correlation —
those stay owned by the frozen detector. This module ENABLES PARSING; it does
not manufacture findings.

Recognized grammar (Android's default `threadtime` logcat format):

    MM-DD HH:MM:SS.mmm  PID  TID  L TAG: message
    03-17 16:13:38.811  1702  2395 D WindowManager: printFreezingDisplayLogs...

  - The stamp has NO year (like RFC 3164); the base year is inferred from the
    file mtime via normalize.infer_base_year, passed in by the caller.
  - The single-letter level L is one of V D I W E F. It is mapped to the
    detector's level vocabulary (anomaly_detector.LINE_RE):
        E, F -> ERROR / CRIT   (Error, Fatal)
        W    -> WARN
        V, D, I -> INFO        (Verbose, Debug, Info — no rule keys on DEBUG)
  - Android logcat carries NO host. `host` is left None (never derived); the
    TAG goes in `proc` and the PID in `pid`, mirroring rfc3164's proc/pid.

`raw` always carries the actual source line, verbatim — evidence is never
fabricated. Files that are not clearly logcat are NOT parsed here; normalize.py
falls through to its other formats or to the honest unrecognized banner.

No third-party dependencies. anomaly_detector.py is never imported or modified.
"""

import re
from datetime import datetime, timezone

# "03-17 16:13:38.811  1702  2395 D WindowManager: message"
# PID/TID columns are space-padded (right-aligned), so whitespace runs vary.
# The TAG is everything up to the first ": " that separates it from the message;
# a tag never contains that separator, message bodies may contain colons freely.
LOGCAT_RE = re.compile(
    r"^(?P<mon>\d{2})-(?P<day>\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\.(?P<ms>\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>.*?):\s(?P<msg>.*)$"
)

# Single-letter logcat priority -> the vocabulary anomaly_detector.LINE_RE knows.
# Deterministic, from the line itself — never a content guess.
LEVEL_MAP = {
    "V": "INFO",
    "D": "INFO",
    "I": "INFO",
    "W": "WARN",
    "E": "ERROR",
    "F": "CRIT",
}


def _ts(mon, day, time_s, ms, year):
    """Build a UTC timestamp from the header fields + the inferred year.

    Android logcat stamps carry no timezone; taken as UTC, consistent with the
    other envelope parsers. A malformed date (e.g. 02-30) yields None rather
    than raising, so one bad line never sinks the whole file."""
    hh, mm, ss = (int(x) for x in time_s.split(":"))
    try:
        return datetime(year, int(mon), int(day), hh, mm, ss,
                        int(ms) * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None


def sniff(path, probe_lines=50):
    """Return "logcat" if the CONTENT clearly matches, else None.

    Strict on purpose: logcat's leading "MM-DD HH:MM:SS.mmm PID TID L TAG:"
    signature cannot be produced by a canonical, rfc3164, or Log360 line, so a
    non-logcat file falls through untouched. Requires a clear majority of the
    probed non-blank lines to match, so a stray coincidental line never steals
    another format's file."""
    matched = seen = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            seen += 1
            if LOGCAT_RE.match(raw):
                matched += 1
            if seen >= probe_lines:
                break
    if matched and matched >= max(1, (seen * 2) // 3):
        return "logcat"
    return None


def load(path, base_year, fmt=None):
    """Parse Android logcat lines into canonical records.

    Returns (records, unparsed, total). `base_year` supplies the year the
    logcat stamp omits (inferred by the caller from the file mtime). A line
    that does not match the grammar is counted as unparsed and surfaced —
    never silently dropped.
    """
    records, unparsed = [], []
    total = 0
    year = base_year
    prev_month = None

    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1

            m = LOGCAT_RE.match(raw)
            if not m:
                unparsed.append((n, raw))
                continue

            month = int(m.group("mon"))
            # A month that jumps backwards mid-file means the year rolled over
            # (Dec -> Jan), mirroring the rfc3164 path's rollover handling.
            if prev_month is not None and month < prev_month - 6:
                year += 1
            prev_month = month

            records.append({
                "n": n,
                "ts": _ts(m.group("mon"), m.group("day"), m.group("time"),
                          m.group("ms"), year),
                "level": LEVEL_MAP[m.group("level")],
                "host": None,           # Android logcat has no host — not derived
                "msg": m.group("msg"),  # ORIGINAL wording — never rewritten here
                "raw": raw,             # the actual logcat line, verbatim
                "proc": m.group("tag"),
                "pid": m.group("pid"),
            })

    return records, unparsed, total
