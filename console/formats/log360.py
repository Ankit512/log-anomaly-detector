#!/usr/bin/env python3
"""
log360.py — sibling parser for ManageEngine Log360 output (Phase: feat/log360-ingest).

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

ENVELOPE ONLY, exactly like normalize.py's other formats: this module decides
field boundaries; it never rewrites message wording, and it never touches
rules, severities, or correlation — those stay owned by the detector.

Two Log360 shapes are recognized, both content-sniffed (never by file name):

  log360_csv     A Log360 CSV export with the header columns
                 Message, Common Severity, LogType, Process Id, Facility,
                 Severity, Time, Device, Source.
                 Mapping: Time -> ts, Severity (fallback Common Severity) -> level,
                 Device (fallback Source) -> host, Message -> msg,
                 and the WHOLE ROW verbatim -> raw.

  log360_syslog  Log360-forwarded syslog with a leading |PRI| envelope:
                 |30|Aug 17 09:37:02 kali start.sh[1158]: ... DEBUG helpers.updater ...
                 The |NN| envelope is stripped, the RFC3164-style ts/host/app are
                 parsed, and the WHOLE LINE verbatim -> raw.

Severity is never guessed:
  - CSV: the Severity cell (or Common Severity when Severity is empty) is mapped
    through a fixed vocabulary table; anything unrecognized -> "UNKNOWN".
  - syslog: an explicit uppercase level token in the message wins; otherwise the
    level encoded in the |PRI| envelope (severity = PRI % 8, per RFC 3164) is
    used; a line with neither -> "UNKNOWN". Both derivations are deterministic
    facts carried by the line itself, not content heuristics.

`raw` always carries the actual source row/line, verbatim — evidence is never
fabricated. Files matching neither shape are NOT parsed here; normalize.py's
sniff falls through to "unknown" and the console shows the honest
unrecognized-format banner.

No third-party dependencies. anomaly_detector.py is never imported or modified.
"""

import csv
import io
import re
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared vocabulary
# ---------------------------------------------------------------------------

# Log360 / syslog severity words -> the level vocabulary the detector's rules
# key on (see anomaly_detector.LINE_RE). Unrecognized values map to UNKNOWN —
# deliberately NOT to INFO — so an unmapped severity is visible, never guessed.
LEVEL_MAP = {
    "emergency": "CRIT", "emerg": "CRIT", "panic": "CRIT",
    "alert": "CRIT",
    "critical": "CRIT", "crit": "CRIT", "fatal": "CRIT",
    "error": "ERROR", "err": "ERROR",
    "warning": "WARN", "warn": "WARN",
    "notice": "INFO",
    "informational": "INFO", "information": "INFO", "info": "INFO",
    "debug": "DEBUG",
}
UNKNOWN_LEVEL = "UNKNOWN"

# RFC 3164 numeric severities (PRI % 8), for the syslog envelope fallback.
PRI_SEVERITY = ["CRIT", "CRIT", "CRIT", "ERROR", "WARN", "INFO", "INFO", "DEBUG"]

# An explicit level token inside a forwarded message, e.g.
# "2026-08-17 09:37:02,481: DEBUG helpers.updater ...". Uppercase only: a
# lowercase "error" is prose, not a level marker.
MSG_LEVEL_RE = re.compile(
    r"\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|FATAL|ERR(?:OR)?|WARN(?:ING)?|"
    r"NOTICE|INFO(?:RMATIONAL)?|DEBUG)\b")

# CSV header columns (matched case-insensitively). Message + Time are required;
# severity and host each have a documented fallback column.
REQUIRED_COLUMNS = {"message", "time"}
SEVERITY_COLUMNS = ("severity", "common severity")
HOST_COLUMNS = ("device", "source")

# "|30|Aug 17 09:37:02 kali start.sh[1158]: message"
ENVELOPE_RE = re.compile(r"^\|(?P<pri>\d{1,3})\|(?P<rest>.*)$")
RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$")
PROC_RE = re.compile(r"^(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# A full date embedded in a forwarded message ("2026-08-17 09:37:02,481"). It
# carries the year the RFC 3164 header omits, so it is the preferred timestamp.
EMBEDDED_TS_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[ T](?P<time>\d{2}:\d{2}:\d{2})(?:[.,](?P<frac>\d{1,6}))?")

TIME_FORMATS = [                       # CSV Time column variants seen in exports
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%b %d, %Y %I:%M:%S %p",
    "%d-%m-%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
]


def map_level(value):
    """Fixed-table severity mapping. Empty or unrecognized -> UNKNOWN, never a guess."""
    return LEVEL_MAP.get((value or "").strip().lower(), UNKNOWN_LEVEL)


def parse_time(value):
    """Parse a Log360 Time cell. Naive stamps are taken as UTC; failure -> None."""
    value = (value or "").strip()
    if not value:
        return None
    try:                               # ISO 8601, incl. fractional seconds ("," or ".")
        ts = datetime.fromisoformat(value.replace(",", "."))
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Sniffing (content-based; ties are broken by normalize.py's own sniff order)
# ---------------------------------------------------------------------------

def _header_matches(line):
    """Does this line look like the Log360 CSV export header?"""
    try:
        cols = next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return False
    names = {c.strip().lower() for c in cols}
    return (REQUIRED_COLUMNS <= names
            and any(c in names for c in SEVERITY_COLUMNS)
            and any(c in names for c in HOST_COLUMNS))


def _is_syslog_line(raw):
    m = ENVELOPE_RE.match(raw)
    return bool(m and RFC3164_RE.match(m.group("rest")))


def sniff(path, probe_lines=50):
    """Return "log360_csv" / "log360_syslog" if the CONTENT matches, else None.

    Strict on purpose: a file that is not clearly Log360 must fall through to
    normalize.py's other formats — or to the honest unrecognized banner.
    """
    first = None
    matched = seen = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            if first is None:
                first = raw
                if _header_matches(raw):
                    return "log360_csv"
            seen += 1
            if _is_syslog_line(raw):
                matched += 1
            if seen >= probe_lines:
                break
    if matched and matched >= max(1, seen // 2):
        return "log360_syslog"
    return None


# ---------------------------------------------------------------------------
# CSV path
# ---------------------------------------------------------------------------

class _LineTrackingReader:
    """Feed csv.reader line by line so each parsed row can be paired with the
    VERBATIM source text it came from (quoted fields may span lines)."""

    def __init__(self, f):
        self.f = f
        self.lineno = 0                # line number of the last line handed out
        self.buffer = []               # raw lines consumed since the last take()

    def __iter__(self):
        return self

    def __next__(self):
        line = next(self.f)
        self.lineno += 1
        self.buffer.append(line)
        return line

    def take(self):
        """The raw text consumed for the row just parsed, and its start line."""
        raw = "".join(self.buffer).rstrip("\n")
        start = self.lineno - (len(self.buffer) - 1)
        self.buffer = []
        return raw, start


def _cell(row, index, name):
    i = index.get(name)
    return row[i].strip() if i is not None and i < len(row) else ""


def load_csv(path):
    """Parse a Log360 CSV export. Returns (records, unparsed, total).

    The header row is envelope, not an event: total counts data rows only.
    """
    records, unparsed = [], []
    total = 0
    with open(path, "r", errors="replace", newline="") as f:
        tracker = _LineTrackingReader(f)
        reader = csv.reader(tracker)
        try:
            header = next(reader)
        except StopIteration:
            return [], [], 0
        tracker.take()                 # discard the header's raw text
        index = {name.strip().lower(): i for i, name in enumerate(header)}

        for row in reader:
            raw, n = tracker.take()
            if not raw.strip():
                continue
            total += 1

            msg = _cell(row, index, "message")
            if len(row) < len(header) or not msg:
                unparsed.append((n, raw))
                continue

            severity = (_cell(row, index, "severity")
                        or _cell(row, index, "common severity"))
            host = (_cell(row, index, "device")
                    or _cell(row, index, "source"))

            records.append({
                "n": n,
                "ts": parse_time(_cell(row, index, "time")),
                "level": map_level(severity),
                "host": host,
                "msg": msg,            # ORIGINAL wording — never rewritten here
                "raw": raw,            # the actual CSV row, verbatim
            })
    return records, unparsed, total


# ---------------------------------------------------------------------------
# Forwarded-syslog path
# ---------------------------------------------------------------------------

def _base_year(path):
    """RFC 3164 headers omit the year; take it from the file's mtime (UTC)."""
    mtime = datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)
    return mtime.year, mtime.month


def _syslog_level(msg, pri):
    """Level of a forwarded line, most specific fact first — never a guess.

    1. an explicit uppercase level token in the message ("DEBUG helpers...")
    2. the severity encoded in the |PRI| envelope (PRI % 8, per RFC 3164)
    3. UNKNOWN
    """
    m = MSG_LEVEL_RE.search(msg)
    if m:
        return map_level(m.group(1))
    if pri is not None and 0 <= pri <= 191:
        return PRI_SEVERITY[pri % 8]
    return UNKNOWN_LEVEL


def _syslog_ts(msg, mon, day, time_s, year):
    """Prefer a full date embedded in the message (it carries the year the
    RFC 3164 header lacks); otherwise the header time with the inferred year."""
    m = EMBEDDED_TS_RE.search(msg)
    if m:
        try:
            ts = datetime.fromisoformat(f"{m.group('date')} {m.group('time')}")
            return ts.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    hh, mm, ss = (int(x) for x in time_s.split(":"))
    try:
        return datetime(year, MONTHS[mon], int(day), hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:                 # e.g. Feb 30 in a malformed line
        return None


def load_syslog(path):
    """Parse Log360-forwarded syslog lines. Returns (records, unparsed, total)."""
    records, unparsed = [], []
    total = 0
    year, mtime_month = _base_year(path)
    prev_month = None

    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1

            env = ENVELOPE_RE.match(raw)
            m = RFC3164_RE.match(env.group("rest")) if env else None
            if not m:
                unparsed.append((n, raw))
                continue

            month = MONTHS[m.group("mon")]
            if prev_month is None and month > mtime_month:
                year -= 1              # log predates the mtime calendar year
            if prev_month is not None and month < prev_month - 6:
                year += 1              # Dec -> Jan rollover mid-file
            prev_month = month

            pm = PROC_RE.match(m.group("rest"))
            msg = pm.group("msg") if pm else m.group("rest")

            records.append({
                "n": n,
                "ts": _syslog_ts(msg, m.group("mon"), m.group("day"),
                                 m.group("time"), year),
                "level": _syslog_level(msg, int(env.group("pri"))),
                "host": m.group("host"),
                "msg": msg,            # ORIGINAL wording, envelope stripped
                "raw": raw,            # the actual forwarded line, |PRI| included
            })
    return records, unparsed, total


def load(path, fmt=None):
    """Dispatch on the sniffed (or given) format. Returns (records, unparsed, total)."""
    fmt = fmt or sniff(path)
    if fmt == "log360_csv":
        return load_csv(path)
    if fmt == "log360_syslog":
        return load_syslog(path)
    raise ValueError(f"not a Log360 file: {path}")
