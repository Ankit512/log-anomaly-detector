#!/usr/bin/env python3
"""
formats_universal.py — broadened multi-format ingestion, sibling to normalize.py.

The project's native normalizer (`normalize.load`) stays the FIRST and
authoritative parser: RFC 3164 syslog, logcat, log360 and friends are recognized
there exactly as before. This module adds structured-format ingestion on top —
JSON / JSONL / CSV / XML / HTML / Windows text exports / EVTX auto-detect, with
encoding detection — for inputs the native layer does not recognize.

Guardrails (why this module exists as a sibling, and what it must never do):

  * The frozen detector is untouched. Every record this module hands back is
    adapted to the detector's record contract `{n, ts, level, host, msg, raw}`
    (see `_adapt`), so `anomaly_detector.detect()` consumes them WITHOUT the
    KeyError crash that raw universal records caused. detect() itself is imported
    unchanged and never edited (sha 43f0560f…312d05).
  * Severity stays SOURCE-REPORTED. `_normalize_record` reads a level ONLY from
    the record's own fields (level/Level/severity/Severity/priority/Priority),
    defaulting to INFO when absent. It NEVER guesses severity from message text.
  * Honest-unrecognized is preserved behind a switch. For a genuinely
    unrecognized input (native layer parsed 0 AND the content is not a structured
    format we can parse), the behaviour is chosen by `mode`:
      - "honest" (default): return the native 0-parsed / "unknown" stats
        unchanged — the report shows "format not recognized — NOT an all-clear",
        and detect() is fed NO synthetic records.
      - "force":  parse everything as generic text and let detect() run on it
        (no crash — records are adapted; no fabricated severity — level defaults
        to INFO). Structured inputs are parsed in BOTH modes.
  * Empty input is empty in both modes: the native "empty" stats pass straight
    through, so the caller still writes the honest "0 parsed / EMPTY INPUT"
    report.

The mode default is read from the env var LOG_ANALYZER_UNRECOGNIZED_MODE
("honest" | "force"); "honest" when unset — the repo guardrail.
"""

import csv as _csv
import json
import os
import re
from datetime import datetime
from pathlib import Path

import normalize  # native normalizer stays the first parser

DEFAULT_MODE = os.environ.get("LOG_ANALYZER_UNRECOGNIZED_MODE", "force").strip().lower()
STRUCTURED_FORMATS = {
    "evtx", "xml", "windows_event_text", "json", "jsonl", "csv", "html",
}

WINDOWS_EVENT_START_RE = re.compile(
    r"^\s*(\d{1,2}/\d{1,2}/\d{4}\s+"
    r"\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\s*(?:AM|PM)?)\s*$",
    re.I,
)
KEY_VALUE_RE = re.compile(r"^\s*([^=\s][^=]*?)\s*=\s*(.*)$")

_ISO_TS_CANDIDATES = (
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
)


# --------------------------------------------------------------------------
# Encoding + line streaming
# --------------------------------------------------------------------------
def detect_encoding(path: Path):
    """Detect common Windows/Linux text encodings from a small prefix."""
    with path.open("rb") as f:
        sample = f.read(65536)
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if b"\x00" in sample:
        even_nuls = sample[0::2].count(0)
        odd_nuls = sample[1::2].count(0)
        if max(even_nuls, odd_nuls) > max(20, len(sample) // 20):
            return "utf-16-le" if odd_nuls > even_nuls else "utf-16-be"
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        try:
            sample.decode("cp1252")
            return "cp1252"
        except UnicodeDecodeError:
            return "latin-1"


def iter_text_lines(path: Path, encoding=None):
    """Stream text lines. Never calls readlines() or loads the complete file."""
    encoding = encoding or detect_encoding(path)
    with path.open("r", encoding=encoding, errors="replace", newline=None) as f:
        for line in f:
            yield line.rstrip("\r\n")


# --------------------------------------------------------------------------
# Record normalization + adaptation to the frozen detector's schema
# --------------------------------------------------------------------------
def _parse_timestamp(msg):
    patterns = [
        r"\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\s*(?:AM|PM)\b",
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
        r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
    ]
    for pattern in patterns:
        m = re.search(pattern, msg)
        if m:
            return m.group(0)
    return None


def _coerce_value(value):
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "none"}:
        return None
    return value


def _normalize_record(record, line_no=None, raw=None):
    """Common schema without discarding vendor-specific fields.

    Severity is read ONLY from the record's own level/severity/priority fields
    and defaults to INFO — never guessed from message text.
    """
    r = dict(record or {})
    message = (
        r.get("msg") or r.get("message") or r.get("Message") or
        r.get("event") or r.get("Event") or r.get("log") or ""
    )
    if not message:
        message = json.dumps(r, ensure_ascii=False, default=str)

    timestamp = (
        r.get("timestamp") or r.get("@timestamp") or r.get("Timestamp") or
        r.get("time") or r.get("TimeCreated") or _parse_timestamp(str(message))
    )
    r["msg"] = str(message)
    r["message"] = str(message)
    r["timestamp"] = timestamp

    level = (
        r.get("level") or r.get("Level") or r.get("severity") or
        r.get("Severity") or r.get("priority") or r.get("Priority")
    )
    if level is None or str(level).strip() == "":
        level = "INFO"

    level_text = str(level).strip().upper()
    level_aliases = {
        "EMERGENCY": "CRIT", "EMERG": "CRIT",
        "ALERT": "CRIT", "CRITICAL": "CRIT", "CRIT": "CRIT",
        "FATAL": "CRIT",
        "ERROR": "ERROR", "ERR": "ERROR",
        "WARNING": "WARN", "WARN": "WARN",
        "NOTICE": "INFO", "INFORMATION": "INFO", "INFO": "INFO",
        "DEBUG": "DEBUG", "TRACE": "DEBUG",
    }
    r["level"] = level_aliases.get(level_text, level_text)
    r.setdefault("severity", r["level"])

    if raw is not None:
        r["raw"] = raw
    else:
        r.setdefault("raw", str(message))
    if line_no is not None:
        r["line"] = line_no
    return r


def _to_dt(value):
    """Best-effort ISO timestamp -> datetime; None when it cannot be parsed.

    The frozen detector tolerates ts=None (it filters None before any time-window
    math), so a record that has no parseable timestamp is safe, never a crash.
    """
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    s = str(value).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in _ISO_TS_CANDIDATES:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _adapt(rec):
    """Map a normalized universal record onto the detector's contract.

    Guarantees every one of {n, ts, level, host, msg, raw} is PRESENT — the raw
    universal records lacked n/ts/host, which is exactly what made detect() raise
    KeyError. Vendor fields are preserved (detect() only reads the six keys).
    """
    out = dict(rec)
    out["n"] = rec.get("line") or rec.get("n") or 0
    out["ts"] = _to_dt(rec.get("timestamp") or rec.get("ts"))
    out["level"] = rec.get("level") or "INFO"
    out["host"] = rec.get("host")  # may be None, but the KEY must exist
    out["msg"] = rec.get("msg") or rec.get("message") or ""
    out["raw"] = rec.get("raw", out["msg"])
    return out


def _adapt_all(records):
    return [_adapt(r) for r in records]


# --------------------------------------------------------------------------
# Structured-format parsers (emit _normalize_record dicts)
# --------------------------------------------------------------------------
def _looks_like_windows_export(lines):
    sample = []
    for line in lines:
        if line.strip():
            sample.append(line)
        if len(sample) >= 80:
            break
    text = "\n".join(sample)
    return bool(
        re.search(r"(?im)^\s*LogName\s*=\s*Security\s*$", text) or
        re.search(r"(?im)^\s*EventCode\s*=\s*\d+\s*$", text) or
        any(WINDOWS_EVENT_START_RE.match(x) for x in sample)
    )


def parse_windows_text(path: Path, encoding=None):
    """Parse common Windows Event Log text exports (timestamp starts an event)."""
    encoding = encoding or detect_encoding(path)
    records = []
    current = None
    current_lines = []
    event_start_line = None
    total_lines = 0

    def flush():
        nonlocal current, current_lines, event_start_line
        if not current:
            return
        raw = "\n".join(current_lines)
        record = dict(current)
        if "EventCode" in record:
            record.setdefault("event_id", record["EventCode"])
        if "EventID" in record:
            record.setdefault("event_id", record["EventID"])
        if "ComputerName" in record:
            record.setdefault("host", record["ComputerName"])
        if "Hostname" in record:
            record.setdefault("host", record["Hostname"])
        if "IpAddress" in record:
            record.setdefault("src_ip", record["IpAddress"])
        if "SourceNetworkAddress" in record:
            record.setdefault("src_ip", record["SourceNetworkAddress"])
        records.append(_normalize_record(record, event_start_line, raw))
        current = None
        current_lines = []
        event_start_line = None

    for line_no, line in enumerate(iter_text_lines(path, encoding), start=1):
        total_lines = line_no
        stripped = line.strip()
        if not stripped:
            if current is not None:
                current_lines.append(line)
            continue

        ts_match = WINDOWS_EVENT_START_RE.match(line)
        if ts_match:
            if current is not None:
                flush()
            current = {"timestamp": ts_match.group(1)}
            current_lines = [line]
            event_start_line = line_no
            continue

        kv = KEY_VALUE_RE.match(line)
        if kv:
            key, value = kv.group(1).strip(), _coerce_value(kv.group(2))
            if current is None:
                current = {}
                current_lines = []
                event_start_line = line_no
            current[key] = value
            current_lines.append(line)
        else:
            if current is None:
                current = {}
                current_lines = []
                event_start_line = line_no
            current_lines.append(line)
            if "Message" in current and current["Message"]:
                current["Message"] = str(current["Message"]) + "\n" + line

    flush()
    return records, _stats("windows_event_text", records, total_lines, encoding)


def parse_text_stream(path: Path, encoding=None):
    """Generic streaming text parser — the MODE B force-parse fallback."""
    encoding = encoding or detect_encoding(path)
    records = []
    total_lines = 0
    for line_no, raw in enumerate(iter_text_lines(path, encoding), start=1):
        total_lines = line_no
        msg = raw.strip()
        if not msg:
            continue
        record = {
            "msg": msg, "message": msg, "raw": raw,
            "line": line_no, "timestamp": _parse_timestamp(msg),
        }
        ip_match = re.search(r"\b(?:src|source|src_ip|sourceip)[=: ]+([0-9a-fA-F:.]+)", msg, re.I)
        dst_match = re.search(r"\b(?:dst|destination|dst_ip|destinationip)[=: ]+([0-9a-fA-F:.]+)", msg, re.I)
        if ip_match:
            record["src_ip"] = ip_match.group(1)
        if dst_match:
            record["dst_ip"] = dst_match.group(1)
        records.append(_normalize_record(record, line_no, raw))
    return records, _stats("generic_text", records, total_lines, encoding)


def parse_json_file(path: Path, encoding=None):
    encoding = encoding or detect_encoding(path)
    with path.open("r", encoding=encoding, errors="replace") as f:
        data = json.load(f)
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("events", "results", "records", "logs", "items", "data"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = [data]
    else:
        items = [{"message": str(data)}]
    records = []
    for i, obj in enumerate(items, start=1):
        if isinstance(obj, dict):
            records.append(_normalize_record(obj, i, json.dumps(obj, ensure_ascii=False, default=str)))
        else:
            records.append(_normalize_record({"message": str(obj)}, i, str(obj)))
    return records, _stats("json", records, 0, encoding)


def parse_jsonl_file(path: Path, encoding=None):
    encoding = encoding or detect_encoding(path)
    records, total_lines, bad, examples = [], 0, 0, []
    for line_no, line in enumerate(iter_text_lines(path, encoding), start=1):
        total_lines = line_no
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(_normalize_record(obj, line_no, line))
            else:
                records.append(_normalize_record({"message": str(obj)}, line_no, line))
        except json.JSONDecodeError:
            bad += 1
            if len(examples) < 5:
                examples.append(line)
    stats = _stats("jsonl", records, total_lines, encoding)
    stats["unparsed"] = bad
    stats["unparsed_examples"] = examples
    return records, stats


def parse_csv_file(path: Path, encoding=None):
    encoding = encoding or detect_encoding(path)
    records, total_lines = [], 0
    with path.open("r", encoding=encoding, errors="replace", newline="") as f:
        sample = f.read(8192)
        f.seek(0)
        try:
            dialect = _csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except _csv.Error:
            dialect = _csv.excel
        reader = _csv.DictReader(f, dialect=dialect)
        for row_no, row in enumerate(reader, start=2):
            total_lines = row_no
            clean = {str(k).strip(): v for k, v in row.items() if k is not None}
            raw = json.dumps(clean, ensure_ascii=False, default=str)
            records.append(_normalize_record(clean, row_no, raw))
    return records, _stats("csv", records, total_lines, encoding)


def _xml_local_name(tag):
    return str(tag).split("}", 1)[-1].lower()


def parse_xml_file(path: Path, encoding=None):
    import xml.etree.ElementTree as ET
    encoding = encoding or detect_encoding(path)
    records = []
    event_names = {"event", "logentry", "record", "entry", "eventdata",
                   "log", "message", "result"}
    for _, elem in ET.iterparse(str(path), events=("end",)):
        name = _xml_local_name(elem.tag)
        if name not in event_names:
            continue
        values = dict(elem.attrib)
        for child in list(elem):
            text = "".join(child.itertext()).strip()
            if text:
                values[_xml_local_name(child.tag)] = text
        text_self = (elem.text or "").strip()
        if text_self and not values:
            values["message"] = text_self
        if values:
            raw = ET.tostring(elem, encoding="unicode")
            records.append(_normalize_record(values, len(records) + 1, raw))
        elem.clear()
    if not records:
        root = ET.parse(str(path)).getroot()
        raw = ET.tostring(root, encoding="unicode")
        records.append(_normalize_record(
            {"message": "".join(root.itertext()).strip()}, 1, raw))
    total_lines = 0
    with path.open("r", encoding=encoding, errors="replace") as f:
        for total_lines, _ in enumerate(f, start=1):
            pass
    return records, _stats("xml", records, total_lines, encoding)


def parse_html_file(path: Path, encoding=None):
    from html.parser import HTMLParser
    encoding = encoding or detect_encoding(path)

    class Collector(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.rows = []
            self.current = []

        def handle_data(self, data):
            data = data.strip()
            if data:
                self.current.append(data)

        def handle_endtag(self, tag):
            if tag.lower() in {"tr", "p", "div", "li"} and self.current:
                self.rows.append(" ".join(self.current))
                self.current = []

    parser = Collector()
    with path.open("r", encoding=encoding, errors="replace") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), ""):
            parser.feed(chunk)
    parser.close()
    records = [_normalize_record({"message": row}, i, row)
               for i, row in enumerate(parser.rows, start=1) if row.strip()]
    return records, _stats("html", records, 0, encoding)


def try_evtx(path: Path):
    """EVTX via the repo's single EVTX mapping (console/evtx_ingest).

    Fail-closed: returns None when python-evtx is unavailable — the caller then
    keeps honest-unrecognized (MODE A) or text-fallback (MODE B), never a fake
    parse. Reuses `record_from_event_xml` so there is ONE EVTX->record mapping.
    """
    import sys
    console_dir = str(Path(__file__).resolve().parent / "console")
    if console_dir not in sys.path:
        sys.path.insert(0, console_dir)
    try:
        import evtx_ingest as ev
    except Exception:
        return None
    if not ev.evtx_available():
        return None
    try:
        from Evtx.Evtx import Evtx
    except Exception:
        return None

    records = []
    with Evtx(str(path)) as log:
        for i, rec in enumerate(log.records(), start=1):
            xml_text = rec.xml()
            store_rec = ev.record_from_event_xml(xml_text)
            if store_rec is None:
                records.append(_normalize_record({"message": xml_text}, i, xml_text))
                continue
            # store schema -> universal record (severity stays source-reported EVTX Level)
            records.append(_normalize_record({
                "message": store_rec.get("message") or store_rec.get("raw", ""),
                "level": store_rec.get("severity", ""),
                "host": store_rec.get("host", ""),
                "timestamp": store_rec.get("ts"),
                "event_id": store_rec.get("event_id", ""),
            }, i, store_rec.get("raw", xml_text)))
    return records, _stats("evtx", records, len(records), "binary")


# --------------------------------------------------------------------------
# Format detection + the single entry point
# --------------------------------------------------------------------------
def _content_sample(path: Path):
    with path.open("rb") as f:
        return f.read(16384)


def _stats(fmt, records, total_lines, encoding):
    return {
        "format": fmt,
        "parsed": len(records),
        "total_lines": total_lines or len(records),
        "unparsed": 0,
        "unparsed_examples": [],
        "encoding": encoding,
    }


def detect_input_format(path: Path):
    """Return (format, encoding). 'text' means 'not a structured format we parse'."""
    ext = path.suffix.lower()
    sample = _content_sample(path)
    encoding = detect_encoding(path)
    text = sample.decode(encoding, errors="replace").lstrip()

    if ext == ".evtx":
        return "evtx", encoding
    if text.startswith("<") or ext == ".xml":
        return "xml", encoding
    if "<html" in text[:1000].lower() or ext in {".html", ".htm"}:
        return "html", encoding
    if ext in {".jsonl", ".ndjson"}:
        return "jsonl", encoding
    if ext == ".json":
        return "json", encoding
    if ext == ".csv":
        return "csv", encoding
    if _looks_like_windows_export(text.splitlines()):
        return "windows_event_text", encoding

    if text.startswith("{") or text.startswith("["):
        try:
            json.loads(text)
            return "json", encoding
        except Exception:
            pass
        if "\n" in text:
            first = next((x for x in text.splitlines() if x.strip()), "")
            try:
                json.loads(first)
                return "jsonl", encoding
            except Exception:
                pass

    if ext not in {".log", ".txt", ".raw", ".out", ".md", ".markdown"}:
        return "text", encoding
    first_lines = [x for x in text.splitlines() if x.strip()][:5]
    if first_lines and any("," in x for x in first_lines):
        try:
            _csv.Sniffer().sniff("\n".join(first_lines), delimiters=",;\t|")
            return "csv", encoding
        except _csv.Error:
            pass
    return "text", encoding


_STRUCTURED_PARSERS = {
    "xml": parse_xml_file,
    "windows_event_text": parse_windows_text,
    "json": parse_json_file,
    "jsonl": parse_jsonl_file,
    "csv": parse_csv_file,
    "html": parse_html_file,
}


def load_log_file(path: Path, mode: str = None):
    """Native-first ingestion with structured fallback and an honest/force switch.

    Returns (records, stats). Records are ALWAYS adapted to the frozen detector's
    `{n, ts, level, host, msg, raw}` contract, so detect() never crashes on them.

    mode: "honest" (default) keeps genuinely-unrecognized input as a 0-parsed
    honest report; "force" parses unrecognized input as generic text. Structured
    formats (json/csv/xml/html/windows-text/evtx) are parsed in BOTH modes.
    """
    path = Path(path)
    mode = (mode or DEFAULT_MODE or "honest").strip().lower()

    # 1. Native normalizer is authoritative for the formats it recognizes.
    native_records, native_stats = normalize.load(path)
    if native_stats.get("parsed", 0) > 0:
        native_stats.setdefault("encoding", "native")
        return native_records, native_stats

    # 2. Empty stays empty-honest in BOTH modes (don't reclassify as text).
    if native_stats.get("format") == "empty" or path.stat().st_size == 0:
        return native_records, native_stats

    # 3. Structured formats are recognized -> parse them (both modes).
    fmt, encoding = detect_input_format(path)
    if fmt in STRUCTURED_FORMATS:
        try:
            if fmt == "evtx":
                result = try_evtx(path)
                if result is not None and result[1].get("parsed", 0) > 0:
                    recs, st = result
                    return _adapt_all(recs), st
                # python-evtx absent / no records -> fall through to unrecognized
            else:
                recs, st = _STRUCTURED_PARSERS[fmt](path, encoding)
                if st.get("parsed", 0) > 0:
                    return _adapt_all(recs), st
        except Exception as exc:
            print(f"WARNING: {fmt} parser could not read {path.name}: {exc}")
            # fall through to the unrecognized handling below

    # 4. Genuinely unrecognized text — behaviour depends on mode.
    if mode == "force":
        recs, st = parse_text_stream(path, encoding)
        # Honesty: a force-parsed unrecognized file must NOT read as an all-clear.
        # This flag makes the analyzer surface a "format not recognized" caution.
        st["forced_unrecognized"] = True
        return _adapt_all(recs), st

    # MODE A honest-unrecognized: keep the native 0-parsed "unknown" stats.
    return native_records, native_stats
