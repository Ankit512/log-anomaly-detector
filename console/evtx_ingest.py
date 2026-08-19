"""Windows Event Log (.evtx) ingest (socf-evtx-history).

A *sibling* subsystem: it turns a binary Windows `.evtx` file into event records
and writes them to the persistent store (`store.insert_event`,
`source_type="evtx"`), per the contract in `docs/soc_command_center.md`.

Honesty posture:

* **Optional dependency, honest degradation.** The binary `.evtx` container is
  parsed by `python-evtx` (`import Evtx`), an OPTIONAL dependency. When it is not
  installed, ingest raises `EvtxUnavailable(EVTX_MISSING_MSG)` — a clear
  "install python-evtx" message — and NEVER a silent or fabricated parse.
* **Raw is verbatim.** Each stored event's `raw` is the record's own event XML,
  exactly as `python-evtx` produced it. Nothing rewrites evidence.
* **Severity is source-reported.** `severity` is derived from the EVTX `<Level>`
  field the event itself carries (Critical/Error/Warning/Information/Verbose) —
  never keyword-guessed from the message text.

The event-XML → record mapping (`record_from_event_xml`) and the store-insert
loop (`ingest_event_xmls`) are stdlib-only and fully testable without the binary
parser; only iterating records out of the `.evtx` container needs the optional
library.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import store

EVTX_MISSING_MSG = "EVTX support needs python-evtx installed (pip install python-evtx)"

# Windows EVTX <Level> codes -> the label the source asserted. This is the
# event's OWN reported level, not a keyword guess. 0 (LogAlways) and 4 are both
# informational in the Windows model.
EVTX_LEVELS = {
    "0": "INFORMATION",
    "1": "CRITICAL",
    "2": "ERROR",
    "3": "WARNING",
    "4": "INFORMATION",
    "5": "VERBOSE",
}


class EvtxUnavailable(RuntimeError):
    """Raised when a .evtx ingest is attempted without python-evtx installed."""


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def evtx_available():
    """True if the optional python-evtx library can be imported."""
    try:
        import Evtx.Evtx  # noqa: F401
        return True
    except Exception:
        return False


def _localname(tag):
    """Strip the XML namespace so `{…}EventID` matches `EventID`."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _find(system, name):
    for child in system:
        if _localname(child.tag) == name:
            return child
    return None


def record_from_event_xml(xml_text):
    """Map one EVTX record's event XML to a store event dict.

    `severity` comes from the `<Level>` code (source-reported); `raw` is the
    verbatim XML. Returns None if the text does not parse as an <Event> — the
    caller counts it as an unparsed record rather than inventing one.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    system = None
    event_data_text = []
    for child in root:
        ln = _localname(child.tag)
        if ln == "System":
            system = child
        elif ln == "EventData":
            for d in child:
                if d.text and d.text.strip():
                    key = d.attrib.get("Name", "")
                    event_data_text.append(f"{key}={d.text.strip()}" if key else d.text.strip())

    def sys_text(name):
        el = _find(system, name) if system is not None else None
        return (el.text or "").strip() if el is not None and el.text else ""

    def sys_attr(name, attr):
        el = _find(system, name) if system is not None else None
        return el.attrib.get(attr, "") if el is not None else ""

    provider = sys_attr("Provider", "Name")
    event_id = sys_text("EventID")
    level_code = sys_text("Level")
    computer = sys_text("Computer")
    channel = sys_text("Channel")
    ts = sys_attr("TimeCreated", "SystemTime") or _now_iso()
    user = sys_attr("Security", "UserID")

    severity = EVTX_LEVELS.get(level_code, "")   # empty when the level is absent/unknown
    summary = " ".join(p for p in (channel, f"EventID {event_id}" if event_id else "",
                                   provider) if p).strip()
    if event_data_text:
        summary = (summary + " — " + "; ".join(event_data_text[:6])).strip(" —")

    return {
        "ts": ts,
        "source": provider or channel or "evtx",
        "source_type": "evtx",
        "category": channel,
        "host": computer,
        "user": user,
        "event_id": event_id,
        "severity": severity,
        "message": summary or xml_text.strip()[:400],
        "raw": xml_text,          # verbatim record XML — evidence is never rewritten
    }


def ingest_event_xmls(xml_iter):
    """Insert a sequence of EVTX event-XML strings into the store. Returns
    {stored, parsed, skipped}. Stdlib only — the caller supplies the iterator
    (the real one comes from python-evtx; a test can pass strings directly)."""
    stored = parsed = skipped = 0
    for xml_text in xml_iter:
        rec = record_from_event_xml(xml_text)
        if rec is None:
            skipped += 1
            continue
        parsed += 1
        if store.insert_event(rec):
            stored += 1
    return {"stored": stored, "parsed": parsed, "skipped": skipped}


def _iter_evtx_records(path):
    """Yield each record's event XML from a .evtx file via python-evtx. Raises
    EvtxUnavailable when the library is not installed."""
    try:
        from Evtx.Evtx import Evtx
    except Exception as exc:  # ImportError or a broken install
        raise EvtxUnavailable(EVTX_MISSING_MSG) from exc
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                yield record.xml()
            except Exception:
                # A single corrupt record must not abort the whole file; it is
                # counted as skipped by record_from_event_xml returning None.
                yield ""


def ingest_evtx_file(path):
    """Parse a .evtx file and store its events. Raises EvtxUnavailable (honest
    'install python-evtx' message) when the optional library is absent — never a
    silent or simulated parse. Returns {stored, parsed, skipped}."""
    if not evtx_available():
        raise EvtxUnavailable(EVTX_MISSING_MSG)
    return ingest_event_xmls(_iter_evtx_records(path))
