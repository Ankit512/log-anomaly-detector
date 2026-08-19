#!/usr/bin/env python3
"""
store.py — the persistent SOC Command Center store (stdlib sqlite3 only).

The single durable home the upcoming SOC Command Center features all write to
(EVTX ingest, live syslog, nmap discovery, threat-intel/OEM enrichment). Schema
+ endpoint contract: docs/soc_command_center.md.

HONESTY MODEL (this differs deliberately from the reference prototype):
  - The store keeps RAW events verbatim (`raw` is the real line). Nothing here
    rewrites evidence.
  - `severity` on a stored event is the SOURCE-REPORTED level (or empty when the
    source gave none). This module NEVER keyword-guesses a severity — anomaly
    verdicts still come only from the frozen rules/detector. A stored level is a
    fact the source asserted, never presented as our verdict.
  - Empty tables mean an honest empty result (`{"items": []}`), never seeded or
    sample rows.
  - Secrets in `settings` are stored but NEVER returned — a settings read
    reports only whether a secret is present, not its value.

Stdlib only: sqlite3, json, hashlib, threading. No pandas / requests / network.
The DB lives at console/.soc/soc_history.db (gitignored). anomaly_detector.py is
never imported.
"""

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Module-level so tests can point these at a temp dir before init_db(). Every
# connection reads them live, so an override takes effect immediately.
SOC_DIR = HERE / ".soc"
DB_PATH = SOC_DIR / "soc_history.db"

_LOCK = threading.RLock()
DEFAULT_RETENTION_DAYS = 90

# Tables that carry a `ts` and are subject to retention cleanup / full purge.
# (settings + connectors are configuration, not history — never auto-expired.)
HISTORY_TABLES = ("events", "assets", "vulnerabilities", "iocs", "investigations")
ALL_DATA_TABLES = HISTORY_TABLES + ("connectors",)

# A settings key is treated as a secret (value stored, never returned) when its
# name contains any of these — so `virustotal_api_key`, `taxii_token`, etc. are
# masked without an explicit per-key list.
SECRET_HINTS = ("key", "token", "secret", "password", "passwd", "credential")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT, source_type TEXT, category TEXT,
    host TEXT, src_ip TEXT, dst_ip TEXT, user TEXT, event_id TEXT,
    severity TEXT,              -- SOURCE-REPORTED level, never a guessed verdict
    action TEXT, message TEXT,
    raw TEXT,                   -- the real source line, verbatim
    mitre TEXT,                 -- optional derived tag(s); display only
    event_hash TEXT UNIQUE      -- dedupe fingerprint (INSERT OR IGNORE)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT, hostname TEXT, mac TEXT, category TEXT,
    vendor TEXT, model TEXT, os TEXT, ports TEXT,
    source TEXT, status TEXT, risk REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    asset_ip TEXT, name TEXT, cve TEXT,
    severity TEXT, cvss REAL DEFAULT 0,
    details TEXT, source TEXT, status TEXT DEFAULT 'OPEN'
);
CREATE INDEX IF NOT EXISTS idx_vuln_ip ON vulnerabilities(asset_ip);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ioc TEXT, ioc_type TEXT, provider TEXT,
    score REAL DEFAULT 0, verdict TEXT, details TEXT,
    source_event_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ioc ON iocs(ioc);

CREATE TABLE IF NOT EXISTS connectors (
    name TEXT PRIMARY KEY,
    kind TEXT,
    config_json TEXT,           -- opaque JSON blob owned by each connector
    enabled INTEGER DEFAULT 0,
    interval INTEGER DEFAULT 0,
    last_run TEXT, last_error TEXT
);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    question TEXT, model TEXT, context TEXT, answer TEXT
);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _connect():
    """A fresh connection with Row access. Reads DB_PATH live (test-overridable)."""
    Path(SOC_DIR).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables/indexes if absent. Idempotent — safe to call every start."""
    with _LOCK, _connect() as c:
        c.executescript(_SCHEMA)


def event_hash(ts, source, raw):
    """Deterministic dedupe fingerprint for a raw event."""
    return hashlib.sha256(f"{ts}|{source}|{raw}".encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# Inserts — each takes the caller's dict; severity is passed through, not guessed
# ---------------------------------------------------------------------------

def insert_event(e):
    """Insert one raw event (deduped by event_hash). Returns True if it was new.

    `severity` is stored exactly as the caller supplies it (a source-reported
    level or ""), never derived from message text here."""
    ts = e.get("ts") or now_iso()
    raw = str(e.get("raw") if e.get("raw") is not None else e.get("message", ""))
    mitre = e.get("mitre")
    if isinstance(mitre, (list, dict)):
        mitre = json.dumps(mitre, ensure_ascii=False)
    fp = e.get("event_hash") or event_hash(ts, e.get("source", ""), raw)
    vals = (ts, e.get("source", ""), e.get("source_type", "file"),
            e.get("category", ""), e.get("host", ""), e.get("src_ip", ""),
            e.get("dst_ip", ""), e.get("user", ""), e.get("event_id", ""),
            e.get("severity", ""), e.get("action", ""), e.get("message", raw),
            raw, mitre or "", fp)
    with _LOCK, _connect() as c:
        cur = c.execute(
            """INSERT OR IGNORE INTO events
               (ts,source,source_type,category,host,src_ip,dst_ip,user,event_id,
                severity,action,message,raw,mitre,event_hash)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
        return cur.rowcount > 0


def insert_asset(a):
    with _LOCK, _connect() as c:
        cur = c.execute(
            """INSERT INTO assets
               (ts,ip,hostname,mac,category,vendor,model,os,ports,source,status,risk)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (a.get("ts") or now_iso(), a.get("ip", ""), a.get("hostname", ""),
             a.get("mac", ""), a.get("category", ""), a.get("vendor", ""),
             a.get("model", ""), a.get("os", ""), a.get("ports", ""),
             a.get("source", ""), a.get("status", ""), float(a.get("risk", 0) or 0)))
        return cur.lastrowid


def insert_vuln(v):
    with _LOCK, _connect() as c:
        cur = c.execute(
            """INSERT INTO vulnerabilities
               (ts,asset_ip,name,cve,severity,cvss,details,source,status)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (v.get("ts") or now_iso(), v.get("asset_ip", ""), v.get("name", ""),
             v.get("cve", ""), v.get("severity", ""), float(v.get("cvss", 0) or 0),
             v.get("details", ""), v.get("source", ""), v.get("status", "OPEN")))
        return cur.lastrowid


def insert_ioc(i):
    with _LOCK, _connect() as c:
        cur = c.execute(
            """INSERT INTO iocs
               (ts,ioc,ioc_type,provider,score,verdict,details,source_event_id)
               VALUES(?,?,?,?,?,?,?,?)""",
            (i.get("ts") or now_iso(), i.get("ioc", ""), i.get("ioc_type", ""),
             i.get("provider", ""), float(i.get("score", 0) or 0),
             i.get("verdict", ""), i.get("details", ""), i.get("source_event_id")))
        return cur.lastrowid


def insert_investigation(question, model, context, answer):
    with _LOCK, _connect() as c:
        cur = c.execute(
            "INSERT INTO investigations(ts,question,model,context,answer) VALUES(?,?,?,?,?)",
            (now_iso(), question, model, context, answer))
        return cur.lastrowid


def upsert_connector(name, kind="", config=None, enabled=None, interval=None,
                     last_run=None, last_error=None):
    """Create or update a connector row by name. Only the fields you pass change."""
    cfg = json.dumps(config, ensure_ascii=False) if isinstance(config, (dict, list)) else config
    with _LOCK, _connect() as c:
        c.execute("INSERT OR IGNORE INTO connectors(name) VALUES(?)", (name,))
        sets, params = [], []
        for col, val in (("kind", kind), ("config_json", cfg),
                         ("enabled", None if enabled is None else int(bool(enabled))),
                         ("interval", interval), ("last_run", last_run),
                         ("last_error", last_error)):
            if val is not None:
                sets.append(f"{col}=?")
                params.append(val)
        if sets:
            params.append(name)
            c.execute(f"UPDATE connectors SET {', '.join(sets)} WHERE name=?", params)


# ---------------------------------------------------------------------------
# Settings — secrets stored but NEVER returned
# ---------------------------------------------------------------------------

def is_secret_key(key):
    k = key.lower()
    return any(h in k for h in SECRET_HINTS)


def set_setting(key, value):
    with _LOCK, _connect() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, "" if value is None else str(value)))


def get_setting(key, default=""):
    """Direct value read — for server-side use only (e.g. a connector reading its
    own API key). NEVER route this to the browser; use public_settings() there."""
    with _LOCK, _connect() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r[0] if r else default


def public_settings():
    """Browser-safe settings view. Non-secret keys return their value; secret
    keys return only whether a non-empty value is present — never the value."""
    settings, secrets = {}, {}
    with _LOCK, _connect() as c:
        for row in c.execute("SELECT key,value FROM settings ORDER BY key"):
            if is_secret_key(row["key"]):
                secrets[row["key"]] = bool(row["value"])
            else:
                settings[row["key"]] = row["value"]
    return {"settings": settings, "secrets": secrets}


def retention_days():
    try:
        return int(get_setting("retention_days", str(DEFAULT_RETENTION_DAYS)))
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS


# ---------------------------------------------------------------------------
# Queries — filtered + paginated, column names whitelisted (no SQL injection)
# ---------------------------------------------------------------------------

# Per table: which columns may be filtered by exact match, and which are scanned
# by the free-text `q` (LIKE). Values are always parameterized.
_QUERYABLE = {
    "events": {"exact": {"severity", "category", "source", "source_type",
                         "host", "src_ip", "dst_ip", "user"},
               "text": ("message", "raw", "host", "src_ip")},
    "assets": {"exact": {"ip", "hostname", "category", "vendor", "status", "source"},
               "text": ("ip", "hostname", "os", "vendor")},
    "vulnerabilities": {"exact": {"asset_ip", "severity", "status", "cve", "source"},
                        "text": ("name", "cve", "details", "asset_ip")},
    "iocs": {"exact": {"ioc_type", "provider", "verdict"},
             "text": ("ioc", "details")},
    "connectors": {"exact": {"kind", "name"}, "text": ("name", "kind")},
    "investigations": {"exact": {"model"}, "text": ("question", "answer")},
}


def query(table, filters=None, q=None, since=None, until=None, limit=100, offset=0):
    """Filtered, paginated read. Returns {items, total, limit, offset}. An empty
    table (or no matches) is an honest empty list, never a fabricated row."""
    spec = _QUERYABLE[table]                      # KeyError = programmer error
    where, params = [], []
    for k, v in (filters or {}).items():
        if k in spec["exact"] and v not in (None, ""):
            where.append(f"{k}=?")
            params.append(v)
    if q:
        cols = spec["text"]
        where.append("(" + " OR ".join(f"{c} LIKE ?" for c in cols) + ")")
        params.extend([f"%{q}%"] * len(cols))
    if since and "ts" not in spec.get("no_ts", ()):
        where.append("ts>=?")
        params.append(since)
    if until:
        where.append("ts<=?")
        params.append(until)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    order = "name" if table == "connectors" else "ts DESC, id DESC"
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    with _LOCK, _connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {table}{clause}", params).fetchone()[0]
        rows = c.execute(
            f"SELECT * FROM {table}{clause} ORDER BY {order} LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
    items = [_row_to_public(table, r) for r in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _row_to_public(table, row):
    d = dict(row)
    if table == "connectors":
        # Never leak a connector's raw config blob (may hold secrets); report
        # only whether it is configured.
        d["hasConfig"] = bool(d.pop("config_json", None))
        d["enabled"] = bool(d.get("enabled"))
    return d


def metrics():
    """Command-Center KPI counts. `critical`/`high` are counts of events whose
    SOURCE-REPORTED severity equals that label — NOT anomaly verdicts. `iocHits`
    counts IOCs whose verdict marks them malicious or suspicious."""
    with _LOCK, _connect() as c:
        def one(sql, params=()):
            return c.execute(sql, params).fetchone()[0]
        return {
            "events": one("SELECT COUNT(*) FROM events"),
            "critical": one("SELECT COUNT(*) FROM events WHERE UPPER(severity)=?", ("CRITICAL",)),
            "high": one("SELECT COUNT(*) FROM events WHERE UPPER(severity)=?", ("HIGH",)),
            "assets": one("SELECT COUNT(*) FROM assets"),
            "openVulns": one("SELECT COUNT(*) FROM vulnerabilities WHERE UPPER(status)=?", ("OPEN",)),
            "iocHits": one("SELECT COUNT(*) FROM iocs WHERE LOWER(verdict) IN (?,?)",
                           ("malicious", "suspicious")),
        }


# ---------------------------------------------------------------------------
# Retention + purge
# ---------------------------------------------------------------------------

def cleanup(days=None):
    """Delete history rows older than `days` (default: the stored retention).
    Returns {table: rows_deleted}. Configuration tables are never touched."""
    days = retention_days() if days is None else int(days)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    deleted = {}
    with _LOCK, _connect() as c:
        for table in HISTORY_TABLES:
            cur = c.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
            deleted[table] = cur.rowcount
    set_setting("retention_days", str(days))
    return deleted


def purge():
    """FULL wipe of every data table (history + connectors). Settings survive
    (they hold retention config + secret presence). Returns {table: rows_deleted}.
    The caller (serve.py) requires an explicit confirm before invoking this."""
    deleted = {}
    with _LOCK, _connect() as c:
        for table in ALL_DATA_TABLES:
            cur = c.execute(f"DELETE FROM {table}")
            deleted[table] = cur.rowcount
    return deleted
