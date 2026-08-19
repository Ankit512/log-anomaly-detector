# SOC Command Center — persistent store & API contract

The shared foundation the SOC Command Center features write to. Implemented in
`console/store.py` (stdlib `sqlite3` only) and served by `console/serve.py` under
`/api/store/*`. **This document is the contract**: the four upcoming feature
tracks (EVTX ingest, live syslog, nmap discovery, threat-intel/OEM enrichment)
build against the tables and endpoints below.

## Honesty model (non-negotiable)

- **Raw is verbatim.** `events.raw` is the real source line. Nothing rewrites evidence.
- **Severity is source-reported, not a verdict.** `events.severity` holds the level the
  *source* asserted (or `""` when it gave none). The store **never** keyword-guesses a
  severity. Anomaly verdicts still come only from the frozen rules/detector
  (`anomaly_detector.py`); a stored level is a fact the source reported, never presented as
  our judgment. KPI counts of `CRITICAL`/`HIGH` events are counts of that *source-reported*
  label — label them as such in any UI.
- **Empty means empty.** Every read returns an honest `{"items": []}` (or zero counts) when a
  table is empty. Never seed sample/demo rows.
- **Secrets are write-only.** Settings whose key contains `key`, `token`, `secret`,
  `password`, or `credential` are stored but **never returned** — a read reports only whether
  a value is present. Connector `config_json` is likewise never returned to the browser.

Storage: `console/.soc/soc_history.db` (gitignored, alongside `.runs/` and the other `.soc`
stores). `store.init_db()` is idempotent and called at server start and on first store request.

---

## Schema

### `events` — raw, deduplicated log/security events
| column | type | notes |
|---|---|---|
| `id` | INTEGER PK | autoincrement |
| `ts` | TEXT | ISO-8601 UTC; required |
| `source` | TEXT | logical source name (file, connector, host) |
| `source_type` | TEXT | `file` \| `syslog` \| `evtx` \| `connector` \| … |
| `category` | TEXT | e.g. `Firewall`, `Windows`, `Network` (source-classified, optional) |
| `host` | TEXT | |
| `src_ip`, `dst_ip` | TEXT | |
| `user` | TEXT | |
| `event_id` | TEXT | e.g. a Windows Event ID |
| `severity` | TEXT | **source-reported** level or `""` — never guessed |
| `action` | TEXT | e.g. `allow`/`deny`/`login` |
| `message` | TEXT | human-readable line (defaults to `raw`) |
| `raw` | TEXT | the real source line, verbatim |
| `mitre` | TEXT | optional derived tag(s), JSON or plain; display only |
| `event_hash` | TEXT UNIQUE | dedupe fingerprint (`sha256(ts\|source\|raw)`); `INSERT OR IGNORE` |

Indexes: `ts`, `(src_ip,dst_ip)`, `severity`.

### `assets` — discovered / observed hosts
`id, ts, ip, hostname, mac, category, vendor, model, os, ports, source, status, risk(REAL)`.
Index: `ip`.

### `vulnerabilities`
`id, ts, asset_ip, name, cve, severity, cvss(REAL), details, source, status` (`status`
defaults `OPEN`). Index: `asset_ip`.

### `iocs` — indicator lookups / hits
`id, ts, ioc, ioc_type, provider, score(REAL), verdict, details, source_event_id`. Index: `ioc`.
An IOC is a **hit** for metrics when `verdict` is `malicious` or `suspicious`.

### `connectors` — connector configuration
`name(PK), kind, config_json, enabled(INT 0/1), interval(INT seconds), last_run, last_error`.
`config_json` is an opaque per-connector JSON blob — **never returned to the browser**
(reads expose `hasConfig` + `enabled` only).

### `settings` — `key(PK), value`
Secret keys (see honesty model) are stored but never returned.

### `investigations` — saved analyst Q&A
`id, ts, question, model, context, answer`.

Retention applies to the history tables (`events, assets, vulnerabilities, iocs,
investigations`); `connectors` and `settings` are configuration and never auto-expired.

---

## `console/store.py` API (for the feature workers — same process)

```
init_db()                                  # idempotent
insert_event(dict) -> bool                 # True if new, False if deduped
insert_asset(dict) -> id
insert_vuln(dict) -> id
insert_ioc(dict) -> id
insert_investigation(question, model, context, answer) -> id
upsert_connector(name, kind=, config=, enabled=, interval=, last_run=, last_error=)
set_setting(key, value)  /  get_setting(key, default="")   # get_setting is SERVER-SIDE only
public_settings() -> {"settings": {...}, "secrets": {key: bool}}   # browser-safe
query(table, filters={}, q=None, since=None, until=None, limit=100, offset=0)
    -> {"items": [...], "total": N, "limit": L, "offset": O}
metrics() -> {events, critical, high, assets, openVulns, iocHits}
cleanup(days=None) -> {table: rows_deleted}     # default: stored retention_days (90)
purge() -> {table: rows_deleted}                # full wipe of data tables
```

`query()` whitelists filter columns per table, so unknown query params are safely ignored;
values are always parameterized. `severity` is stored as given — callers pass the
source-reported level, or `""`.

---

## HTTP endpoints (`/api/store/*`)

### Reads (GET)
| endpoint | returns |
|---|---|
| `GET /api/store/events` | `{items, total, limit, offset}` |
| `GET /api/store/assets` | `{items, …}` |
| `GET /api/store/vulns` | `{items, …}` (table `vulnerabilities`) |
| `GET /api/store/iocs` | `{items, …}` |
| `GET /api/store/connectors` | `{items, …}` — each item has `hasConfig`, `enabled`; no raw config |
| `GET /api/store/settings` | `{"settings": {...}, "secrets": {key: bool}}` |
| `GET /api/store/metrics` | `{events, critical, high, assets, openVulns, iocHits}` |

Common query params on the table reads: any whitelisted column (exact match, e.g.
`?severity=HIGH&src_ip=203.0.113.44`), `q` (free-text LIKE over that table's text columns),
`since`/`until` (ISO ts bounds), `limit` (≤1000, default 100), `offset`. Empty table →
`{"items": [], "total": 0, …}`.

### Writes (POST, JSON body)
| endpoint | body | effect |
|---|---|---|
| `POST /api/store/settings` | `{"settings": {k: v}}` or `{"key","value"}` | upsert; returns `public_settings()` |
| `POST /api/store/cleanup` | `{"days": N}` (optional) | retention purge of history older than N days (default stored `retention_days`); returns `{deleted:{table:n}, retentionDays}` |
| `POST /api/store/purge` | `{"confirm": true}` | **full wipe** of all data tables; without `confirm:true` → `400` |

Event ingestion is done **in-process** via `store.insert_*` by each feature/connector — there
is intentionally no public "POST an event" endpoint (the browser never asserts raw events).

---

## How the four feature tracks map to the store

| Feature | Writes | Notes |
|---|---|---|
| **EVTX ingest** | `events` (`source_type="evtx"`, `event_id`, `user`, `host`, source-reported `severity`) | parse .evtx → `insert_event` per record; dedupe via `event_hash`. Feed anomaly findings through the frozen detector separately — the store keeps the raw event. |
| **Live syslog** | `events` (`source_type="syslog"`) | tail/receive syslog → `insert_event`; `severity` from the syslog PRI/level, never guessed. |
| **nmap discovery** | `assets` (+ optional `vulnerabilities`) | scan → `insert_asset` (ip/hostname/mac/os/ports/vendor); NSE vuln scripts → `insert_vuln` (`status="OPEN"`). Register the scan as a `connector` (`kind="discovery"`). |
| **TI / OEM enrichment** | `iocs` (+ `connectors`, `settings`) | look up event IPs/domains → `insert_ioc` with `provider`, `verdict`, `score`, `source_event_id`; store provider API keys as **secret** settings (masked on read). |

Each track owns its connector row (`upsert_connector`) for `enabled`/`interval`/`last_run`/
`last_error`, and reads its own API keys server-side via `get_setting` — never returning them
to the browser.
