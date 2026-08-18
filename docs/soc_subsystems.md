# SOC subsystems — data model and API contract (Phase B)

The contract the React frontend (Phase A) builds against. Every subsystem
below follows one honesty rule: **a value is either derived from data that
actually exists (parsed events, rule findings, saved runs, files on disk) or
entered by the analyst — never fabricated.** Where the honest answer is "not
enough data", the API returns `null` (and says why here), and the UI must
render that as *n/a*, never as zero-that-looks-like-good-news.

Rules own severity; the LLM only explains. Nothing in these subsystems can
change, suppress, or escalate a finding's severity. Incident/asset severity
labels below are **aggregations for display**, not new verdicts.

All stores live in `console/.soc/` (gitignored, like `console/.runs/`):

    console/.soc/incidents.json     derived incidents + analyst lifecycle
    console/.soc/cases.json         analyst-created cases (pure user data)
    console/.soc/reports/           generated report artifacts (HTML exports)

Logic lives in the sibling module `console/soc.py`; `console/serve.py` only
routes. The detector (`anomaly_detector.py`) is frozen and untouched.

---

## 1. Incidents — `GET /api/incidents`, `GET /api/incidents/<id>`, `POST /api/incidents/<id>/state`

**What an incident is.** A correlated cluster of the current run's findings.
The correlation rule (deterministic, documented here, implemented in
`soc.derive_incidents`):

1. Each finding's **primary entity** is the first IP among its chips; else its
   derived host; else its rule type. (These are values the parser actually
   observed — nothing is inferred.)
2. Findings with the same primary entity are sorted by timestamp and
   **chain-linked**: a gap of ≤ 30 minutes extends the cluster; a larger gap
   starts a new incident. Findings without timestamps join the entity's first
   cluster (stated in `timeUncertain`).
3. An incident is only ever created from ≥ 1 real finding. Empty incidents
   cannot exist.

Derived incidents are upserted into the store by a **deterministic id**
(`inc-<sha1(runId|entity|firstStamp)[:12]>`), so re-analyzing the same run
does not duplicate them and analyst lifecycle edits survive re-derivation.

**Lifecycle** (analyst-entered, the only mutable part):
`new → acknowledged → investigating → resolved`. `createdAt` = the earliest
finding timestamp (detection time, from the log itself — not "when the row
was written"). `acknowledgedAt` is stamped on the first transition out of
`new`; `resolvedAt` when entering `resolved`. Timestamps the analyst never
caused stay `null`.

Shape (list returns `{"incidents": [...]}`; `?state=<state>` filters; item
endpoint returns one object; unknown id → 404):

```json
{
  "id": "inc-3f2a9c1b04de",
  "runId": "attack-2026-08-18",
  "entity": "203.0.113.44",
  "entityKind": "ip | host | rule",
  "title": "203.0.113.44 — 3 correlated finding(s)",
  "severity": "CRITICAL",              // max member severity (display aggregation)
  "state": "new | acknowledged | investigating | resolved",
  "findingIds": ["detector-0", "detector-1"],
  "findingCount": 2,
  "techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
  "attackerStatus": "Spreading Inside",   // via tactic_phase_map; "" when unmapped
  "createdAt": "2026-08-13T02:16:44+00:00",   // earliest finding time = detection
  "firstSeen": "…", "lastSeen": "…",
  "acknowledgedAt": null,               // set by the analyst, else null
  "resolvedAt": null,
  "timeUncertain": false                // true when a member had no timestamp
}
```

`POST /api/incidents/<id>/state` body `{"state": "acknowledged"}` — allowed
values above; the response is the updated incident. Moving backwards is
allowed (a mistaken resolve can be reopened) but never erases a timestamp
already earned; `resolvedAt` clears only when leaving `resolved` (documented
so MTTR can't be gamed by accident).

## 2. Assets & users — `GET /api/assets`, `GET /api/users`

Derived **only from entities the parser actually observed** in the current
run: hosts come from parsed events, IPs from finding entities/chips, usernames
extracted from event messages and finding titles with the same patterns the
redaction module uses (`console/redact.py` — one vocabulary, two uses). There
is no inventory to invent: an asset that never appeared in a log does not
exist here.

```json
GET /api/assets -> { "assets": [
  { "id": "asset-host-app-01", "name": "app-01", "kind": "host | ip",
    "events": 143, "findings": 2, "atRisk": true,     // atRisk = ≥1 finding
    "lastSeen": "2026-08-13T02:18:00+00:00" } ] }     // null if no timestamps

GET /api/users -> { "users": [
  { "id": "user-admin", "name": "admin",
    "events": 6, "findings": 1, "atRisk": true } ] }
```

Both return `{"error": "no run yet…"}` when the server is idle — an empty
inventory would be indistinguishable from "no assets are at risk".

## 3. Cases — `GET/POST /api/cases`, `GET/PATCH /api/cases/<id>`

Pure analyst-entered data (that is what makes storing it honest). CRUD over
`cases.json`:

```json
{ "id": "case-1", "title": "Investigate 203.0.113.44",
  "notes": "…", "assignee": "",
  "status": "open | investigating | closed",
  "links": { "findings": ["detector-0"], "incidents": ["inc-…"] },
  "createdAt": "…", "updatedAt": "…" }
```

`POST /api/cases` requires `title`; `notes/assignee/links` optional; status
starts `open`. `PATCH /api/cases/<id>` accepts any subset of
`title, notes, assignee, status, links` and bumps `updatedAt`. Unknown id →
404; unknown status → 400. List returns `{"cases": [...]}` newest first.

## 4. Reports — `GET /api/reports`, `POST /api/reports`

Lists **files that exist** in `console/.soc/reports/`; nothing is listed that
was not generated. `POST /api/reports` (no body needed) renders the CURRENT
run through the existing standalone exporter (`console/export.py`) and saves
it as `<runId>-<UTC stamp>.html`; 409 when no run is loaded.

```json
GET /api/reports -> { "reports": [
  { "name": "attack-2026-08-18-20260818T190301Z.html",
    "bytes": 48213, "createdAt": "2026-08-18T19:03:01+00:00" } ] }
POST /api/reports -> the new entry (same shape)
```

## 5. Threat intel — `GET /api/threat-intel`

Surfaces what `threat_intel/` already holds — no new data is created:

```json
{ "indicators": [ { "id": "indicator--…", "name": "Known brute-force source IP",
                    "pattern": "[ipv4-addr:value = '203.0.113.44']",
                    "types": ["malicious-activity"], "validFrom": "…" } ],
  "indicatorSource": "threat_intel/demo_threat_intel.json (offline STIX bundle)",
  "ruleTechniques": { "auth_bruteforce": [ {"id": "T1110", "name": "…", "tactic": "…"} ] },
  "attackCacheWarm": false }        // is ~/.cache/mitre_attack populated?
```

## 6. Metrics — `GET /api/metrics`

Every field is computed from real lifecycle data or is `null`:

```json
{ "openIncidents": 3,                  // store incidents not resolved
  "mttdSeconds": 420,                  // mean(acknowledgedAt−createdAt), only over
                                       // incidents an analyst acknowledged; null if none
  "mttrSeconds": null,                 // mean(resolvedAt−createdAt) over resolved; null if none
  "mttdBasis": 2, "mttrBasis": 0,      // how many incidents each mean is built on
  "assetsAtRisk": 2, "usersAtRisk": 1, // from the current run; null when idle
  "dataSources": 3 }                   // distinct source labels across saved runs
```

MTTD/MTTR are means over incidents that genuinely carry both timestamps; the
`*Basis` counts say how many that was, so a mean of one incident reads as
what it is. **The UI must render null as "n/a", never 0.**

---

## Phase D design (doc only — NOT built yet): real-time via SSE

`GET /api/stream?source=<bundled sample value>` — `text/event-stream`.

- **Source selection**: only whitelisted sources (the same `resolve_sample`
  whitelist the picker uses, or the currently loaded run's log). No arbitrary
  paths from the browser — same security boundary as `/api/analyze`.
- **Mechanism**: a server thread tails the file (`seek` to EOF, poll every
  0.5 s; inotify/kqueue later). New lines run through the SAME pipeline —
  `normalize` for the envelope, then the frozen detector's rules over a
  sliding window of recent records — so a streamed event is parsed exactly
  like a batch one. No separate "realtime parser" to drift.
- **Event shape**: `event: log` with the standard event dict
  (`{n, ts, level, host, msg, raw, bucket}`), and `event: finding` with the
  adapted finding when a rule fires on the window. A heartbeat
  (`event: ping`) every 15 s keeps proxies from killing the stream.
- **Backpressure**: per-client bounded queue (e.g. 500 events). On overflow
  the server drops oldest **and emits `event: gap` with the dropped count** —
  a silent drop would fake a quiet log. Client reconnect uses
  `Last-Event-ID` = last line number to resume without replaying the file.
- **Honesty**: streaming never bypasses rules; severities still come from the
  detector; LLM explanations stay on-demand only.
