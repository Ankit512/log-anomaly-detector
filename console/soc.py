#!/usr/bin/env python3
"""
soc.py — the SOC subsystems behind /api/incidents, /api/assets, /api/users,
/api/cases, /api/reports, /api/threat-intel and /api/metrics.

One honesty rule governs everything here (see docs/soc_subsystems.md, the
contract the frontend builds against): a value is either DERIVED from data
that actually exists — parsed events, rule findings, saved runs, files on
disk — or ENTERED by the analyst. Nothing is fabricated; where the honest
answer is "not enough data", the answer is null.

Severity stays owned by the detector's rules. An incident's severity is the
max of its members' rule severities — an aggregation for display, never a new
verdict. The LLM appears nowhere in this module.

Stores live in console/.soc/ (gitignored, like .runs/):
    incidents.json   derived incidents + analyst lifecycle fields
    cases.json       analyst-created cases (pure user-entered data)
    reports/         generated report artifacts (standalone HTML exports)

Stdlib only. anomaly_detector.py is never imported or modified.
"""

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "threat_intel"))

import export  # noqa: E402
import redact  # noqa: E402
from rule_mitre_map import RULE_TECHNIQUES  # noqa: E402
from tactic_phase_map import phase_for_tactics  # noqa: E402

SOC_DIR = HERE / ".soc"                       # monkeypatched to a tmp dir in tests

INCIDENT_STATES = ("new", "acknowledged", "investigating", "resolved")
CASE_STATUSES = ("open", "investigating", "closed")
CLUSTER_GAP_SECONDS = 30 * 60                 # the documented correlation window

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# JSON stores
# ---------------------------------------------------------------------------

def _load(name):
    path = SOC_DIR / name
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save(name, data):
    SOC_DIR.mkdir(parents=True, exist_ok=True)
    (SOC_DIR / name).write_text(json.dumps(data, indent=1))


# ---------------------------------------------------------------------------
# Incidents — correlated clusters of real findings
# ---------------------------------------------------------------------------

def _primary_entity(finding):
    """The entity a finding is about: first IP chip, else derived host, else
    its rule type. All three are values the parser actually observed."""
    for chip in finding.get("chips") or []:
        text = str(chip.get("text", ""))
        if redact.IPV4_RE.fullmatch(text):
            return text, "ip"
    if finding.get("hostDerived") and finding.get("host") not in (None, "", "—"):
        return finding["host"], "host"
    return finding.get("type") or "finding", "rule"


def derive_incidents(state):
    """Cluster the run's findings by shared entity + ≤30-minute chain gaps.

    Deterministic and documented in docs/soc_subsystems.md. An incident is
    only ever built from ≥1 real finding — there is no other source.
    """
    by_entity = {}
    for f in state.get("findings", []):
        entity, kind = _primary_entity(f)
        by_entity.setdefault((entity, kind), []).append(f)

    incidents = []
    for (entity, kind), members in by_entity.items():
        stamped = sorted((f for f in members if _parse_ts(f.get("stamp"))),
                         key=lambda f: f["stamp"])
        unstamped = [f for f in members if not _parse_ts(f.get("stamp"))]

        clusters = []
        for f in stamped:
            if clusters and (_parse_ts(f["stamp"])
                             - _parse_ts(clusters[-1][-1]["stamp"])
                             ).total_seconds() <= CLUSTER_GAP_SECONDS:
                clusters[-1].append(f)
            else:
                clusters.append([f])
        if unstamped:                          # join the first cluster; flagged below
            if clusters:
                clusters[0].extend(unstamped)
            else:
                clusters.append(unstamped)

        for members in clusters:
            stamps = sorted(f["stamp"] for f in members if _parse_ts(f.get("stamp")))
            first = stamps[0] if stamps else None
            techniques, tactics = [], []
            for f in members:
                for t in f.get("mitre") or []:
                    if all(t["id"] != x["id"] for x in techniques):
                        techniques.append({"id": t["id"], "name": t["name"],
                                           "tactic": t["tactic"]})
                    if t["tactic"] not in tactics:
                        tactics.append(t["tactic"])
            sev = min((str(f.get("sev", "INFO")).upper() for f in members),
                      key=lambda s: SEV_RANK.get(s, 5))
            raw_id = f"{state.get('runId', '')}|{entity}|{first or 'no-stamp'}"
            incidents.append({
                "id": "inc-" + hashlib.sha1(raw_id.encode()).hexdigest()[:12],
                "runId": state.get("runId", ""),
                "entity": entity,
                "entityKind": kind,
                "title": f"{entity} — {len(members)} correlated finding(s)",
                "severity": sev,
                "findingIds": [f.get("id") for f in members],
                "findingCount": len(members),
                "techniques": techniques,
                "attackerStatus": phase_for_tactics(tactics),
                "createdAt": first,            # detection = earliest finding time
                "firstSeen": first,
                "lastSeen": stamps[-1] if stamps else None,
                "timeUncertain": bool(unstamped),
            })
    return incidents


def sync_incidents(state):
    """Upsert derived incidents into the store, preserving analyst lifecycle.

    Deterministic ids make this idempotent: re-analyzing the same run updates
    the derived fields of an existing incident and never duplicates it or
    erases the analyst's state/acknowledgedAt/resolvedAt."""
    store = _load("incidents.json")
    for inc in derive_incidents(state):
        prev = store.get(inc["id"], {})
        inc["state"] = prev.get("state", "new")
        inc["acknowledgedAt"] = prev.get("acknowledgedAt")
        inc["resolvedAt"] = prev.get("resolvedAt")
        store[inc["id"]] = inc
    _save("incidents.json", store)
    return store


def list_incidents(state=None, state_filter=None):
    """All stored incidents, newest detection first. Syncs from the current
    run first when one is loaded, so the list always reflects real findings."""
    if state and not state.get("idle"):
        store = sync_incidents(state)
    else:
        store = _load("incidents.json")
    out = sorted(store.values(), key=lambda i: i.get("createdAt") or "", reverse=True)
    if state_filter:
        out = [i for i in out if i.get("state") == state_filter]
    return out


def get_incident(iid):
    return _load("incidents.json").get(iid)


def set_incident_state(iid, new_state):
    """Analyst lifecycle transition. Timestamps record what actually happened:
    acknowledgedAt on the first move out of 'new', resolvedAt on entering
    'resolved' (cleared when a mistaken resolve is reopened). Returns the
    updated incident, or None for an unknown id; ValueError on a bad state."""
    if new_state not in INCIDENT_STATES:
        raise ValueError(f"state must be one of {INCIDENT_STATES}")
    store = _load("incidents.json")
    inc = store.get(iid)
    if not inc:
        return None
    if new_state != "new" and not inc.get("acknowledgedAt"):
        inc["acknowledgedAt"] = _now()
    if new_state == "resolved" and not inc.get("resolvedAt"):
        inc["resolvedAt"] = _now()
    if new_state != "resolved":
        inc["resolvedAt"] = None
    inc["state"] = new_state
    _save("incidents.json", store)
    return inc


# ---------------------------------------------------------------------------
# Assets & users — observed entities only
# ---------------------------------------------------------------------------

def derive_assets(state):
    """Hosts seen in parsed events + IPs seen in findings. Nothing else exists."""
    assets = {}

    def touch(name, kind):
        key = (kind, name)
        if key not in assets:
            assets[key] = {"id": f"asset-{kind}-{name}", "name": name, "kind": kind,
                           "events": 0, "findings": 0, "atRisk": False,
                           "lastSeen": None}
        return assets[key]

    for e in state.get("events", []):
        if e.get("host"):
            a = touch(e["host"], "host")
            a["events"] += 1
            if e.get("ts") and (a["lastSeen"] or "") < e["ts"]:
                a["lastSeen"] = e["ts"]

    for f in state.get("findings", []):
        if f.get("hostDerived") and f.get("host") not in (None, "", "—"):
            a = touch(f["host"], "host")
            a["findings"] += 1
            a["atRisk"] = True
        for chip in f.get("chips") or []:
            text = str(chip.get("text", ""))
            if redact.IPV4_RE.fullmatch(text):
                a = touch(text, "ip")
                a["findings"] += 1
                a["atRisk"] = True
                if f.get("stamp") and (a["lastSeen"] or "") < f["stamp"]:
                    a["lastSeen"] = f["stamp"]

    return sorted(assets.values(),
                  key=lambda a: (-a["findings"], -a["events"], a["name"]))


def derive_users(state):
    """Usernames actually present in event messages and finding titles,
    extracted with the SAME patterns the redaction pass masks (one vocabulary,
    two uses). No user directory is invented."""
    users = {}

    def found_in(text):
        for pat in redact.USER_PATTERNS:
            for m in pat.finditer(text or ""):
                yield m.group("u")

    for e in state.get("events", []):
        for name in found_in(e.get("msg")):
            u = users.setdefault(name, {"id": f"user-{name}", "name": name,
                                        "events": 0, "findings": 0, "atRisk": False})
            u["events"] += 1
    for f in state.get("findings", []):
        for name in set(found_in(f.get("title"))):
            u = users.setdefault(name, {"id": f"user-{name}", "name": name,
                                        "events": 0, "findings": 0, "atRisk": False})
            u["findings"] += 1
            u["atRisk"] = True

    return sorted(users.values(), key=lambda u: (-u["findings"], -u["events"], u["name"]))


# ---------------------------------------------------------------------------
# Cases — analyst-entered, so storing them IS the honest source
# ---------------------------------------------------------------------------

def list_cases():
    store = _load("cases.json")
    return sorted(store.values(), key=lambda c: c.get("createdAt") or "", reverse=True)


def get_case(cid):
    return _load("cases.json").get(cid)


def create_case(payload):
    title = str(payload.get("title") or "").strip()
    if not title:
        raise ValueError("a case needs a title")
    store = _load("cases.json")
    cid = f"case-{max((int(k.split('-')[1]) for k in store), default=0) + 1}"
    case = {
        "id": cid,
        "title": title[:200],
        "notes": str(payload.get("notes") or "")[:10000],
        "assignee": str(payload.get("assignee") or "")[:100],
        "status": "open",
        "links": {
            "findings": [str(x) for x in (payload.get("links") or {}).get("findings", [])],
            "incidents": [str(x) for x in (payload.get("links") or {}).get("incidents", [])],
        },
        "createdAt": _now(),
        "updatedAt": _now(),
    }
    store[cid] = case
    _save("cases.json", store)
    return case


def patch_case(cid, payload):
    """Update any subset of title/notes/assignee/status/links. None for an
    unknown id; ValueError for an invalid field value."""
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    if "status" in payload:
        if payload["status"] not in CASE_STATUSES:
            raise ValueError(f"status must be one of {CASE_STATUSES}")
        case["status"] = payload["status"]
    if "title" in payload:
        title = str(payload["title"] or "").strip()
        if not title:
            raise ValueError("a case needs a title")
        case["title"] = title[:200]
    if "notes" in payload:
        case["notes"] = str(payload["notes"] or "")[:10000]
    if "assignee" in payload:
        case["assignee"] = str(payload["assignee"] or "")[:100]
    if "links" in payload:
        links = payload["links"] or {}
        case["links"] = {
            "findings": [str(x) for x in links.get("findings", [])],
            "incidents": [str(x) for x in links.get("incidents", [])],
        }
    case["updatedAt"] = _now()
    _save("cases.json", store)
    return case


# ---------------------------------------------------------------------------
# Reports — files that exist, plus a generate action
# ---------------------------------------------------------------------------

def _reports_dir():
    d = SOC_DIR / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_reports():
    out = []
    for path in sorted(_reports_dir().glob("*.html"),
                       key=lambda p: p.stat().st_mtime, reverse=True):
        st = path.stat()
        out.append({"name": path.name, "bytes": st.st_size,
                    "createdAt": datetime.fromtimestamp(
                        st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")})
    return out


def generate_report(state):
    """Render the current run through the existing standalone exporter."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_run = re.sub(r"[^A-Za-z0-9._-]", "_", state.get("runId") or "run")
    path = _reports_dir() / f"{safe_run}-{stamp}.html"
    path.write_text(export.build(state))
    st = path.stat()
    return {"name": path.name, "bytes": st.st_size,
            "createdAt": datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")}


# ---------------------------------------------------------------------------
# Threat intel — surface what threat_intel/ already holds
# ---------------------------------------------------------------------------

def threat_intel_summary():
    indicators = []
    bundle_path = ROOT / "threat_intel" / "demo_threat_intel.json"
    try:
        bundle = json.loads(bundle_path.read_text())
    except (OSError, json.JSONDecodeError):
        bundle = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            indicators.append({"id": obj.get("id"), "name": obj.get("name"),
                               "pattern": obj.get("pattern"),
                               "types": obj.get("indicator_types", []),
                               "validFrom": obj.get("valid_from")})
    return {
        "indicators": indicators,
        "indicatorSource": "threat_intel/demo_threat_intel.json (offline STIX bundle)",
        "ruleTechniques": {k: [dict(t) for t in v] for k, v in RULE_TECHNIQUES.items()},
        "attackCacheWarm": any((Path.home() / ".cache" / "mitre_attack").glob("*")
                               ) if (Path.home() / ".cache" / "mitre_attack").exists()
                             else False,
    }


# ---------------------------------------------------------------------------
# Metrics — real lifecycle math or null, never a made-up number
# ---------------------------------------------------------------------------

def _mean_seconds(pairs):
    """Mean duration over (start, end) iso pairs that BOTH exist. (value, basis)."""
    durations = []
    for start, end in pairs:
        a, b = _parse_ts(start), _parse_ts(end)
        if a and b and b >= a:
            durations.append((b - a).total_seconds())
    if not durations:
        return None, 0
    return round(sum(durations) / len(durations)), len(durations)


def metrics(state, run_labels=()):
    incidents = list(_load("incidents.json").values())
    mttd, mttd_basis = _mean_seconds(
        (i.get("createdAt"), i.get("acknowledgedAt")) for i in incidents)
    mttr, mttr_basis = _mean_seconds(
        (i.get("createdAt"), i.get("resolvedAt"))
        for i in incidents if i.get("state") == "resolved")

    idle = not state or state.get("idle")
    return {
        "openIncidents": sum(1 for i in incidents if i.get("state") != "resolved"),
        "mttdSeconds": mttd, "mttdBasis": mttd_basis,
        "mttrSeconds": mttr, "mttrBasis": mttr_basis,
        # Per-run derivations have no honest value without a run.
        "assetsAtRisk": None if idle else sum(
            1 for a in derive_assets(state) if a["atRisk"]),
        "usersAtRisk": None if idle else sum(
            1 for u in derive_users(state) if u["atRisk"]),
        "dataSources": len({label for label in run_labels if label}),
    }
