"""Threat-Intel enrichment + OEM/API polling (socf-ti-oem).

Two *sibling* subsystems for the SOC Command Center, both writing to the
persistent store (`console/store.py`, contract in `docs/soc_command_center.md`).
Stdlib only — `urllib`/`json`/`sqlite3`; no `requests`, no `pandas`.

Honesty / credentials posture (non-negotiable):

* **All credentials are user-supplied and write-only.** OTX / AbuseIPDB API keys
  and OEM vendor tokens are stored via `store.set_setting` under secret-hinted
  keys, so the store masks them: reads expose only *whether* a value is present
  (`hasKey`), never the value. Nothing here hardcodes or invents a credential.
* **Never fabricate a verdict.** An IOC's score/verdict comes straight from the
  provider's real response (OTX pulse count, AbuseIPDB confidence) — never
  keyword-guessed. An OEM event's severity is the level the vendor API itself
  reported, or empty.
* **Honest "not configured" and honest errors.** With no key set we say so and
  do not call out. A failed external call surfaces the real error and stores
  nothing — never a fake MATCH or a fabricated event.
* **External calls only to user-configured endpoints, always with a timeout.**
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import store

HTTP_TIMEOUT = 15

# Provider API bases. Module-level so a test can point them at a local stub;
# in production these are the real OTX / AbuseIPDB endpoints and nothing else.
OTX_BASE = "https://otx.alienvault.com"
ABUSE_BASE = "https://api.abuseipdb.com"

# Settings keys under which the user's provider keys live (secret-hinted -> the
# store masks them; a read only reveals presence).
OTX_KEY_SETTING = "otx_api_key"
ABUSE_KEY_SETTING = "abuseipdb_api_key"


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _http_get_json(url, headers, timeout=HTTP_TIMEOUT):
    """GET a URL and parse JSON. Raises urllib/OS/JSON errors to the caller,
    which turns them into an honest error string — never a fabricated result."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return json.loads(body.decode("utf-8", "replace") or "null")


# ---------------------------------------------------------------------------
# Threat-Intel enrichment — OTX (AlienVault) + AbuseIPDB.
# ---------------------------------------------------------------------------

def _valid_ip(ip):
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def _enrich_otx(ip, key):
    """Query OTX general indicator. score/verdict derive from the real pulse
    count — never guessed. Returns an ioc dict or raises."""
    url = f"{OTX_BASE}/api/v1/indicators/IPv4/{urllib.parse.quote(ip)}/general"
    data = _http_get_json(url, {"X-OTX-API-KEY": key, "Accept": "application/json"})
    pulses = 0
    if isinstance(data, dict):
        pulses = int((data.get("pulse_info") or {}).get("count", 0) or 0)
    score = float(min(100, pulses * 10))
    # Verdict from the real pulse count (store counts malicious/suspicious as a
    # hit): many pulses => malicious, some => suspicious, none => clean.
    verdict = "malicious" if pulses >= 5 else "suspicious" if pulses > 0 else "clean"
    return {
        "ioc": ip, "ioc_type": "ipv4", "provider": "OTX", "score": score,
        "verdict": verdict, "details": json.dumps({"pulseCount": pulses})[:2000],
    }


def _enrich_abuse(ip, key):
    """Query AbuseIPDB check. score/verdict derive from the real abuse
    confidence score — never guessed. Returns an ioc dict or raises."""
    qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    url = f"{ABUSE_BASE}/api/v2/check?{qs}"
    data = _http_get_json(url, {"Key": key, "Accept": "application/json"})
    d = data.get("data", {}) if isinstance(data, dict) else {}
    score = float(d.get("abuseConfidenceScore", 0) or 0)
    verdict = "malicious" if score >= 50 else "suspicious" if score > 0 else "clean"
    return {
        "ioc": ip, "ioc_type": "ipv4", "provider": "AbuseIPDB", "score": score,
        "verdict": verdict,
        "details": json.dumps({
            "abuseConfidenceScore": score,
            "totalReports": d.get("totalReports"),
            "countryCode": d.get("countryCode"),
            "isp": d.get("isp"),
        })[:2000],
    }


def enrich_ip(ip, source_event_id=None):
    """Enrich one IP via every configured provider. Returns
    {ip, results:[ioc...], errors:[{provider,error}], notConfigured:[provider]}.

    A provider with no key set is reported in `notConfigured` and NOT called. A
    call that fails is reported in `errors` with the real reason and stores
    nothing. Only real provider responses are stored via insert_ioc.
    """
    ip = (ip or "").strip()
    if not _valid_ip(ip):
        return {"ip": ip, "error": "not a valid IP address",
                "results": [], "errors": [], "notConfigured": []}

    results, errors, not_configured = [], [], []
    providers = [
        ("OTX", store.get_setting(OTX_KEY_SETTING, ""), _enrich_otx),
        ("AbuseIPDB", store.get_setting(ABUSE_KEY_SETTING, ""), _enrich_abuse),
    ]
    for name, key, fn in providers:
        if not key:
            not_configured.append(name)
            continue
        try:
            ioc = fn(ip, key)
            ioc["ts"] = _now_iso()
            if source_event_id is not None:
                ioc["source_event_id"] = source_event_id
            store.insert_ioc(ioc)
            results.append(ioc)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                socket.timeout, ValueError, json.JSONDecodeError) as exc:
            errors.append({"provider": name, "error": _explain(exc)})
    return {"ip": ip, "results": results, "errors": errors,
            "notConfigured": not_configured}


def _explain(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code} from provider"
    if isinstance(exc, socket.timeout):
        return "provider request timed out"
    if isinstance(exc, urllib.error.URLError):
        return f"could not reach provider: {getattr(exc, 'reason', exc)}"
    return str(exc)[:300]


def ti_key_status():
    """Which provider keys are configured — presence only, never the value."""
    pub = store.public_settings().get("secrets", {})
    return {
        "otx": bool(pub.get(OTX_KEY_SETTING)),
        "abuseipdb": bool(pub.get(ABUSE_KEY_SETTING)),
    }


# ---------------------------------------------------------------------------
# OEM / API polling — read-only vendor event feeds -> store events.
# ---------------------------------------------------------------------------

# Templates the UI can prefill. The base URLs are PLACEHOLDERS (uppercase host)
# the user must replace; the poller refuses to call a URL that still contains
# one, so an unconfigured connector never makes a bogus request.
OEM_TEMPLATES = {
    "Cisco Firepower": {"vendor": "cisco", "baseUrl": "https://FIREPOWER",
                        "eventsPath": "/api/fdm/v6/events"},
    "Ruckus SmartZone": {"vendor": "ruckus", "baseUrl": "https://SMARTZONE",
                         "eventsPath": "/wsg/api/public/v11_0/events"},
    "ManageEngine Log360": {"vendor": "log360", "baseUrl": "https://LOG360",
                            "eventsPath": "/api/v2/events"},
}
_PLACEHOLDER_HOSTS = ("FIREPOWER", "SMARTZONE", "LOG360", "MANAGEMENT",
                      "FORTIMANAGER", "JUNOS")


def _token_setting(name):
    # Secret-hinted (contains 'token') so the store masks it on read.
    return f"oem_token_{name}"


def create_connector(name, config, enabled=None, interval=None, token=None):
    """Create/update an OEM connector. `config` = {vendor, baseUrl, eventsPath}.
    A supplied token is stored as a SECRET setting (masked, never returned); the
    connector's config keeps only a reference to that setting key.

    Fields are MERGED onto the existing config: a field omitted or left blank
    keeps its stored value, so a plain enable/disable (config={}) never wipes the
    saved URL/token.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("connector name is required")
    existing = _read_config(name) or {}
    config = config or {}

    def pick(field):
        incoming = str(config.get(field, "") or "").strip()
        return incoming if incoming else str(existing.get(field, "") or "")

    cfg = {
        "vendor": pick("vendor"),
        "baseUrl": pick("baseUrl"),
        "eventsPath": pick("eventsPath"),
        "tokenKey": _token_setting(name),
    }
    if token:
        store.set_setting(_token_setting(name), token)
    store.upsert_connector(
        name, kind="oem", config=cfg,
        enabled=enabled, interval=interval)
    return connector_view(name)


def _safe_row(row):
    """A browser-safe connector view: presence flags only, never the config
    blob or the token."""
    return {
        "name": row.get("name"),
        "kind": row.get("kind"),
        "enabled": bool(row.get("enabled")),
        "interval": row.get("interval"),
        "lastRun": row.get("last_run"),
        "lastError": row.get("last_error") or "",
        "hasConfig": bool(row.get("hasConfig")),
        "hasToken": bool(store.get_setting(_token_setting(row.get("name", "")), "")),
    }


def list_connectors():
    rows = store.query("connectors", filters={"kind": "oem"}, limit=1000)["items"]
    return [_safe_row(r) for r in rows]


def connector_view(name):
    rows = store.query("connectors", filters={"name": name}, limit=1)["items"]
    return _safe_row(rows[0]) if rows else None


def _read_config(name):
    """Server-side only: the connector's real config (may include the token
    key). Never returned to the browser."""
    with store._LOCK, store._connect() as c:
        r = c.execute("SELECT config_json FROM connectors WHERE name=?",
                      (name,)).fetchone()
    if not r or not r[0]:
        return None
    try:
        return json.loads(r[0])
    except (ValueError, TypeError):
        return None


def poll_connector(name):
    """Poll one connector's events endpoint once, now. Returns
    {name, ok, stored, error}. A placeholder/empty base URL or a failed call is
    an honest error that stores nothing — never a fabricated event.
    """
    cfg = _read_config(name)
    if cfg is None:
        return _finish_poll(name, 0, "connector is not configured")

    base = cfg.get("baseUrl", "")
    path = cfg.get("eventsPath", "")
    url = (base.rstrip("/") + "/" + path.lstrip("/")) if (base and path) else ""
    if not url:
        return _finish_poll(name, 0, "connector base URL / events path not set")
    if any(ph in url.upper() for ph in _PLACEHOLDER_HOSTS):
        return _finish_poll(
            name, 0, "connector base URL is still a placeholder — set the real host")

    headers = {"Accept": "application/json"}
    token = store.get_setting(cfg.get("tokenKey", ""), "") if cfg.get("tokenKey") else ""
    if token:
        headers["Authorization"] = f"Bearer {token}"

    vendor = cfg.get("vendor") or name
    try:
        payload = _http_get_json(url, headers)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            socket.timeout, ValueError, json.JSONDecodeError) as exc:
        return _finish_poll(name, 0, _explain(exc))

    stored = _ingest_events(name, vendor, payload)
    return _finish_poll(name, stored, "")


def _ingest_events(name, vendor, payload):
    """Turn a vendor events payload into store events. severity is the level the
    vendor reported (source-reported), never guessed. raw is the verbatim JSON
    of the record."""
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = (payload.get("events") or payload.get("data")
                   or payload.get("items") or [])
        if not isinstance(records, list):
            records = []
    else:
        records = []

    stored = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        raw = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        ev = {
            "ts": str(rec.get("ts") or rec.get("timestamp") or _now_iso()),
            "source": name,
            "source_type": f"oem:{vendor}",
            "category": str(rec.get("category", "") or ""),
            "host": str(rec.get("host") or rec.get("hostname", "") or ""),
            "src_ip": str(rec.get("src_ip") or rec.get("source_ip", "") or ""),
            "dst_ip": str(rec.get("dst_ip") or rec.get("dest_ip", "") or ""),
            "user": str(rec.get("user", "") or ""),
            "event_id": str(rec.get("event_id") or rec.get("id", "") or ""),
            # Source-reported severity ONLY — empty when the vendor gave none.
            "severity": str(rec.get("severity", "") or ""),
            "action": str(rec.get("action", "") or ""),
            "message": str(rec.get("message") or rec.get("msg", "") or raw),
            "raw": raw,
        }
        if store.insert_event(ev):
            stored += 1
    return stored


def _finish_poll(name, stored, error):
    store.upsert_connector(name, kind="oem", last_run=_now_iso(),
                           last_error=error or "")
    return {"name": name, "ok": not error, "stored": stored, "error": error or ""}


# ---------------------------------------------------------------------------
# Background poller — polls each ENABLED connector on its own interval.
# ---------------------------------------------------------------------------

class PollerEngine:
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._last = {}   # name -> monotonic-ish last poll (wall clock ISO)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def running(self):
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._poll_due()
            except Exception:
                pass
            self._stop.wait(10)

    def _poll_due(self):
        rows = store.query("connectors", filters={"kind": "oem"}, limit=1000)["items"]
        now = datetime.now(timezone.utc)
        for r in rows:
            if not r.get("enabled"):
                continue
            interval = max(15, int(r.get("interval") or 60))
            last = r.get("last_run")
            due = True
            if last:
                try:
                    due = (now - datetime.fromisoformat(last)).total_seconds() >= interval
                except (ValueError, TypeError):
                    due = True
            if due:
                try:
                    poll_connector(r["name"])
                except Exception:
                    pass


POLLER = PollerEngine()
