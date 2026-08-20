"""tools.py — the read-only tool implementations, independent of the MCP SDK.

Each function takes an ApiClient and returns a plain dict (JSON-serializable).
Keeping the logic here — separate from server.py's MCP wiring — means the whole
tool surface is testable network-free (mock the client) and WITHOUT the mcp SDK
installed, which is exactly how test_mcp.py proves honesty without touching the
network or adding a dependency to the core project.

Invariants every tool upholds:
  * It computes no verdict. Severity, correlation, and rule verdicts come from
    the backend (the frozen detector owns them); tools only relay.
  * Every response carries a `provenance` block (see _provenance).
  * Backend errors / idle / "0 lines parsed" states are relayed honestly — an
    error is `{"ok": false, "error": ...}`, never a fabricated all-clear.
"""

import hashlib
import time

from .client import ItsocError
from . import redaction
from . import threat_intel_offline as tio

# The frozen detector's known-good hash (CLAUDE.md non-negotiable #1 / #7). We
# surface whatever the backend reports; this constant lets a tool FLAG a mismatch
# honestly rather than silently trusting an unexpected build.
EXPECTED_DETECTOR_SHA = "43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05"


# ---------------------------------------------------------------------------
# provenance — attached to every tool response
# ---------------------------------------------------------------------------
def _provenance(client, detector_sha=None, include_redaction=False):
    prov = {
        "verdicts": "deterministic and rule-owned — computed locally by the frozen "
                    "detector on the backend; this MCP server computes none",
        "explanations": "advisory only — an explanation never changes, suppresses, "
                        "or escalates a verdict",
        "mitre": "derived annotation, not a verdict",
        "detector_sha256": detector_sha,
        "detector_sha256_matches_frozen": (detector_sha == EXPECTED_DETECTOR_SHA
                                           if detector_sha else None),
        "backend": client.base_url,
    }
    if include_redaction:
        prov["redaction"] = redaction.redaction_mode()
    return prov


def _detector_sha_from_state(state):
    manifest = state.get("manifest") if isinstance(state, dict) else None
    if isinstance(manifest, dict):
        return manifest.get("detector_sha256")
    return None


def _error(client, message, detector_sha=None):
    """A single honest failure shape. Never carries fabricated findings."""
    return {"ok": False, "error": str(message),
            "provenance": _provenance(client, detector_sha)}


def _looks_like_url(source):
    s = (source or "").strip().lower()
    return s.startswith("http://") or s.startswith("https://")


# ---------------------------------------------------------------------------
# TOOL 1 — analyze_log
# ---------------------------------------------------------------------------
def analyze_log(client, source, compare=False, sleep=time.sleep,
                poll_interval=1.0, max_polls=600):
    """Run the EXISTING analyze flow against a local path or a URL and return a
    run summary — never a verdict of our own.

    Flow mirrors the browser: POST /api/analyze (the backend runs it on a
    background thread and answers 202), then poll GET /api/progress until the job
    is done or errors, then read /console_state.json for the rule-owned result.

    Honesty:
      * A bad source / already-running / oversize upload becomes an honest error
        (the backend's own message), never a fabricated success.
      * An unrecognized format surfaces as `unrecognized: true` with 0 lines
        parsed and an explicit note — this is NOT an all-clear.
    """
    source = (source or "").strip()
    if not source:
        return _error(client, "provide a source: a local file path or an http(s) URL")

    # --- kick off the analysis (the only 'write' this package expresses) ---
    try:
        if _looks_like_url(source):
            client.post_json("/api/analyze", {"url": source, "compare": bool(compare)})
        else:
            from pathlib import Path
            path = Path(source).expanduser()
            if not path.is_file():
                return _error(
                    client,
                    f"no such local file: {source} "
                    "(pass a readable path or an http(s) URL)")
            client.post_multipart(
                "/api/analyze", field_name="file", filename=path.name,
                data=path.read_bytes(),
                extra_fields={"compare": "1"} if compare else {})
    except ItsocError as e:
        return _error(client, str(e))

    # --- poll to completion ------------------------------------------------
    try:
        for _ in range(max_polls):
            snap = client.get_json("/api/progress")
            status = snap.get("status")
            if status == "error":
                return _error(client, snap.get("error") or "analysis failed")
            if status == "done":
                break
            if status == "idle":
                # No job is running and none errored — nothing was started.
                return _error(client, "the backend reports no analysis in progress")
            sleep(poll_interval)
        else:
            return _error(client, "analysis did not finish within the polling window")
    except ItsocError as e:
        return _error(client, str(e))

    # --- read the rule-owned result ---------------------------------------
    try:
        state = client.get_json("/console_state.json")
    except ItsocError as e:
        return _error(client, str(e))

    detector_sha = _detector_sha_from_state(state)
    if state.get("idle"):
        return _error(client, "the run finished but no state is available", detector_sha)

    lines_parsed = int(state.get("linesParsed", 0) or 0)
    unrecognized = bool(state.get("unrecognized"))
    empty_input = bool(state.get("emptyInput"))
    findings = state.get("findings") or []
    severity_counts = state.get("severityCounts") or {}

    result = {
        "ok": True,
        "run_id": state.get("runId"),
        "source": state.get("sourceLabel") or source,
        "parsed_label": state.get("runParsed", ""),
        "summary": {
            "lines_parsed": lines_parsed,
            "lines_unparsed": int(state.get("linesUnparsed", 0) or 0),
            "unrecognized": unrecognized,
            "empty_input": empty_input,
            "finding_count": len(findings),
            "severity_counts": severity_counts,
        },
        "provenance": _provenance(client, detector_sha),
    }

    # Honest banners — an empty result is not automatically an all-clear.
    if unrecognized:
        result["note"] = ("unrecognized format — 0 lines parsed. This is NOT an "
                          "all-clear: nothing was analyzed.")
    elif empty_input:
        result["note"] = "empty input — no lines to analyze."
    elif not findings:
        result["note"] = f"all clear — {lines_parsed} line(s) parsed, no findings."

    return result


# ---------------------------------------------------------------------------
# shared helpers for the current-run tools
# ---------------------------------------------------------------------------
def best_effort_detector_sha(client):
    """The running detector's sha256 if the backend is reachable, else None
    (honest — never a hardcoded claim about a server we couldn't read)."""
    try:
        state = client.get_json("/console_state.json")
    except ItsocError:
        return None
    return _detector_sha_from_state(state)


def _current_state_or_error(client):
    """Return (state, None) for a loaded run, or (None, error_dict) honestly."""
    try:
        state = client.get_json("/console_state.json")
    except ItsocError as e:
        return None, _error(client, str(e))
    if state.get("idle"):
        return None, _error(
            client, "no run is loaded — call analyze_log first (or open a run "
                    "in the console)", _detector_sha_from_state(state))
    return state, None


def _run_guard(state, run_id):
    """The current-run tools read the backend's ACTIVE run. This read-only server
    deliberately does NOT switch the active run (that is a shared side effect), so
    a run_id that isn't the current one is an honest error, not a silent mismatch."""
    if run_id and state.get("runId") and run_id != state.get("runId"):
        return (f"run '{run_id}' is not the active run (current: "
                f"'{state.get('runId')}'). This read-only server does not switch "
                "the active run; omit run_id to use the current one, or open that "
                "run in the console first.")
    return None


def _finding_by_id(state, finding_id):
    return next((f for f in state.get("findings", []) if f.get("id") == finding_id), None)


# ---------------------------------------------------------------------------
# TOOL 2 — list_runs
# ---------------------------------------------------------------------------
def list_runs(client):
    """List saved runs from the backend's run history (read-only). Pass-through:
    if there are none, the list is honestly empty — never a fabricated entry."""
    try:
        data = client.get_json("/api/runs")
    except ItsocError as e:
        return _error(client, str(e))
    runs = data.get("runs") or []
    projected = [{
        "run_id": r.get("runId"),
        "file": r.get("file"),
        "label": r.get("label"),
        "generated_at": r.get("generatedAt"),
        "finding_count": r.get("findings"),
        "unrecognized": bool(r.get("unrecognized")),
        "compare_run": bool(r.get("compareRun")),
        "marked": r.get("marked"),
    } for r in runs]
    return {
        "ok": True,
        "current_run_id": data.get("current"),
        "count": len(projected),
        "runs": projected,
        "provenance": _provenance(client, best_effort_detector_sha(client)),
    }


# ---------------------------------------------------------------------------
# TOOL 3 — get_findings
# ---------------------------------------------------------------------------
def get_findings(client, run_id="", severity="", rule="", host="", limit=50):
    """Filtered findings for the ACTIVE run, with rule-owned severity, rule_id,
    and derived MITRE tags. Host/title carry entity values, so they are redacted
    by default (egress guard). Verdicts are relayed, never recomputed."""
    state, err = _current_state_or_error(client)
    if err:
        return err
    guard = _run_guard(state, run_id)
    if guard:
        return _error(client, guard, _detector_sha_from_state(state))

    findings = state.get("findings") or []
    sev_f = (severity or "").strip().upper()
    rule_f = (rule or "").strip().lower()
    host_f = (host or "").strip().lower()

    selected = []
    for f in findings:
        if sev_f and str(f.get("sev", "")).upper() != sev_f:
            continue
        if rule_f and rule_f not in str(f.get("type", "")).lower():
            continue
        if host_f and host_f not in str(f.get("host", "")).lower():
            continue
        selected.append(f)

    total_matched = len(selected)
    try:
        limit = max(0, int(limit))
    except (TypeError, ValueError):
        limit = 50
    clipped = selected[:limit] if limit else selected

    # Redact entity-bearing fields (host, title) in one shared scope.
    hosts = [f.get("host", "") for f in clipped]
    titles = [f.get("title", "") for f in clipped]
    red = redaction.redact_batch(hosts + titles)
    red_hosts, red_titles = red[:len(clipped)], red[len(clipped):]

    out = []
    for f, rh, rt in zip(clipped, red_hosts, red_titles):
        out.append({
            "finding_id": f.get("id"),
            "severity": f.get("sev"),                 # rule-owned
            "provenance_kind": f.get("prov"),         # RULE-CAUGHT / ANALYZER / LLM-SURFACED
            "rule_id": f.get("type"),
            "host": rh,
            "title": rt,
            "time": f.get("time", ""),
            "occurrences": f.get("occurrences", 1),
            "mitre": [{"id": t.get("id"), "name": t.get("name"),
                       "tactic": t.get("tactic")} for t in (f.get("mitre") or [])],
        })

    return {
        "ok": True,
        "run_id": state.get("runId"),
        "total_matched": total_matched,
        "returned": len(out),
        "truncated": total_matched > len(out),
        "filters": {"severity": severity or None, "rule": rule or None,
                    "host": host or None, "limit": limit},
        "findings": out,
        "provenance": _provenance(client, _detector_sha_from_state(state),
                                  include_redaction=True),
    }


# ---------------------------------------------------------------------------
# TOOL 4 — get_evidence
# ---------------------------------------------------------------------------
def get_evidence(client, finding_id, run_id=""):
    """Real evidence lines + rule predicate + timeline for ONE finding. Raw log
    lines and timeline labels pass through console/redact.py BEFORE returning,
    UNLESS ITSOC_MCP_TRUSTED_LOCAL=1. Evidence is verbatim source text (masked),
    never fabricated; a finding with no readable source says so honestly."""
    state, err = _current_state_or_error(client)
    if err:
        return err
    guard = _run_guard(state, run_id)
    if guard:
        return _error(client, guard, _detector_sha_from_state(state))

    finding = _finding_by_id(state, finding_id)
    if not finding:
        return _error(client, f"no such finding '{finding_id}' in the active run",
                      _detector_sha_from_state(state))

    # Reconstruct each evidence line (a + hit + b) and gather timeline labels;
    # redact everything in one shared scope so a value masks consistently.
    ev_lines = finding.get("lines") or []
    line_texts = [f"{ln.get('a', '')}{ln.get('hit', '')}{ln.get('b', '')}" for ln in ev_lines]
    line_nums = [ln.get("n", "") for ln in ev_lines]
    tl = finding.get("timeline") or []
    tl_labels = [e.get("label", "") for e in tl]

    host = finding.get("host", "")
    combined = redaction.redact_batch(
        line_texts + tl_labels + [host] + [finding.get("title", "")],
        hosts=[host] if host and host != "—" else [])
    n_lines, n_tl = len(line_texts), len(tl_labels)
    red_lines = combined[:n_lines]
    red_labels = combined[n_lines:n_lines + n_tl]
    red_host = combined[n_lines + n_tl]
    red_title = combined[n_lines + n_tl + 1]

    evidence = [{"line": num, "text": txt} for num, txt in zip(line_nums, red_lines)]
    timeline = [{"time": e.get("t", ""), "label": lab, "line": e.get("line")}
                for e, lab in zip(tl, red_labels)]

    return {
        "ok": True,
        "run_id": state.get("runId"),
        "finding_id": finding_id,
        "severity": finding.get("sev"),               # rule-owned
        "rule_id": finding.get("type"),
        "host": red_host,
        "title": red_title,
        "predicate": finding.get("predicate", ""),    # rule metadata, not raw log
        "rule_why": finding.get("ruleWhy", ""),
        "evidence": evidence,
        "evidence_note": finding.get("linesNote"),
        "timeline": timeline,
        "mitre": [{"id": t.get("id"), "name": t.get("name"), "tactic": t.get("tactic")}
                  for t in (finding.get("mitre") or [])],
        "provenance": _provenance(client, _detector_sha_from_state(state),
                                  include_redaction=True),
    }


# ---------------------------------------------------------------------------
# TOOL 5 — explain_finding
# ---------------------------------------------------------------------------
def explain_finding(client, finding_id, run_id=""):
    """Advisory LLM explanation for ONE finding, via the EXISTING /api/explain
    endpoint. The explanation is advisory prose — it never changes, suppresses,
    or escalates the verdict. Prose can echo entity values, so it is redacted by
    default. An unreachable model / unlocatable source is an honest error."""
    # Verify the finding belongs to the active run before asking the backend, so
    # a run_id mismatch is an honest error rather than a silent current-run answer.
    state, err = _current_state_or_error(client)
    if err:
        return err
    guard = _run_guard(state, run_id)
    if guard:
        return _error(client, guard, _detector_sha_from_state(state))
    finding = _finding_by_id(state, finding_id)
    if not finding:
        return _error(client, f"no such finding '{finding_id}' in the active run",
                      _detector_sha_from_state(state))

    try:
        resp = client.post_json("/api/explain", {"id": finding_id})
    except ItsocError as e:
        return _error(client, str(e), _detector_sha_from_state(state))

    text = resp.get("explanation") or ""
    host = finding.get("host", "")
    return {
        "ok": True,
        "run_id": state.get("runId"),
        "finding_id": finding_id,
        "severity": resp.get("sev", finding.get("sev")),   # rule-owned, unchanged
        "advisory": True,
        # Advisory prose can echo entities: mask IPs/known-host + recognized
        # username patterns via the same choke point (raw only with trusted-local).
        "explanation": redaction.redact_text(
            text, hosts=[host] if host and host != "—" else ()),
        "note": "advisory only — this explanation never changes, suppresses, or "
                "escalates the rule verdict.",
        "provenance": _provenance(client, _detector_sha_from_state(state),
                                  include_redaction=True),
    }


# ---------------------------------------------------------------------------
# TOOL 6 — export_run
# ---------------------------------------------------------------------------
EXPORT_FORMATS = ("csv", "html", "xml", "json", "md")


def export_run(client, format="html", run_id=""):
    """Proxy /api/export for the ACTIVE run. When idle the backend returns 409
    ('nothing to export yet') and this relays that honestly — never an empty
    file. A completed export carries raw log text, so by DEFAULT the content is
    withheld (redaction posture) and only its verifiable metadata (size + sha256)
    is returned; set ITSOC_MCP_TRUSTED_LOCAL=1 to receive the content inline."""
    fmt = (format or "html").strip().lower()
    if fmt not in EXPORT_FORMATS:
        return _error(client, f"unknown export format '{fmt}' "
                              f"(use {'/'.join(EXPORT_FORMATS)})")

    # Guard against a stale run_id when the backend has a run loaded.
    try:
        state = client.get_json("/console_state.json")
    except ItsocError as e:
        return _error(client, str(e))
    detector_sha = _detector_sha_from_state(state)
    guard = _run_guard(state, run_id)
    if guard:
        return _error(client, guard, detector_sha)

    try:
        body, content_type, filename = client.get_raw(f"/api/export?format={fmt}")
    except ItsocError as e:
        # 409 idle ('nothing to export yet') and 400 unknown format both land here.
        return _error(client, str(e), detector_sha)

    body = body or b""
    result = {
        "ok": True,
        "run_id": state.get("runId"),
        "format": fmt,
        "filename": filename,
        "content_type": content_type,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "provenance": _provenance(client, detector_sha, include_redaction=True),
    }
    if redaction.trusted_local():
        result["content"] = body.decode("utf-8", "replace")
    else:
        result["content"] = None
        result["content_withheld"] = (
            "the export carries raw log text; content is withheld by default. "
            "Set ITSOC_MCP_TRUSTED_LOCAL=1 to receive it inline, or download it "
            "from the console. Size and sha256 above are the real export.")
    return result


# ---------------------------------------------------------------------------
# TOOL 7 — threat_intel_lookup
# ---------------------------------------------------------------------------
def threat_intel_lookup(client, ip, bundle_path=None):
    """OFFLINE STIX->MITRE lookup for one IP, reusing the project's existing
    offline threat-intel code (no network). Severity + match come from
    threat_intel/threat_detector.py (rule-owned); MITRE tags are derived. No
    bundle configured -> honest n/a (nothing to match against), never a fake
    verdict; no match -> an honest 'no match', not an all-clear on the host."""
    ip = (ip or "").strip()
    if not tio.is_ipv4(ip):
        return _error(client, f"'{ip}' is not a valid IPv4 address")

    detector_sha = best_effort_detector_sha(client)
    path = tio.bundle_path(bundle_path)
    if not path:
        return {
            "ok": True,
            "ip": ip,
            "matched": False,
            "note": ("no offline STIX bundle configured (set ITSOC_STIX_BUNDLE=/path/"
                     "to/bundle.json). Nothing to match against — this is NOT a "
                     "clean verdict on the IP."),
            "provenance": _provenance_ti(client, detector_sha),
        }

    try:
        objects = tio.load_objects(path)
    except FileNotFoundError:
        return _error(client, f"STIX bundle not found: {path}", detector_sha)
    except (ValueError, OSError) as e:
        return _error(client, f"could not read STIX bundle {path}: {e}", detector_sha)

    mapper, mapper_note = tio.build_mapper()
    try:
        matches = tio.match_ip(ip, objects, mapper)
    except Exception as e:                           # pragma: no cover - defensive
        return _error(client, f"offline threat-intel match failed: {e}", detector_sha)

    projected = [{
        "indicator": m.get("threat_intel_name") or m.get("threat_intel_stix_id"),
        "labels": m.get("threat_intel_labels", []),
        "severity": m.get("severity"),               # from threat_detector.severity_for
        "valid_from": m.get("valid_from"),
        "mitre_techniques": [{
            "technique_id": t.get("technique_id"), "name": t.get("name"),
            "tactics": t.get("tactics", []), "url": t.get("url"),
        } for t in m.get("mitre_techniques", [])],
    } for m in matches]

    result = {
        "ok": True,
        "ip": ip,
        "matched": bool(projected),
        "match_count": len(projected),
        "bundle": path,
        "matches": projected,
        "provenance": _provenance_ti(client, detector_sha),
    }
    if not projected:
        result["note"] = (f"no match for {ip} in the configured bundle — an honest "
                          "no-match, not an all-clear on the host.")
    if mapper_note:
        result["mitre_note"] = mapper_note
    return result


def _provenance_ti(client, detector_sha):
    """Provenance for the offline threat-intel tool: the match + severity come
    from the existing offline detector code; the lookup itself is network-free."""
    prov = _provenance(client, detector_sha)
    prov["threat_intel"] = ("offline STIX match + severity from "
                            "threat_intel/threat_detector.py; MITRE names from the "
                            "locally-cached ATT&CK database. No network egress.")
    return prov
