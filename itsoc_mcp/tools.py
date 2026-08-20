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

import time

from .client import ItsocError
from . import redaction

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
