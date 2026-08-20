#!/usr/bin/env python3
"""test_mcp.py — NETWORK-FREE smoke tests for the itsoc read-only MCP tools.

No sockets, no mcp SDK: the ApiClient is replaced by a scripted fake, so these
run with ZERO installs and prove the honesty contract, not the transport. Run:

    python3 itsoc_mcp/test_mcp.py

Stage 1 covers analyze_log: the happy path, the honest unrecognized/empty/error
states (never a fabricated all-clear), and the provenance block that states
verdicts are rule-owned plus the detector sha256.
"""

import sys
from pathlib import Path

# Import the package whether run from the repo root or elsewhere.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from itsoc_mcp import tools
from itsoc_mcp.client import ItsocError

FROZEN_SHA = "43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05"

_PASS = 0
_FAIL = 0


def check(name, cond):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  \033[32mok\033[0m   {name}")
    else:
        _FAIL += 1
        print(f"  \033[31mFAIL\033[0m {name}")


# ---------------------------------------------------------------------------
# A scripted, network-free stand-in for ApiClient.
# ---------------------------------------------------------------------------
class FakeClient:
    def __init__(self, state=None, progress=None, kickoff_error=None,
                 base_url="http://127.0.0.1:8765"):
        self.base_url = base_url
        self._state = state or {}
        # A queue of /api/progress snapshots; the last one repeats.
        self._progress = list(progress or [{"status": "done"}])
        self._kickoff_error = kickoff_error
        self.calls = []                # record of (method, path) for assertions

    def post_json(self, path, obj):
        self.calls.append(("post_json", path, obj))
        if self._kickoff_error:
            raise ItsocError(self._kickoff_error, status=400)
        return {"status": "running"}

    def post_multipart(self, path, field_name, filename, data, extra_fields=None):
        self.calls.append(("post_multipart", path, filename))
        if self._kickoff_error:
            raise ItsocError(self._kickoff_error, status=400)
        return {"status": "running"}

    def get_json(self, path):
        self.calls.append(("get_json", path, None))
        if path == "/api/progress":
            return self._progress.pop(0) if len(self._progress) > 1 else self._progress[0]
        if path == "/console_state.json":
            return self._state
        raise AssertionError(f"unexpected GET {path}")


_NOSLEEP = lambda _s: None


def _good_state(**over):
    state = {
        "idle": False,
        "runId": "auth-2026-08-20",
        "sourceLabel": "auth.log",
        "runParsed": "2,000 lines parsed · 0 unparsed",
        "linesParsed": 2000,
        "linesUnparsed": 0,
        "unrecognized": False,
        "emptyInput": False,
        "findings": [{"id": "detector-0", "sev": "CRITICAL"},
                     {"id": "detector-1", "sev": "HIGH"}],
        "severityCounts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
        "manifest": {"detector_sha256": FROZEN_SHA},
    }
    state.update(over)
    return state


# ---------------------------------------------------------------------------
# analyze_log — happy path over a URL source
# ---------------------------------------------------------------------------
def test_analyze_url_happy():
    print("analyze_log — URL happy path")
    c = FakeClient(state=_good_state(),
                   progress=[{"status": "running"}, {"status": "done"}])
    r = tools.analyze_log(c, "https://example.com/auth.log", sleep=_NOSLEEP)

    check("ok=True", r.get("ok") is True)
    check("run_id relayed from state", r.get("run_id") == "auth-2026-08-20")
    check("lines_parsed relayed", r["summary"]["lines_parsed"] == 2000)
    check("finding_count relayed", r["summary"]["finding_count"] == 2)
    check("severity_counts relayed verbatim",
          r["summary"]["severity_counts"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0})
    check("not flagged unrecognized", r["summary"]["unrecognized"] is False)
    # provenance: rule-owned verdicts + detector sha, matching the frozen build.
    prov = r.get("provenance", {})
    check("provenance present", bool(prov))
    check("provenance: verdicts are rule-owned", "rule-owned" in prov.get("verdicts", ""))
    check("provenance: detector sha surfaced", prov.get("detector_sha256") == FROZEN_SHA)
    check("provenance: sha matches frozen", prov.get("detector_sha256_matches_frozen") is True)
    # URL source must go out as JSON, never multipart.
    check("URL kicked off via post_json",
          any(m == "post_json" and p == "/api/analyze" for m, p, *_ in c.calls))
    check("no fabricated findings list leaked", "findings" not in r)


# ---------------------------------------------------------------------------
# analyze_log — local file path uses multipart upload
# ---------------------------------------------------------------------------
def test_analyze_local_file_multipart(tmpfile):
    print("analyze_log — local file path")
    c = FakeClient(state=_good_state(sourceLabel=tmpfile.name),
                   progress=[{"status": "done"}])
    r = tools.analyze_log(c, str(tmpfile), sleep=_NOSLEEP)
    check("ok=True", r.get("ok") is True)
    check("local file kicked off via multipart",
          any(m == "post_multipart" and p == "/api/analyze" for m, p, *_ in c.calls))


def test_analyze_missing_file():
    print("analyze_log — missing local file is an honest error")
    c = FakeClient()
    r = tools.analyze_log(c, "/no/such/path/xyz.log", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("names the missing file honestly", "no such local file" in r.get("error", ""))
    check("no analyze POST was attempted", c.calls == [])
    check("still carries provenance", bool(r.get("provenance")))


# ---------------------------------------------------------------------------
# Honest empty/degenerate states — never a fake all-clear
# ---------------------------------------------------------------------------
def test_analyze_unrecognized():
    print("analyze_log — unrecognized format is NOT an all-clear")
    state = _good_state(linesParsed=0, linesUnparsed=42, unrecognized=True,
                        findings=[], severityCounts={"CRITICAL": 0, "HIGH": 0})
    c = FakeClient(state=state, progress=[{"status": "done"}])
    r = tools.analyze_log(c, "https://example.com/mystery.bin", sleep=_NOSLEEP)
    check("ok=True (honest, not an error)", r.get("ok") is True)
    check("unrecognized flag surfaced", r["summary"]["unrecognized"] is True)
    check("0 lines parsed relayed", r["summary"]["lines_parsed"] == 0)
    check("note says NOT an all-clear", "NOT an" in r.get("note", ""))
    check("note does not claim all clear", "all clear" not in r.get("note", "").lower())


def test_analyze_empty_input():
    print("analyze_log — empty input is honest")
    state = _good_state(linesParsed=0, linesUnparsed=0, emptyInput=True, findings=[])
    c = FakeClient(state=state, progress=[{"status": "done"}])
    r = tools.analyze_log(c, "https://example.com/empty.log", sleep=_NOSLEEP)
    check("empty_input flag surfaced", r["summary"]["empty_input"] is True)
    check("note mentions empty input", "empty input" in r.get("note", "").lower())


def test_analyze_all_clear():
    print("analyze_log — a genuine all-clear says so, with the parsed count")
    state = _good_state(findings=[], severityCounts={"CRITICAL": 0, "HIGH": 0})
    c = FakeClient(state=state, progress=[{"status": "done"}])
    r = tools.analyze_log(c, "https://example.com/clean.log", sleep=_NOSLEEP)
    check("ok=True", r.get("ok") is True)
    check("all-clear note cites lines parsed", "all clear" in r.get("note", "").lower()
          and "2000" in r.get("note", ""))


# ---------------------------------------------------------------------------
# Honest failure paths
# ---------------------------------------------------------------------------
def test_analyze_job_error():
    print("analyze_log — a failed job is an honest error, no fabricated result")
    c = FakeClient(progress=[{"status": "running"},
                             {"status": "error", "error": "analysis failed: boom"}])
    r = tools.analyze_log(c, "https://example.com/x.log", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("relays backend error message", "boom" in r.get("error", ""))
    check("no summary fabricated", "summary" not in r)
    check("carries provenance", bool(r.get("provenance")))


def test_analyze_kickoff_rejected():
    print("analyze_log — backend rejecting the source is an honest error")
    c = FakeClient(kickoff_error="only http(s) URLs are allowed")
    r = tools.analyze_log(c, "https://example.com/bad", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("relays backend rejection", "http(s)" in r.get("error", ""))


def test_analyze_backend_unreachable():
    print("analyze_log — an unreachable backend is honest, not a fake success")

    class Down:
        base_url = "http://127.0.0.1:8765"
        calls = []

        def post_json(self, path, obj):
            raise ItsocError("backend not reachable at http://127.0.0.1:8765")

        def post_multipart(self, *a, **k):
            raise ItsocError("backend not reachable")

        def get_json(self, path):
            raise ItsocError("backend not reachable")

    r = tools.analyze_log(Down(), "https://example.com/x.log", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("says backend not reachable", "not reachable" in r.get("error", ""))


def test_analyze_empty_source():
    print("analyze_log — empty source is rejected honestly")
    c = FakeClient()
    r = tools.analyze_log(c, "", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("asks for a source", "source" in r.get("error", "").lower())
    check("no POST attempted", c.calls == [])


def main():
    print("\n=== itsoc_mcp Stage 1 smoke tests (network-free) ===\n")
    tmp = _REPO_ROOT / "itsoc_mcp" / "_tmp_sample.log"
    tmp.write_text("Aug 20 10:00:00 host sshd[1]: Failed password for admin from 10.0.0.9\n")
    try:
        test_analyze_url_happy()
        test_analyze_local_file_multipart(tmp)
        test_analyze_missing_file()
        test_analyze_unrecognized()
        test_analyze_empty_input()
        test_analyze_all_clear()
        test_analyze_job_error()
        test_analyze_kickoff_rejected()
        test_analyze_backend_unreachable()
        test_analyze_empty_source()
    finally:
        tmp.unlink(missing_ok=True)

    print(f"\n{_PASS} passed, {_FAIL} failed\n")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
