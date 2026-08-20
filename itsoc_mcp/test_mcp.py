#!/usr/bin/env python3
"""test_mcp.py — NETWORK-FREE smoke tests for the itsoc read-only MCP tools.

No sockets, no mcp SDK, no ATT&CK cache dependency: the ApiClient is replaced by
a scripted fake and the offline MITRE mapper is stubbed, so these run with ZERO
installs and prove the HONESTY contract, not the transport. Run:

    python3 itsoc_mcp/test_mcp.py

Covers all 7 tools: analyze_log, list_runs, get_findings, get_evidence,
explain_finding, export_run, threat_intel_lookup — the happy path plus the
honest empty/idle/error states (never a fabricated all-clear or empty file), and
that raw log text is REDACTED by default and returned only with
ITSOC_MCP_TRUSTED_LOCAL=1.
"""

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from itsoc_mcp import tools, redaction
from itsoc_mcp import threat_intel_offline as tio
from itsoc_mcp.client import ItsocError

FROZEN_SHA = "43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05"

_PASS = 0
_FAIL = 0
_SKIP = 0


def check(name, cond):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  \033[32mok\033[0m   {name}")
    else:
        _FAIL += 1
        print(f"  \033[31mFAIL\033[0m {name}")


def skip(name, reason):
    global _SKIP
    _SKIP += 1
    print(f"  \033[33mskip\033[0m {name} — {reason}")


# ---------------------------------------------------------------------------
# A scripted, network-free stand-in for ApiClient.
# ---------------------------------------------------------------------------
class FakeClient:
    def __init__(self, state=None, progress=None, kickoff_error=None,
                 runs=None, explain=None, export=None,
                 base_url="http://127.0.0.1:8765"):
        self.base_url = base_url
        self._state = state if state is not None else {}
        self._progress = list(progress or [{"status": "done"}])
        self._kickoff_error = kickoff_error
        self._runs = runs if runs is not None else {"runs": [], "current": None}
        self._explain = explain          # dict OR an ItsocError to raise
        self._export = export            # (bytes, ctype, filename) OR ItsocError
        self.calls = []

    def post_json(self, path, obj):
        self.calls.append(("post_json", path, obj))
        if path == "/api/analyze":
            if self._kickoff_error:
                raise ItsocError(self._kickoff_error, status=400)
            return {"status": "running"}
        if path == "/api/explain":
            if isinstance(self._explain, ItsocError):
                raise self._explain
            return self._explain or {}
        raise AssertionError(f"unexpected POST {path}")

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
        if path == "/api/runs":
            return self._runs
        raise AssertionError(f"unexpected GET {path}")

    def get_raw(self, path):
        self.calls.append(("get_raw", path, None))
        if isinstance(self._export, ItsocError):
            raise self._export
        return self._export


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
        "findings": [
            {"id": "detector-0", "sev": "CRITICAL", "prov": "RULE-CAUGHT",
             "type": "possible_break_in", "host": "app-01", "title": "SUCCESSFUL login for 'admin' from 10.0.0.9",
             "time": "10:00", "occurrences": 3,
             "predicate": "N failures then success", "ruleWhy": "brute force then success",
             "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
             "lines": [{"n": 12, "a": "Failed password for admin from ", "hit": "10.0.0.9", "b": " port 22"},
                       {"n": 15, "a": "Accepted password for admin from ", "hit": "10.0.0.9", "b": " port 22"}],
             "timeline": [{"t": "10:00", "label": "Failed password from 10.0.0.9", "line": 12}]},
            {"id": "detector-1", "sev": "HIGH", "prov": "RULE-CAUGHT",
             "type": "port_scan", "host": "app-02", "title": "Port scan from 10.0.0.5",
             "time": "10:05", "occurrences": 1, "predicate": "", "ruleWhy": "",
             "mitre": [], "lines": [], "timeline": []},
        ],
        "severityCounts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
        "manifest": {"detector_sha256": FROZEN_SHA},
    }
    state.update(over)
    return state


def _no_trusted():
    os.environ.pop("ITSOC_MCP_TRUSTED_LOCAL", None)


# ===========================================================================
# analyze_log
# ===========================================================================
def test_analyze_url_happy():
    print("analyze_log — URL happy path")
    _no_trusted()
    c = FakeClient(state=_good_state(), progress=[{"status": "running"}, {"status": "done"}])
    r = tools.analyze_log(c, "https://example.com/auth.log", sleep=_NOSLEEP)
    check("ok=True", r.get("ok") is True)
    check("run_id relayed", r.get("run_id") == "auth-2026-08-20")
    check("lines_parsed relayed", r["summary"]["lines_parsed"] == 2000)
    check("finding_count relayed", r["summary"]["finding_count"] == 2)
    check("severity_counts verbatim",
          r["summary"]["severity_counts"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0})
    prov = r.get("provenance", {})
    check("provenance: verdicts rule-owned", "rule-owned" in prov.get("verdicts", ""))
    check("provenance: detector sha matches frozen", prov.get("detector_sha256_matches_frozen") is True)
    check("URL via post_json", any(m == "post_json" and p == "/api/analyze" for m, p, *_ in c.calls))


def test_analyze_local_multipart(tmpfile):
    print("analyze_log — local file uses multipart")
    c = FakeClient(state=_good_state(), progress=[{"status": "done"}])
    r = tools.analyze_log(c, str(tmpfile), sleep=_NOSLEEP)
    check("ok=True", r.get("ok") is True)
    check("kicked off via multipart",
          any(m == "post_multipart" and p == "/api/analyze" for m, p, *_ in c.calls))


def test_analyze_missing_file():
    print("analyze_log — missing file is honest")
    c = FakeClient()
    r = tools.analyze_log(c, "/no/such/xyz.log", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("names missing file", "no such local file" in r.get("error", ""))
    check("no POST attempted", c.calls == [])


def test_analyze_unrecognized():
    print("analyze_log — unrecognized is NOT an all-clear")
    st = _good_state(linesParsed=0, linesUnparsed=42, unrecognized=True, findings=[],
                     severityCounts={"CRITICAL": 0, "HIGH": 0})
    c = FakeClient(state=st, progress=[{"status": "done"}])
    r = tools.analyze_log(c, "https://example.com/mystery.bin", sleep=_NOSLEEP)
    check("unrecognized surfaced", r["summary"]["unrecognized"] is True)
    check("0 lines parsed", r["summary"]["lines_parsed"] == 0)
    check("note NOT all-clear", "NOT an" in r.get("note", "") and "all clear" not in r.get("note", "").lower())


def test_analyze_job_error():
    print("analyze_log — failed job is honest, no fabricated result")
    c = FakeClient(progress=[{"status": "running"}, {"status": "error", "error": "analysis failed: boom"}])
    r = tools.analyze_log(c, "https://example.com/x.log", sleep=_NOSLEEP)
    check("ok=False", r.get("ok") is False)
    check("relays error", "boom" in r.get("error", ""))
    check("no summary fabricated", "summary" not in r)


# ===========================================================================
# list_runs
# ===========================================================================
def test_list_runs():
    print("list_runs — projects history, honest empty")
    runs = {"runs": [{"runId": "auth-2026-08-20", "file": "auth.json", "label": "auth.log",
                      "generatedAt": "2026-08-20", "findings": 2, "unrecognized": False,
                      "compareRun": False, "marked": 1}],
            "current": "auth-2026-08-20"}
    c = FakeClient(state=_good_state(), runs=runs)
    r = tools.list_runs(c)
    check("ok=True", r.get("ok") is True)
    check("count=1", r.get("count") == 1)
    check("current relayed", r.get("current_run_id") == "auth-2026-08-20")
    check("run_id projected", r["runs"][0]["run_id"] == "auth-2026-08-20")
    check("provenance present", bool(r.get("provenance")))

    empty = FakeClient(state={"idle": True}, runs={"runs": [], "current": None})
    r2 = tools.list_runs(empty)
    check("empty history is honestly empty", r2.get("count") == 0 and r2["runs"] == [])


# ===========================================================================
# get_findings
# ===========================================================================
def test_get_findings_filter_and_redact():
    print("get_findings — filter + rule-owned severity + redacted title/host")
    _no_trusted()
    c = FakeClient(state=_good_state())
    r = tools.get_findings(c, severity="CRITICAL")
    check("ok=True", r.get("ok") is True)
    check("filter applied (1 CRITICAL)", r["returned"] == 1 and r["total_matched"] == 1)
    f = r["findings"][0]
    check("severity is rule-owned CRITICAL", f["severity"] == "CRITICAL")
    check("rule_id relayed", f["rule_id"] == "possible_break_in")
    check("MITRE tag derived", f["mitre"][0]["id"] == "T1110")
    check("title redacted (no raw IP)", "10.0.0.9" not in f["title"])
    check("title redacted (no raw user)", "admin" not in f["title"])
    check("provenance shows redaction on", r["provenance"].get("redaction") == "on")


def test_get_findings_limit_truncates():
    print("get_findings — limit truncates honestly")
    c = FakeClient(state=_good_state())
    r = tools.get_findings(c, limit=1)
    check("returned=1", r["returned"] == 1)
    check("total_matched=2", r["total_matched"] == 2)
    check("truncated flagged", r["truncated"] is True)


def test_get_findings_no_run():
    print("get_findings — no run loaded is honest")
    c = FakeClient(state={"idle": True})
    r = tools.get_findings(c)
    check("ok=False", r.get("ok") is False)
    check("says no run loaded", "no run" in r.get("error", "").lower())


def test_get_findings_run_guard():
    print("get_findings — non-current run_id is an honest error")
    c = FakeClient(state=_good_state())
    r = tools.get_findings(c, run_id="some-other-run")
    check("ok=False", r.get("ok") is False)
    check("explains it won't switch runs", "not the active run" in r.get("error", ""))


# ===========================================================================
# get_evidence — redaction by default, raw only with trusted-local
# ===========================================================================
def test_get_evidence_redacted_by_default():
    print("get_evidence — REDACTED by default")
    _no_trusted()
    c = FakeClient(state=_good_state())
    r = tools.get_evidence(c, "detector-0")
    check("ok=True", r.get("ok") is True)
    check("severity rule-owned", r["severity"] == "CRITICAL")
    joined = json.dumps(r["evidence"]) + json.dumps(r["timeline"]) + r.get("host", "") + r.get("title", "")
    check("raw IP masked everywhere", "10.0.0.9" not in joined)
    check("raw user masked", "admin" not in joined)
    check("evidence still present (not dropped)", len(r["evidence"]) == 2)
    check("IP placeholder consistent across line+timeline",
          any("[IP-" in e["text"] for e in r["evidence"]) and "[IP-" in r["timeline"][0]["label"])
    check("provenance redaction=on", r["provenance"].get("redaction") == "on")


def test_get_evidence_trusted_local_raw():
    print("get_evidence — raw ONLY with ITSOC_MCP_TRUSTED_LOCAL=1")
    os.environ["ITSOC_MCP_TRUSTED_LOCAL"] = "1"
    try:
        c = FakeClient(state=_good_state())
        r = tools.get_evidence(c, "detector-0")
        joined = json.dumps(r["evidence"])
        check("raw IP present under trusted-local", "10.0.0.9" in joined)
        check("provenance redaction=off", "off" in r["provenance"].get("redaction", ""))
    finally:
        _no_trusted()


def test_get_evidence_missing():
    print("get_evidence — unknown finding is honest")
    c = FakeClient(state=_good_state())
    r = tools.get_evidence(c, "nope-99")
    check("ok=False", r.get("ok") is False)
    check("says no such finding", "no such finding" in r.get("error", ""))


# ===========================================================================
# explain_finding
# ===========================================================================
def test_explain_advisory_redacted():
    print("explain_finding — advisory, redacted by default")
    _no_trusted()
    finding_resp = dict(_good_state()["findings"][0])
    # Prose in a shape the choke point recognizes: an IP (always masked) and a
    # username in the "Failed <method> for <user>" pattern console/redact.py knows.
    finding_resp["explanation"] = "Failed password for admin from 10.0.0.9 indicates brute force."
    c = FakeClient(state=_good_state(), explain=finding_resp)
    r = tools.explain_finding(c, "detector-0")
    check("ok=True", r.get("ok") is True)
    check("advisory flag", r.get("advisory") is True)
    check("severity unchanged rule-owned", r["severity"] == "CRITICAL")
    check("explanation redacted (IP + user masked)",
          "10.0.0.9" not in r["explanation"] and "admin" not in r["explanation"])
    check("note stresses advisory", "never change" in r.get("note", "").lower()
          or "never changes" in r.get("note", "").lower())


def test_explain_model_unreachable():
    print("explain_finding — unreachable model is honest, not made up")
    c = FakeClient(state=_good_state(),
                   explain=ItsocError("the analyst model is not reachable", status=502))
    r = tools.explain_finding(c, "detector-0")
    check("ok=False", r.get("ok") is False)
    check("relays unreachable", "not reachable" in r.get("error", ""))


# ===========================================================================
# export_run — honest idle 409, withheld-by-default, raw only trusted-local
# ===========================================================================
def test_export_idle_honest():
    print("export_run — idle backend relays 409 honestly (never empty file)")
    c = FakeClient(state={"idle": True},
                   export=ItsocError("nothing to export yet", status=409))
    r = tools.export_run(c, format="csv")
    check("ok=False", r.get("ok") is False)
    check("relays 'nothing to export'", "nothing to export" in r.get("error", ""))
    check("no fabricated content", "content" not in r)


def test_export_withheld_by_default():
    print("export_run — content withheld by default, real size+sha")
    _no_trusted()
    body = b"n,severity,host\n1,CRITICAL,app-01\n"
    c = FakeClient(state=_good_state(), export=(body, "text/csv", "auth.csv"))
    r = tools.export_run(c, format="csv")
    check("ok=True", r.get("ok") is True)
    check("bytes is real length", r["bytes"] == len(body))
    check("sha256 present", len(r.get("sha256", "")) == 64)
    check("content withheld", r.get("content") is None and "content_withheld" in r)


def test_export_trusted_local_content():
    print("export_run — content inline ONLY with trusted-local")
    os.environ["ITSOC_MCP_TRUSTED_LOCAL"] = "1"
    try:
        body = b"n,severity,host\n1,CRITICAL,app-01\n"
        c = FakeClient(state=_good_state(), export=(body, "text/csv", "auth.csv"))
        r = tools.export_run(c, format="csv")
        check("content present under trusted-local", r.get("content", "").startswith("n,severity"))
    finally:
        _no_trusted()


def test_export_bad_format():
    print("export_run — unknown format is honest")
    c = FakeClient(state=_good_state())
    r = tools.export_run(c, format="pdf")
    check("ok=False", r.get("ok") is False)
    check("names valid formats", "csv" in r.get("error", ""))


# ===========================================================================
# threat_intel_lookup — offline STIX->MITRE, honest n/a & no-match
# ===========================================================================
def _stix_bundle_file(tmpdir, ip="198.51.100.7", with_link=True):
    objs = [{
        "type": "indicator", "id": "indicator--aaaaaaaa",
        "name": "Known bad host", "pattern": f"[ipv4-addr:value = '{ip}']",
        "indicator_types": ["malicious-activity"], "valid_from": "2026-01-01T00:00:00Z",
    }]
    if with_link:
        objs += [
            {"type": "attack-pattern", "id": "attack-pattern--bbbbbbbb", "name": "Brute Force"},
            {"type": "relationship", "relationship_type": "indicates",
             "source_ref": "indicator--aaaaaaaa", "target_ref": "attack-pattern--bbbbbbbb"},
        ]
    path = tmpdir / "bundle.json"
    path.write_text(json.dumps({"type": "bundle", "objects": objs}))
    return path


class _FakeMapper:
    def lookup_by_stix_id(self, stix_id):
        if stix_id == "attack-pattern--bbbbbbbb":
            return {"technique_id": "T1110", "name": "Brute Force",
                    "tactics": ["Credential Access"], "url": "https://attack.mitre.org/techniques/T1110"}
        return None


def test_ti_no_bundle_is_na():
    print("threat_intel_lookup — no bundle configured -> honest n/a")
    os.environ.pop("ITSOC_STIX_BUNDLE", None)
    c = FakeClient(state=_good_state())
    r = tools.threat_intel_lookup(c, "198.51.100.7")
    check("ok=True (honest)", r.get("ok") is True)
    check("matched False", r.get("matched") is False)
    check("note says not a clean verdict", "NOT a" in r.get("note", ""))
    check("provenance mentions offline", "offline" in r["provenance"].get("threat_intel", "").lower())


def test_ti_invalid_ip():
    print("threat_intel_lookup — invalid IP is honest")
    c = FakeClient(state=_good_state())
    r = tools.threat_intel_lookup(c, "not-an-ip")
    check("ok=False", r.get("ok") is False)
    check("says invalid IPv4", "not a valid IPv4" in r.get("error", ""))


def test_ti_match(tmpdir, monkeypatch_build_mapper):
    print("threat_intel_lookup — real match -> rule-owned severity + MITRE")
    bundle = _stix_bundle_file(tmpdir)
    c = FakeClient(state=_good_state())
    r = tools.threat_intel_lookup(c, "198.51.100.7", bundle_path=str(bundle))
    check("ok=True", r.get("ok") is True)
    check("matched True", r.get("matched") is True)
    m = r["matches"][0]
    check("severity from threat_detector (critical)", m["severity"] == "critical")
    check("MITRE technique enriched", m["mitre_techniques"][0]["technique_id"] == "T1110")


def test_ti_no_match(tmpdir, monkeypatch_build_mapper):
    print("threat_intel_lookup — no match is honest, not an all-clear")
    bundle = _stix_bundle_file(tmpdir, ip="203.0.113.9")
    c = FakeClient(state=_good_state())
    r = tools.threat_intel_lookup(c, "198.51.100.7", bundle_path=str(bundle))
    check("ok=True", r.get("ok") is True)
    check("matched False", r.get("matched") is False)
    check("note is honest no-match", "no match" in r.get("note", "").lower()
          and "not an all-clear" in r.get("note", "").lower())


# ===========================================================================
# Standalone redaction — vendored mirror, drift-guard, active source
# ===========================================================================
# A corpus exercising every masking position: IPv4/IPv6, all username patterns,
# known hosts/users, control chars, and an over-long line.
_REDACT_CORPUS = [
    "Failed password for admin from 10.0.0.9 port 22",
    "Accepted publickey for ankit from 192.168.1.5 port 22",
    "auth failed for user 'root' from 172.16.0.1",
    "pam_unix(sshd:auth): authentication failure; logname= user=daemon",
    "Failed password for invalid user oracle from 2001:db8::1 port 22",
    "Brute-force then SUCCESSFUL login for 'operator' from fe80::1",
    "connection from app-01.internal (10.1.1.1) and app-01",
    "control\x07chars\x1bstripped " + "x" * 3000,
]
_REDACT_HOSTS = ["app-01.internal", "app-01"]
_REDACT_USERS = ["operator", "ankit"]


def test_vendored_masks_by_default():
    print("_redact_vendored — masks IPs and usernames (standalone-safe)")
    from itsoc_mcp import _redact_vendored as v
    out = v.redact_text("Failed password for admin from 10.0.0.9")
    check("IP masked", "10.0.0.9" not in out and "[IP-1]" in out)
    check("user masked", "admin" not in out and "[USER-1]" in out)
    # Shared scope keeps one value one placeholder.
    r = v.Redactor()
    a, b = r.redact("from 10.0.0.9"), r.redact("again 10.0.0.9")
    check("consistent placeholder in a scope", "[IP-1]" in a and "[IP-1]" in b)


def test_redact_source_is_console_in_repo():
    print("redaction.redact_source — single source of truth when in-repo")
    check("active source is console.redact in-repo",
          redaction.redact_source() == "console.redact")


def test_drift_guard_vendored_matches_console():
    print("DRIFT-GUARD — vendored masking is byte-identical to console/redact.py")
    try:
        from console import redact as canonical
    except ImportError:
        skip("drift-guard", "console/redact.py not importable (standalone) — "
                            "vendored copy is the single source by definition")
        return
    from itsoc_mcp import _redact_vendored as vendored

    # 1) redact_text on each corpus line, with known hosts/users.
    identical = True
    for s in _REDACT_CORPUS:
        a = canonical.redact_text(s, hosts=_REDACT_HOSTS, users=_REDACT_USERS)
        b = vendored.redact_text(s, hosts=_REDACT_HOSTS, users=_REDACT_USERS)
        if a != b:
            identical = False
            print(f"    DIVERGENCE on {s!r}:\n      console:  {a!r}\n      vendored: {b!r}")
    check("redact_text identical across corpus", identical)

    # 2) shared-scope batch (whole corpus in one Redactor) identical too.
    ca = [canonical.Redactor(hosts=_REDACT_HOSTS, users=_REDACT_USERS).redact(s) for s in _REDACT_CORPUS]
    cb = [vendored.Redactor(hosts=_REDACT_HOSTS, users=_REDACT_USERS).redact(s) for s in _REDACT_CORPUS]
    check("Redactor scope identical across corpus", ca == cb)

    # 3) module-level redact_lines returns the same masked lines.
    la, _ = canonical.redact_lines(_REDACT_CORPUS, hosts=_REDACT_HOSTS, users=_REDACT_USERS)
    lb, _ = vendored.redact_lines(_REDACT_CORPUS, hosts=_REDACT_HOSTS, users=_REDACT_USERS)
    check("redact_lines identical across corpus", la == lb)


def test_ti_unavailable_fails_closed():
    print("threat_intel_lookup — standalone (no threat_intel/) FAILS CLOSED")
    _real_avail = tio.threat_intel_available
    tools.tio.threat_intel_available = lambda: False
    try:
        c = FakeClient(state=_good_state())
        # No bundle configured — must NOT be the soft 'n/a', it must fail closed.
        r = tools.threat_intel_lookup(c, "198.51.100.7")
        check("ok=False (fail closed)", r.get("ok") is False)
        check("honest unavailable message", "unavailable" in r.get("error", "").lower())
        check("explicitly not an all-clear", "all-clear" in r.get("error", "").lower())
        check("no fabricated matches", "matches" not in r and r.get("matched") is not True)
        # Even WITH a bundle path, standalone still fails closed (never a fake match).
        r2 = tools.threat_intel_lookup(c, "198.51.100.7", bundle_path="/tmp/whatever.json")
        check("bundle-set still fails closed", r2.get("ok") is False
              and "unavailable" in r2.get("error", "").lower())
    finally:
        tools.tio.threat_intel_available = _real_avail


def main():
    print("\n=== itsoc_mcp smoke tests — all 7 tools, network-free ===\n")
    _no_trusted()
    tmp = _REPO_ROOT / "itsoc_mcp" / "_tmp_sample.log"
    tmp.write_text("Aug 20 10:00:00 host sshd[1]: Failed password for admin from 10.0.0.9\n")
    tmpdir = _REPO_ROOT / "itsoc_mcp" / "_tmp_ti"
    tmpdir.mkdir(exist_ok=True)

    # Stub the offline MITRE mapper so the threat-intel tests need no 47MB cache.
    _real_build_mapper = tio.build_mapper
    tools.tio.build_mapper = lambda: (_FakeMapper(), None)
    try:
        test_analyze_url_happy()
        test_analyze_local_multipart(tmp)
        test_analyze_missing_file()
        test_analyze_unrecognized()
        test_analyze_job_error()
        test_list_runs()
        test_get_findings_filter_and_redact()
        test_get_findings_limit_truncates()
        test_get_findings_no_run()
        test_get_findings_run_guard()
        test_get_evidence_redacted_by_default()
        test_get_evidence_trusted_local_raw()
        test_get_evidence_missing()
        test_explain_advisory_redacted()
        test_explain_model_unreachable()
        test_export_idle_honest()
        test_export_withheld_by_default()
        test_export_trusted_local_content()
        test_export_bad_format()
        test_ti_no_bundle_is_na()
        test_ti_invalid_ip()
        test_ti_match(tmpdir, True)
        test_ti_no_match(tmpdir, True)
        test_ti_unavailable_fails_closed()
        # Standalone redaction: vendored mirror + drift-guard + active source.
        test_vendored_masks_by_default()
        test_redact_source_is_console_in_repo()
        test_drift_guard_vendored_matches_console()
    finally:
        tools.tio.build_mapper = _real_build_mapper
        tmp.unlink(missing_ok=True)
        for p in tmpdir.glob("*"):
            p.unlink(missing_ok=True)
        tmpdir.rmdir()
        _no_trusted()

    tail = f", {_SKIP} skipped" if _SKIP else ""
    print(f"\n{_PASS} passed, {_FAIL} failed{tail}\n")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
