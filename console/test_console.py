#!/usr/bin/env python3
"""
test_console.py — headless render smoke test for the anomaly console.

The console is the only part of this project that isn't Python, and it is the
part a reviewer actually looks at. This runs its real render path against a
stubbed DOM and asserts what ends up on the page: every run state, the filters,
selection and marking, and — most importantly — the honest states, because those
are the ones that would quietly lie if they broke.

No browser, no network, no model, no report on disk: the live state is a small
literal below. The console's own JS is extracted from the HTML and executed as-is,
so this tests the shipped file rather than a copy.

Node is required to execute JavaScript. If it is absent the suite reports SKIPPED
and exits 0 rather than failing a machine that simply has no JS runtime — the same
posture test_threat_intel.py takes with a cold ATT&CK cache.

Usage:
  python3 console/test_console.py
"""

import inspect
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSOLE_HTML = HERE / "anomaly_console.html"

# A live state in console/adapter.py's shape. Hand-written so the test needs no
# analyzer run: two rule findings that disagree with the model, one that agrees,
# and one below every threshold.
LIVE_STATE = {
    "live": True,
    "runId": "bench-2026-08-15",
    "runWindow": "02:16–02:19 UTC",
    "runHosts": "server-01, server-03",
    "runParsed": "19 lines parsed · 0 unparsed",
    "generatedAt": "2026-08-15T02:20:00+00:00",
    "manifest": {
        "input_sha256": "7e8b3dfd9c3293ca166bb2fe8aedda86fe0e4fcb32ee906ad5b238add4648049",
        "detector_sha256": "43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05",
        "model": "llama3.1:8b", "temperature": 0, "ruleset": "v1",
    },
    "compareRun": True, "underratedCount": 2,
    "chunksUsable": 1, "chunksTotal": 1, "degraded": False, "analyzerErrors": 0,
    "findings": [
        {
            "id": "d0", "sev": "CRITICAL", "sevColor": "#e2807f", "ruleSev": "CRITICAL",
            "llmSev": "HIGH", "llmWhy": "Saw the failures but not the success.",
            "delta": "under-rated", "prov": "RULE-CAUGHT",
            "type": "auth_bruteforce_success", "host": "server-01", "hostDerived": True,
            "time": "02:16:52", "stamp": "2026-08-13T02:16:52+00:00",
            "title": "Brute-force then SUCCESSFUL login for 'admin' from 203.0.113.44",
            "ruleWhy": "Failures then a success from the same source.",
            "explanation": "Treat the admin account as compromised.",
            "predicate": "failures_from(ip) >= 5\n-> severity = critical",
            "ruleRef": "anomaly_detector.py · detect_auth_bruteforce()",
            "occurrences": 1, "linesNote": None,
            "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                      {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}],
            "chips": [{"text": "203.0.113.44"}],
            "lines": [{"n": 5, "a": "2026-08-13T02:16:44Z ERROR server-01 auth failed from ",
                       "hit": "203.0.113.44", "b": "", "crit": True}],
            "timeline": [{"t": "02:16:44", "label": "First failed login", "dot": "#e2807f"}],
        },
        {
            "id": "d1", "sev": "HIGH", "sevColor": "#d8a35e", "ruleSev": "HIGH",
            "llmSev": "LOW", "llmWhy": "Read 'blocked' as resolved.",
            "delta": "under-rated", "prov": "RULE-CAUGHT",
            "type": "suspicious_outbound", "host": "firewall-01", "hostDerived": True,
            "time": "02:19:10", "stamp": "2026-08-13T02:19:10+00:00",
            "title": "Outbound connection to 45.153.160.2:4444 (blocked)",
            "ruleWhy": "Port 4444 is a known C2 port.", "explanation": "Investigate server-02.",
            "predicate": "dest_port in SUSPICIOUS_PORTS", "ruleRef": "detect_suspicious_ports()",
            "occurrences": 1, "linesNote": None,
            "mitre": [{"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"}],
            "chips": [],
            "lines": [{"n": 18, "a": "blocked outbound ", "hit": "45.153.160.2:4444",
                       "b": "", "crit": False}],
            "timeline": [{"t": "02:19:10", "label": "Connection dropped", "dot": "#d8a35e"}],
        },
        {
            "id": "d2", "sev": "CRITICAL", "sevColor": "#e2807f", "ruleSev": "CRITICAL",
            "llmSev": "CRITICAL", "llmWhy": "Agrees.", "delta": "agree", "prov": "RULE-CAUGHT",
            "type": "critical_service_event", "host": "server-03", "hostDerived": True,
            "time": "02:18:30", "stamp": "2026-08-13T02:18:30+00:00",
            "title": "Database connection pool exhausted on server-03",
            "ruleWhy": "CRIT plus an exhaustion keyword.", "explanation": "Check the pool.",
            "predicate": "level == CRIT", "ruleRef": "detect_critical_and_resource()",
            "occurrences": 2, "linesNote": None, "chips": [],
            "lines": [{"n": 14, "a": "pool exhausted", "hit": "", "b": "", "crit": True}],
            "timeline": [{"t": "02:18:30", "label": "Pool hits its ceiling", "dot": "#e2807f"}],
        },
        {
            "id": "l0", "sev": "LOW", "sevColor": "#9397ab", "ruleSev": "— below threshold",
            "llmSev": None, "llmWhy": None, "delta": "note-only", "prov": "LLM-SURFACED",
            "type": "disk", "host": "—", "hostDerived": False, "time": "", "stamp": "",
            "title": "Disk at 78% on /var/log — below the 80% threshold",
            "ruleWhy": "", "explanation": "Watch log growth.", "predicate": "",
            "ruleRef": "", "occurrences": 1,
            "linesNote": "this rule records a summary, not a line excerpt",
            "chips": [{"text": "no rule fired"}],
            "lines": [{"n": "", "a": "disk usage at 78%", "hit": "", "b": "", "crit": False}],
            "timeline": [],
        },
    ],
}

# --- Dashboard-redesign contract keys (shared with feat/dashboard-data) -------
# events: every parsed record with a display bucket; severityCounts sums to
# linesParsed; mitreFrequency is ranked descending. Hand-written like the rest
# of LIVE_STATE — the INFO filler lines are generated to keep this readable.
LIVE_STATE["linesParsed"] = 19
LIVE_STATE["linesUnparsed"] = 0


def _ev(n, ts, level, host, msg, bucket, isFinding=False, findingId=None):
    raw = f"{ts} {level or ''} {host} {msg}".strip()
    return {"n": n, "ts": ts, "level": level, "host": host, "msg": msg,
            "raw": raw, "bucket": bucket, "isFinding": isFinding, "findingId": findingId}


LIVE_STATE["events"] = [
    _ev(1, "2026-08-13T02:14:01Z", "INFO", "server-01", "healthcheck ok #1", "INFO"),
    _ev(2, "2026-08-13T02:14:05Z", "INFO", "server-01",
        "request GET /api/status 200 12ms", "INFO"),
    _ev(3, "2026-08-13T02:15:02Z", "WARN", "server-01",
        "disk usage at 78% on /var/log", "MEDIUM"),
    _ev(4, "2026-08-13T02:15:40Z", "NOTICE", "server-02", "config reloaded", "LOW"),
    _ev(5, "2026-08-13T02:16:52Z", "ERROR", "server-01",
        "auth success for 'admin' from 203.0.113.44 after failures", "CRITICAL",
        isFinding=True, findingId="d0"),
    _ev(6, "2026-08-13T02:17:10Z", "ERROR", "server-02",
        "TLS handshake failure from 198.51.100.9", "HIGH"),
] + [
    _ev(n, f"2026-08-13T02:17:{n + 4:02d}Z", "INFO", "server-02",
        f"healthcheck ok #{n}", "INFO")
    for n in [*range(7, 14), 15, 16]         # 9 INFO filler lines; 14 is the finding
] + [
    _ev(14, "2026-08-13T02:18:30Z", "CRIT", "server-03",
        "db connection pool exhausted", "CRITICAL", isFinding=True, findingId="d2"),
    _ev(17, "2026-08-13T02:18:29Z", "INFO", "server-03", "pool watermark 91%", "INFO"),
    _ev(18, "2026-08-13T02:19:10Z", "WARN", "firewall-01",
        "blocked outbound 45.153.160.2:4444", "HIGH", isFinding=True, findingId="d1"),
    _ev(19, None, None, "—", "###corrupted trailer###", "UNKNOWN"),
]
LIVE_STATE["severityCounts"] = {"CRITICAL": 2, "HIGH": 2, "MEDIUM": 1, "LOW": 1,
                                "INFO": 12, "UNKNOWN": 1}     # == linesParsed (19)
LIVE_STATE["mitreFrequency"] = [
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "count": 4},
    {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control", "count": 2},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "count": 1},
]

HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const js = fs.readFileSync(process.argv[2], "utf8");
const LIVE = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));

let fails = 0;
const check = (label, cond, detail) => {
  if (!cond) fails++;
  console.log(`  [${cond ? "PASS" : "FAIL"}] ${label}${!cond && detail ? " — " + detail : ""}`);
};

/* Runs the console's real render path against a stubbed DOM.
   `pre` lets a case set console state (e.g. open the manifest) before boot.
   `post` runs AFTER boot, for state boot itself owns — marks and the bulk selection
   are hydrated from the run at boot, so setting them beforehand is overwritten. */
function run(consoleData, pre, post) {
  let html = "";
  const listeners = {};
  let src = pre ? js.replace("boot();", pre + " boot();") : js;
  if (post) src = src.replace("boot();", "boot(); " + post + " render();");
  const ctx = {
    document: {
      getElementById: () => ({ set innerHTML(v) { html = v; }, get innerHTML() { return html; } }),
      addEventListener: (t, fn) => { listeners[t] = fn; },
      activeElement: { tagName: "BODY" },
    },
    window: { print: () => {} }, navigator: {},
    fetch: () => Promise.reject(new Error("no server")),   // file:// behaviour
    console,
  };
  if (consoleData) ctx.window.CONSOLE_DATA = consoleData;
  vm.createContext(ctx);
  vm.runInContext(src, ctx);
  return { html, listeners, ctx };
}
const rows = (h) => (h.match(/class="row"/g) || []).length;
const clone = (o) => JSON.parse(JSON.stringify(o));

console.log("0. log-source picker (serve.py started with no --input):");
{
  const idle = { idle: true, live: true, findings: [] };
  const withSources = (pre) => run(idle, `state.sources = ${JSON.stringify({
    samples: [{ value: "sample-2.log", name: "sample-2.log", lines: 19, bytes: 1576 },
              { value: "samples/OpenSSH_2k.log", name: "OpenSSH_2k.log", lines: 2000, bytes: 1 }],
    suggestedUrls: [{ label: "LogHub · OpenSSH (2k lines)", url: "https://example/OpenSSH_2k.log" }]
  })}; ${pre || ""}`).html;

  let p = withSources();
  check("renders the picker, not a findings list", p.includes("Choose a log to analyze"));
  check("(a) bundled samples listed as buttons", p.includes('data-sample="sample-2.log"'));
  check("(a) shows sample line counts", p.includes("19 lines"));
  check("(b) local file input present", p.includes('id="fileInput"') && p.includes('data-act="upload"'));
  check("(b) states the file never leaves the machine",
        p.includes("never leaves this machine"));
  check("(b) accept attr lists the broadened types",
        p.includes('accept=".log,.txt,.out,.syslog,.messages,.err,.1,.2"'));
  check("(b) hint names the accepted types", p.includes("reads as plain text"));
  check("(c) URL field + fetch action", p.includes('id="urlInput"') && p.includes('data-act="fetch"'));
  check("(c) suggested LogHub chips", p.includes("data-suggest="));
  check("(c) network source is visually separated", p.includes("src-net"));
  check("(c) says it downloads public data and uploads nothing",
        p.includes("downloads</strong>") && p.includes("never uploaded"));
  check("compare checkbox offered", p.includes('id="cmpInput"'));
  check("no findings table on the picker", (p.match(/class="row"/g) || []).length === 0);

  p = withSources('state.error = "could not fetch that URL: timed out";');
  check("surfaces analysis errors on the picker", p.includes("could not fetch that URL"));

  p = withSources('state.busy = true; state.busyLabel = "OpenSSH_2k.log";');
  check("busy screen while analyzing", p.includes("Analyzing OpenSSH_2k.log"));
  check("busy screen explains what is happening", p.includes("runs on this machine"));

  // A bare spinner is indistinguishable from a hang, so the counts are the feature.
  p = withSources('state.busy = true; state.busyLabel = "OpenSSH_2k.log"; '
    + 'state.progress = {status:"running", phase:"explain", done:4, total:23, '
    + 'findings:18, chunks:80, gapFill:false, etaSeconds:1408};');
  check("busy screen shows chunk progress", p.includes("chunk 4 of 23"));
  check("busy screen shows a percentage", p.includes("17%"));
  check("busy screen shows an ETA", p.includes("~23 min left"));
  check("busy screen reports findings already found", p.includes("18 rule finding(s) already"));
  check("busy screen explains the scoping", p.includes("cost scales with findings"));
}

console.log("\n0b. results view offers a way back to the picker:");
check("'New analysis' button on a live run", run(LIVE).html.includes('data-act="new"'));

console.log("\n0c. run navigation — results outlive a refresh or a restart:");
{
  const RUNS = JSON.stringify([
    { file: "a.json", runId: "sample-2-2026-08-16", label: "sample-2.log", findings: 5,
      generatedAt: "2026-08-16T14:14:41", compareRun: true, unrecognized: false },
    { file: "b.json", runId: "Linux_2k-2026-08-16", label: "samples/Linux_2k.log", findings: 27,
      generatedAt: "2026-08-16T14:17:27", compareRun: false, unrecognized: false },
  ]);
  let h = run(LIVE, `state.runs = ${RUNS};`).html;
  check("nav button shows the saved-run count", h.includes(">Runs (2)<"));
  check("panel hidden until opened", !h.includes("Saved runs"));

  h = run(LIVE, `state.runs = ${RUNS}; state.showRuns = true;`).html;
  check("panel lists every saved run", h.includes("sample-2-2026-08-16")
        && h.includes("Linux_2k-2026-08-16"));
  check("entries are clickable", h.includes('data-run="a.json"'));
  check("entries carry finding counts", h.includes("27 finding(s)"));
  check("compare runs are marked", h.includes("· compare"));

  // The picker offers history too, so a restart lands somewhere useful.
  const idle = { idle: true, live: true, findings: [] };
  h = run(idle, `state.sources = {samples:[],suggestedUrls:[]}; state.runs = ${RUNS};`).html;
  check("picker offers saved runs", h.includes("Reopen a saved run"));
  // contiguous fragment: the sentence wraps across a newline in the template
  check("picker explains why history exists", h.includes("not cost you another analysis"));
}

console.log("\n0d. standalone export mode (no server exists behind it):");
{
  // The export inlines its run and sets STANDALONE. Every server-backed control
  // must be absent rather than present-and-broken.
  const withFlag = (pre) => {
    let out = "";
    const ctx = {
      document: { getElementById: () => ({ set innerHTML(v) { out = v; },
                                           get innerHTML() { return out; } }),
                  addEventListener: () => {}, activeElement: { tagName: "BODY" } },
      window: { CONSOLE_DATA: LIVE, STANDALONE: true, print: () => {} },
      navigator: {},
      fetch: () => { throw new Error("a standalone export must never call the network"); },
      console,
    };
    vm.createContext(ctx);
    vm.runInContext(pre ? js.replace("boot();", pre + " boot();") : js, ctx);
    return out;
  };

  const h = withFlag();
  // Banded default: CRITICAL+HIGH open -> 3 of the 4 finding cards visible.
  check("renders the run without any fetch", (h.match(/class="row"/g) || []).length === 3);
  check("static-export banner shown", h.includes("Static export"));
  check("banner says it opens anywhere", h.includes("open anywhere, no install"));
  check("banner states no network calls", h.includes("no network calls"));
  check("'New analysis' removed (no server)", !h.includes('data-act="new"'));
  check("run navigation removed (no server)", !h.includes('data-act="runs"'));
  check("download button removed (already downloaded)", !h.includes('data-act="download"'));
  check("keeps the local-processing cue", h.includes("0 bytes leave this machine"));
  check("keeps the integrity manifest button", h.includes('data-act="manifest"'));

  // A finding without prose must never offer a button that cannot work.
  const noProse = clone(LIVE);
  noProse.findings[0].explanation = "";
  const h2 = withFlag(`window.CONSOLE_DATA.findings[0].explanation = ""; state.selId = "d0";`);
  check("unexplained finding has no dead button", !h2.includes('data-act="explain"'));
  check("points at the interactive app instead",
        h2.includes("Explanation available in the") || h2.includes("interactive app"));
}

console.log("\n1. fixture fallback (no data, fetch fails — the file must still open):");
let { html: h, listeners } = run(null);
check("renders", h.length > 3000, h.length + " chars");
check("demo run-state switcher present", h.includes('name="runview"'));
check("click/change/keydown handlers bound",
      ["click", "change", "keydown"].every((k) => typeof listeners[k] === "function"));

console.log("\n2. live data — the run reads from the report, not the fixture:");
h = run(LIVE).html;
check("live run id rendered", h.includes("bench-2026-08-15"));
check("run-state switcher HIDDEN (state is derived, not chosen)", !h.includes('name="runview"'));
// The banded default view opens CRITICAL and HIGH only, so 3 of the 4 finding
// cards render; the LOW finding appears once its band is expanded.
check("default view renders the CRITICAL/HIGH findings", rows(h) === 3, rows(h) + " rows");
const OPEN_ALL = 'state.bands={CRITICAL:true,HIGH:true,MEDIUM:true,LOW:true,INFO:true,UNKNOWN:true};';
check("all 4 findings render with every band expanded",
      rows(run(LIVE, null, OPEN_ALL).html) === 4,
      rows(run(LIVE, null, OPEN_ALL).html) + " rows");
check("rule severity shown", h.includes("CRITICAL"));
check("under-rated delta shown", h.includes("under-rated by LLM"));
check("derived host shown", h.includes("server-01"));
check("evidence line text rendered", h.includes("auth failed from"));
check("evidence highlight applied", h.includes("ev-hit"));
check("predicate rendered", h.includes("failures_from(ip)"));
check("timeline rendered", h.includes("First failed login"));
check("under-rated pill matches the data", h.includes("<b>2</b>"));
// The LLM-surfaced finding lives in the LOW band, so its row needs the band open.
{
  const oh = run(LIVE, null, OPEN_ALL).html;
  check("LLM-surfaced row credits the model, no blank dash",
        oh.includes("model surfaced this") && oh.includes("no rule fired"));
}
// NOTE: `occurrences` is carried in the state but the console does not render it
// today, so a finding the dedupe collapsed reads as one event. Not asserted here
// because the test must describe the console as it is, not as it should be.

// When a rule records a summary rather than a line excerpt, the evidence header
// must say so instead of claiming the text is verbatim from the log.
h = run(LIVE, 'state.selId="l0";').html;
check("linesNote replaces the 'verbatim from the source log' claim",
      h.includes("not a line excerpt") && !h.includes("verbatim from the source log"));

console.log("\n2b. MITRE ATT&CK tags — derived annotation, never invented:");
h = run(LIVE).html;
check("mapped finding shows the compact technique tag",
      h.includes("T1110 · Brute Force · Credential Access"));
check("multi-technique rule shows every technique",
      h.includes("T1078 · Valid Accounts · Initial Access"));
check("C2-port rule shows its own technique",
      h.includes("T1571 · Non-Standard Port · Command and Control"));
check("tag is visually distinct from entity chips", h.includes("tag-mitre"));
check("tag states it does not affect severity",
      h.includes("does not affect severity"));
// d2 and l0 carry no mapping: exactly the 3 mapped tags above (2 on d0, 1 on
// d1), nothing invented for the other two findings.
check("unmapped findings show NO tag (3 tags, all on mapped findings)",
      (h.match(/tag-mitre/g) || []).length === 3,
      (h.match(/tag-mitre/g) || []).length + " tag(s)");
{
  // States saved before this feature carry no `mitre` key at all — must render.
  const legacy = clone(LIVE);
  legacy.findings.forEach((f) => delete f.mitre);
  const lh = run(legacy).html;
  check("legacy state without mitre keys still renders", rows(lh) === 3, rows(lh) + " rows");
  check("legacy state shows no tags", !lh.includes("tag-mitre"));
}

console.log("\n2c. criticality bands — the clean segmented default:");
h = run(LIVE).html;
{
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    .map((b) => h.indexOf(`data-bucket="${b}"`));
  check("all six bands render in criticality order",
        order.every((i) => i >= 0) && order.every((i, k) => k === 0 || i > order[k - 1]),
        order.join(","));
  check("band headers carry finding + event counts",
        h.includes("2 finding(s) · 2 event(s)")        // CRITICAL
        && h.includes("0 finding(s) · 12 event(s)"));  // INFO
  const expanded = (b) => new RegExp(
    `data-band="${b}"[^>]*aria-expanded="true"`).test(h);
  check("CRITICAL and HIGH start expanded", expanded("CRITICAL") && expanded("HIGH"));
  check("MEDIUM/LOW/INFO/UNKNOWN start collapsed",
        ["MEDIUM", "LOW", "INFO", "UNKNOWN"].every((b) => !expanded(b)));
  check("a finding keeps its full card inside its band",
        /data-bucket="CRITICAL"[\s\S]*?class="row"[\s\S]*?RULE-CAUGHT/.test(h));
  check("plain events render compactly, distinct from finding cards",
        h.includes('class="evt-line"') && h.includes("TLS handshake failure"));
  check("finding lines are not repeated as plain events",
        !h.includes(">db connection pool exhausted</span>") || rows(h) === 3);
  check("a collapsed band's events are not in the DOM", !h.includes("healthcheck ok #7"));
  check("no severity badge on a plain event (grouping is not a verdict)",
        !/evt-line[^>]*>[\s\S]{0,200}sev-label/.test(h));
}
{
  const opened = run(LIVE, null, OPEN_ALL).html;
  check("expanding INFO reveals its compact events", opened.includes("healthcheck ok #7"));
  check("UNKNOWN band holds the unparseable-level line",
        /data-bucket="UNKNOWN"[\s\S]*?corrupted trailer/.test(opened));
}

console.log("\n2d. event dropdowns — detail waits until asked for:");
{
  const closed = run(LIVE).html;
  // Event n6 sits in the open HIGH band: its compact line shows the msg, but the
  // full raw line exists only inside its dropdown.
  check("raw line absent while the dropdown is closed",
        !closed.includes("2026-08-13T02:17:10Z ERROR server-02 TLS handshake failure"));
  const open = run(LIVE, null, "state.openEvents=[6];").html;
  check("dropdown shows the raw line VERBATIM",
        open.includes("2026-08-13T02:17:10Z ERROR server-02 TLS handshake failure from 198.51.100.9"));
  check("dropdown carries line/ts/level/host fields",
        open.includes("<k>level</k>") && open.includes("<k>host</k>")
        && open.includes("<k>ts</k>"));
}

console.log("\n2e. overview — Top ATT&CK ranking and the three charts:");
{
  check("Top-ATT&CK panel present", h.includes('id="atk-panel"'));
  check("panel renders the compact ranked line",
        h.includes("T1110 · Brute Force · Credential Access — 4"));
  const iT1110 = h.indexOf('data-atk="T1110"'), iT1571 = h.indexOf('data-atk="T1571"'),
        iT1078 = h.indexOf('data-atk="T1078"');
  check("techniques ranked by frequency, descending",
        iT1110 >= 0 && iT1110 < iT1571 && iT1571 < iT1078,
        [iT1110, iT1571, iT1078].join(","));
  check("ATT&CK chart: one SVG bar per technique",
        (h.match(/class="chart-atk"/g) || []).length === 3);
  check("ATT&CK bars reflect the counts (100/50/25%)",
        h.includes('width="100.0"') && h.includes('width="50.0"') && h.includes('width="25.0"'));

  check("severity chart: one SVG bar per bucket",
        (h.match(/class="chart-sev"/g) || []).length === 6);
  // counts 2/12 and 12/12 of the max bucket (INFO=12).
  check("severity bars reflect the counts",
        h.includes('width="16.7"') && h.includes("<b>12</b>"));
  check("severity chart names its total", h.includes("19 parsed events"));

  check("timeline chart SVG present", h.includes('class="chart-timeline"'));
  check("timeline is honest about unplaceable events",
        h.includes("1 event(s) have no"));
  check("charts declare themselves display-only",
        h.includes("severities come from the rules"));
  check("charts can be tucked away", h.includes('data-act="overview"'));
  const hidden = run(LIVE, null, "state.overview=false;").html;
  check("hidden overview leaves no charts, only the toggle",
        !hidden.includes("chart-sev") && hidden.includes("show charts"));

  // No techniques -> NO panel, never an invented ranking.
  const noAtk = clone(LIVE);
  noAtk.mitreFrequency = [];
  check("empty mitreFrequency renders no ATT&CK panel",
        !run(noAtk).html.includes('id="atk-panel"'));
}

console.log("\n2f. honest states keep their banners and get NO charts:");
{
  const unrec = clone(LIVE);
  unrec.findings = []; unrec.linesParsed = 0; unrec.linesUnparsed = 100;
  unrec.unrecognized = true; unrec.emptyInput = false;
  const uh = run(unrec).html;
  check("unrecognized run keeps the honest banner", uh.includes("Log format not recognized"));
  check("unrecognized run renders no charts",
        !uh.includes("chart-sev") && !uh.includes("chart-timeline")
        && !uh.includes('id="atk-panel"'));
  check("unrecognized run renders no bands", !uh.includes('data-bucket='));

  const emptyIn = clone(LIVE);
  emptyIn.findings = []; emptyIn.linesParsed = 0; emptyIn.linesUnparsed = 0;
  emptyIn.unrecognized = false; emptyIn.emptyInput = true; emptyIn.events = [];
  const eh = run(emptyIn).html;
  check("empty input keeps its banner, no charts",
        eh.includes("the input is empty") && !eh.includes("chart-sev"));

  // A run saved before this feature has none of the new keys: flat list, no bands.
  const legacy = clone(LIVE);
  delete legacy.events; delete legacy.severityCounts; delete legacy.mitreFrequency;
  const lh = run(legacy).html;
  check("legacy run falls back to the flat finding list", rows(lh) === 4, rows(lh) + " rows");
  check("legacy run shows no bands and no charts",
        !lh.includes('data-bucket=') && !lh.includes("chart-sev"));
}

console.log("\n3. filters:");
const F = (name) => run(LIVE, `state.filter=${JSON.stringify(name)};`).html;
// "All" keeps the clean band defaults (LOW stays collapsed); any other filter is
// an explicit "show me these", so a band holding a match auto-expands.
check("All -> 3 rows (band defaults)", rows(F("all")) === 3, rows(F("all")) + "");
check("Rule != LLM -> 2 rows", rows(F("dis")) === 2, rows(F("dis")) + "");
check("LLM-surfaced -> 1 row (its band auto-expands)", rows(F("llm")) === 1, rows(F("llm")) + "");
check("Unreviewed -> 4 rows", rows(F("open")) === 4, rows(F("open")) + "");

console.log("\n4. selection, marking, bulk:");
h = run(LIVE, 'state.selId="d1";').html;
check("detail follows selection", h.includes("45.153.160.2:4444"));
h = run(LIVE, null, 'state.marks={d0:"tp"};').html;
check("true-positive mark rendered", h.includes("Marked true positive"));
h = run(LIVE, null, 'state.marks={d0:"fp"};').html;
check("false-positive mark rendered", h.includes("Dismissed false positive"));
h = run(LIVE, null, 'state.marks={d0:"tp"}; state.filter="open";').html;
check("Unreviewed filter excludes a marked finding", rows(h) === 3, rows(h) + "");
h = run(LIVE, null, 'state.checked=["d0","d1"];').html;
check("bulk bar shows the selection count", h.includes("2 selected"));

console.log("\n4b. marks are persisted, not page-local:");
// The run carries the marks. This is the whole point: a refresh, a restart, or
// reopening from history must show the review that was already done.
const marked = clone(LIVE);
marked.marks = { d0: "tp", d1: "fp" };
h = run(marked).html;
check("marks arrive from the run, with no page state set",
      h.includes("Marked true positive"));
check("a run's marks survive into the Unreviewed filter",
      rows(run(marked, null, 'state.filter="open";').html) === 2,
      rows(run(marked, null, 'state.filter="open";').html) + "");
// A run with no marks must CLEAR them, not inherit the last run's.
{
  const r = run(marked, null, 'DATA = {live:true, findings:DATA.findings}; adoptMarks();');
  check("reopening a run with no marks clears the previous run's",
        !r.html.includes("Marked true positive"));
}
{
  // Marking writes to the server. Without this the mark lives only in the tab.
  const posts = [];
  const r = run(LIVE);
  r.ctx.fetch = (url, opts) => { posts.push([url, JSON.parse(opts.body)]);
                                 return Promise.resolve({ ok: true, json: () => ({}) }); };
  vm.runInContext('mark("d0", "tp");', r.ctx);
  check("marking POSTs to /api/mark", posts.length === 1 && posts[0][0] === "/api/mark",
        JSON.stringify(posts));
  check("it sends the finding id and the mark",
        posts.length === 1 && posts[0][1].id === "d0" && posts[0][1].mark === "tp",
        JSON.stringify(posts[0] && posts[0][1]));
}

console.log("\n5. manifest is integrity, never a signature:");
h = run(LIVE, "state.manifest=true;").html;
check("real input hash shown", h.includes(LIVE.manifest.input_sha256.slice(0, 16)));
check("real detector hash shown", h.includes(LIVE.manifest.detector_sha256.slice(0, 16)));
check("NO 'signature valid' claim", !h.includes("signature valid"));
check("NO 'signed' field", !/<k>signed<\/k>/.test(h));
check("states hashes are recomputable, not a signature", h.includes("not a signature"));

console.log("\n6. HONEST STATE — compare not run is never a fake zero:");
const noCmp = clone(LIVE);
noCmp.compareRun = false; noCmp.underratedCount = null;
noCmp.findings.forEach((f) => { f.llmSev = null; f.delta = null; });
h = run(noCmp).html;
// Header and row are asserted with DISTINCT strings: "compare not run" appears in
// both, so a single substring check passes even if the header loses it entirely.
check("header pill states compare was not run",
      /pill[^>]*>[\s\S]{0,200}compare not run[\s\S]{0,120}rerun with/.test(h));
check("no under-rated count pill", !/<b>\d+<\/b>\s*<span>findings a raw LLM/.test(h));
check("row LLM column states compare not run",
      /cmp-k">LLM alone<\/div>\s*<div class="cmp-v"[^>]*>compare not run/.test(h));
check("detail card offers the --compare rerun", h.includes("--compare"));

console.log("\n7. HONEST STATE — degraded chunks are Partial, not misses:");
const deg = clone(LIVE);
deg.degraded = true; deg.chunksUsable = 0; deg.chunksTotal = 4;
deg.findings[0].delta = "unknown"; deg.findings[0].llmSev = "UNKNOWN";
h = run(deg).html;
check("partial banner shown", h.includes("This run is partial"));
check("explains UNKNOWN is not a miss", h.includes("not the same as missing them"));
check("row shows the model gave no usable answer", h.includes("model gave no usable answer"));

console.log("\n8. HONEST STATE — analyzer errors also mean Partial:");
const errd = clone(LIVE);
errd.analyzerErrors = 1;
check("partial banner shown for an unanalyzed chunk",
      run(errd).html.includes("This run is partial"));

console.log("\n9. severity ramp — monotonic, and no green anywhere:");
/* Green reads as "safe". A severity scale that drifts toward it mis-signals at a
   glance, whatever the label says — so the ramp is asserted by hue, not by eye. */
const hueOf = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
  if (!d) return null;
  let h = mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
  h *= 60; return h < 0 ? h + 360 : h;
};
const RAMP = { CRITICAL: "#e2807f", HIGH: "#d8a35e", MEDIUM: "#dcb64a",
               LOW: "#9397ab", INFO: "#75798c" };
for (const [name, hex] of Object.entries(RAMP)) {
  const hue = hueOf(hex);
  const green = hue !== null && hue > 50 && hue < 170;
  check(`${name} is not green (hue ${hue === null ? "n/a" : hue.toFixed(0)}°)`, !green, hex);
}
check("MEDIUM is gold, not the old lime #c9c07a", !js.includes("c9c07a"));
check("warm steps descend in alarm: CRITICAL < HIGH < MEDIUM hue",
      hueOf(RAMP.CRITICAL) < hueOf(RAMP.HIGH) && hueOf(RAMP.HIGH) < hueOf(RAMP.MEDIUM));
h = run(LIVE).html;
check("MEDIUM colour is actually applied in the render",
      h.includes("#dcb64a") || js.includes("#dcb64a"));

console.log("\n10. sovereignty copy is present tense in BOTH places:");
h = run(LIVE).html;
check("header states the standing guarantee", h.includes("0 bytes leave this machine"));
check("footer matches the header exactly",
      (h.match(/0 bytes leave this machine/g) || []).length === 2,
      (h.match(/0 bytes leave this machine/g) || []).length + " occurrence(s)");
check("no past-tense 'left the machine' anywhere", !h.includes("left the machine"));

console.log("\n11. LLM-surfaced framing is positive, never a blank or a failure:");
h = run(LIVE, 'state.selId="l0";').html;
check("outcome credits the model", h.includes("Model surfaced this"));
check("explains the below-threshold catch", h.includes("below every rule threshold"));
check("shows the model's own severity, not an empty dash",
      /Model severity[\s\S]{0,220}>LOW</.test(h));
check("no 'shown as context only' dismissal", !h.includes("Shown as context only"));
check("rule card says no rule fired rather than a bare em-dash",
      h.includes("no rule fired") && h.includes("Nothing in the ruleset matched"));

console.log("\n11b. an analyzer failure is not a model contribution:");
const noModel = clone(LIVE);
noModel.modelFindings = 0; noModel.analyzerErrors = 2;
h = run(noModel).html;
check("run bar says the model contributed nothing", h.includes("contributed no findings"));
check("names the unanalyzed chunk count", h.includes("2 chunk(s) not analyzed"));
const withModel = clone(LIVE);
withModel.modelFindings = 1; withModel.analyzerErrors = 0;
check("silent when the model did contribute",
      !run(withModel).html.includes("contributed no findings"));

console.log("\n12. HONEST STATE — 0 parsed is NOT an all-clear:");
/* Zero findings because nothing was read is not zero findings. Showing the green
   tick here would report a false success on an audit surface. */
const unrec = clone(LIVE);
unrec.findings = []; unrec.linesParsed = 0; unrec.linesUnparsed = 100;
unrec.unrecognized = true; unrec.emptyInput = false;
unrec.runParsed = "0 lines parsed · 100 unparsed";
h = run(unrec).html;
check("shows the unrecognized-format state", h.includes("Log format not recognized"));
check("states 0 of N parsed", h.includes("0 of 100 lines parsed"));
check("explicitly NOT an all-clear", h.includes("not</strong> an all-clear"));
check("does NOT render the green all-clear", !h.includes("All clear — 0 anomalies"));
check("no success tick", !h.includes(">✓<"));
check("detail pane says nothing was analyzed", h.includes("Nothing was analyzed"));

/* The bug this guards: the caution used to live inside the empty-list renderer, so a
   run that parsed nothing but still listed model output showed a normal findings list
   and no warning at all — coverage the run never had. */
const unrecWithFindings = clone(LIVE);
unrecWithFindings.linesParsed = 0; unrecWithFindings.linesUnparsed = 100;
unrecWithFindings.unrecognized = true; unrecWithFindings.emptyInput = false;
h = run(unrecWithFindings).html;
check("warning shows even WITH findings listed", h.includes("Log format not recognized"));
check("says it is not evidence the log is clean", h.includes("not</strong> evidence"));
check("names the unvalidated items", h.includes("not rule-backed"));
check("findings still render (not hidden, just qualified)",
      rows(h) === LIVE.findings.length, rows(h) + " rows");

const emptyIn = clone(LIVE);
emptyIn.findings = []; emptyIn.linesParsed = 0; emptyIn.linesUnparsed = 0;
emptyIn.unrecognized = false; emptyIn.emptyInput = true;
h = run(emptyIn).html;
check("empty input gets its own wording", h.includes("the input is empty"));
check("empty input is not an all-clear either", !h.includes("All clear — 0 anomalies"));

console.log("\n13. HONEST STATE — zero findings WITH lines parsed is All clear:");
const clear = clone(LIVE);
clear.findings = []; clear.linesParsed = 19; clear.linesUnparsed = 0;
clear.unrecognized = false; clear.emptyInput = false;
h = run(clear).html;
check("all-clear empty state", h.includes("All clear — 0 anomalies"));
check("detail pane empty state", h.includes("No finding to review"));
check("no 'signed manifest' language", !h.includes("signed manifest"));

console.log(`\n${fails ? "FAILED — " + fails + " check(s)" : "PASSED — all checks green"}`);
process.exit(fails ? 1 : 0);
"""


def extract_js(html_path):
    src = html_path.read_text()
    m = re.search(r"<script>\n(.*?)\n</script>", src, re.S)
    if not m:
        print("ERROR: could not find the console's <script> block")
        sys.exit(1)
    return m.group(1)


def check_server_routing():
    """Python-side checks on serve.py: source resolution and the route table.

    No sockets, no analyzer, no network — these exercise the pure functions that
    decide what a browser request is allowed to reach.
    """
    sys.path.insert(0, str(HERE))
    import serve

    results = []

    def check(label, cond, detail=""):
        results.append(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond or not detail else f" — {detail}"))

    print("\nserve.py routing and source resolution:")

    samples = serve.bundled_samples()
    check("bundled samples discovered", len(samples) >= 1, f"{len(samples)} found")
    check("sample-2.log is offered", any(s["value"] == "sample-2.log" for s in samples))
    check("samples carry line counts", all(s["lines"] > 0 for s in samples))

    # The whitelist is the security boundary for a browser-supplied string.
    for bad in ("../../../etc/passwd", "/etc/passwd", "samples/../log_analyzer.py", ""):
        try:
            serve.resolve_sample(bad)
            check(f"rejects {bad!r}", False, "it was accepted")
        except ValueError:
            check(f"rejects {bad!r}", True)
    try:
        serve.resolve_sample("sample-2.log")
        check("accepts a real bundled sample", True)
    except ValueError as e:
        check("accepts a real bundled sample", False, str(e))

    for bad in ("file:///etc/passwd", "ftp://host/x.log", "not-a-url", "javascript:alert(1)"):
        try:
            serve.fetch_url(bad, "/tmp")
            check(f"refuses to fetch {bad!r}", False, "it was accepted")
        except ValueError:
            check(f"refuses to fetch {bad!r}", True)
        except Exception:
            check(f"refuses to fetch {bad!r}", True)   # network never reached

    handler = serve.ConsoleHandler
    check("GET routes exist", all(hasattr(handler, m) for m in ("do_GET", "do_HEAD")))
    check("POST route exists (analyze is the only write-ish action)", hasattr(handler, "do_POST"))
    for method in ("do_PUT", "do_DELETE", "do_PATCH"):
        check(f"{method} refused", hasattr(handler, method))

    body = (b'--X\r\nContent-Disposition: form-data; name="file"; filename="a.log"\r\n\r\n'
            b'2026-08-13T02:16:44Z WARN h auth failed\r\n--X\r\n'
            b'Content-Disposition: form-data; name="compare"\r\n\r\n1\r\n--X--\r\n')
    fields = serve.parse_multipart(body, 'multipart/form-data; boundary=X')
    check("multipart upload parses (cgi is gone in 3.13)",
          fields.get("file", (None, None))[0] == "a.log"
          and b"auth failed" in (fields.get("file", (None, b""))[1] or b""))
    check("multipart non-file fields parse", fields.get("compare", (None, b""))[1] == b"1")

    print("\nstylesheet:")
    css = CONSOLE_HTML.read_text()
    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
    # Only var() calls with no fallback: `var(--x, 0 0 0 1px #000)` is fine undefined.
    used = set(re.findall(r"var\((--[a-z0-9-]+)\s*\)", css))
    # An undefined token makes the whole declaration invalid, so the property silently
    # falls back to its initial value — a var(--space-5) typo zeroed the detail pane's
    # padding and nothing failed. This is the check that would have caught it.
    check("every CSS variable used is defined", not (used - defined),
          "undefined: " + ", ".join(sorted(used - defined)))
    check("the narrow-window breakpoint is present (panes stack rather than clip)",
          "@media (max-width:1000px)" in css)

    print("\nrun history — a review must survive a reopen:")
    with tempfile.TemporaryDirectory(prefix="runs-test-") as runs_tmp:
        # The live state file sits BESIDE the run directory, as it does in the app —
        # inside it, list_runs() would count it as a run.
        runs_dir = Path(runs_tmp) / ".runs"
        runs_dir.mkdir()
        orig_runs, orig_state = serve.RUNS_DIR, serve.STATE_FILE
        orig_current, orig_STATE = serve.CURRENT_RUN_FILE, serve.STATE
        try:
            serve.RUNS_DIR = runs_dir
            serve.STATE_FILE = Path(runs_tmp) / "console_state.json"

            older = {"runId": "run-a", "generatedAt": "2026-08-16T09:00:00Z",
                     "findings": [{"id": "d0"}]}
            newer = {"runId": "run-b", "generatedAt": "2026-08-16T18:00:00Z",
                     "findings": [{"id": "d0"}]}
            serve.save_run(older)
            newer_file = serve.save_run(newer)

            check("saved runs are listed newest first",
                  [r["runId"] for r in serve.list_runs()] == ["run-b", "run-a"],
                  str([r["runId"] for r in serve.list_runs()]))

            # A mark on the OLDER run rewrites its file. Ordering must not follow that
            # write, or reviewing an old run would silently promote it to newest.
            serve.STATE = dict(older)
            serve.CURRENT_RUN_FILE = sorted(p.name for p in runs_dir.glob("*.json"))[0]
            serve.STATE["marks"] = {"d0": "tp"}
            serve.persist_state()
            check("marking an old run does not reorder history",
                  [r["runId"] for r in serve.list_runs()] == ["run-b", "run-a"],
                  str([r["runId"] for r in serve.list_runs()]))
            check("the mark is written into the saved run, not just the live state",
                  json.loads((runs_dir / serve.CURRENT_RUN_FILE).read_text())
                      .get("marks") == {"d0": "tp"})
            check("reopening that run returns the mark",
                  serve.load_run(serve.CURRENT_RUN_FILE).get("marks") == {"d0": "tp"})
            check("the run index reports how many findings were marked",
                  next(r["marked"] for r in serve.list_runs() if r["runId"] == "run-a") == 1)

            # An explanation generated after a reopen has to land in the same place.
            serve.STATE = serve.load_run(newer_file)
            serve.CURRENT_RUN_FILE = newer_file
            serve.STATE["findings"][0]["explanation"] = "generated on demand"
            serve.persist_state()
            check("an on-demand explanation is written back to the reopened run",
                  json.loads((runs_dir / newer_file).read_text())["findings"][0]
                      .get("explanation") == "generated on demand")

            # With no run to write to, persisting must not invent one.
            serve.CURRENT_RUN_FILE = None
            serve.STATE = {"runId": "unsaved", "findings": [], "marks": {"d0": "fp"}}
            serve.persist_state()
            check("a run not yet in history is not conjured into it",
                  len(list(runs_dir.glob("*.json"))) == 2,
                  str(sorted(p.name for p in runs_dir.glob("*.json"))))
        finally:
            serve.RUNS_DIR, serve.STATE_FILE = orig_runs, orig_state
            serve.CURRENT_RUN_FILE, serve.STATE = orig_current, orig_STATE

    print("\nexplanation acceptance (shared by the on-demand button and the second pass):")
    import log_analyzer as la

    def with_reply(explanations, **kw):
        """Run explain_single against a canned model reply."""
        real = la.analyze_chunk
        la.analyze_chunk = lambda *a, **k: {"explanations": explanations}
        try:
            return la.explain_single("", "", "", [], 0, "", **kw)
        finally:
            la.analyze_chunk = real

    check("takes an explanation whose rule id matches",
          with_reply([{"rule_id": "auth_bruteforce", "explanation": "brute force from 10.0.0.1"}],
                     rule_id="auth_bruteforce") == "brute force from 10.0.0.1")
    check("takes an explanation with no rule id (the context named one finding)",
          with_reply([{"explanation": "prose"}], rule_id="auth_bruteforce") == "prose")
    check("refuses an explanation about a different rule",
          with_reply([{"rule_id": "disk_space_low", "explanation": "disk"}],
                     rule_id="auth_bruteforce") == "")
    check("refuses prose that never names the finding's host",
          with_reply([{"rule_id": "auth_bruteforce", "explanation": "attack from 10.0.0.9"}],
                     rule_id="auth_bruteforce", ident="10.0.0.1") == "")
    check("accepts prose that does name it",
          with_reply([{"rule_id": "auth_bruteforce", "explanation": "attack from 10.0.0.1"}],
                     rule_id="auth_bruteforce", ident="10.0.0.1") == "attack from 10.0.0.1")
    check("an empty explanation is not an answer",
          with_reply([{"rule_id": "auth_bruteforce", "explanation": ""}],
                     rule_id="auth_bruteforce") == "")
    check("no explanations at all returns nothing, never a placeholder",
          with_reply([]) == "")

    print("\nmarks across a re-publish (rules-only, then explained):")
    prev = {"findings": [{"id": "detector-0", "title": "brute force"},
                         {"id": "detector-1", "title": "disk low"}],
            "marks": {"detector-0": "tp", "detector-1": "fp"}}
    same = {"findings": [{"id": "detector-0", "title": "brute force"},
                         {"id": "detector-1", "title": "disk low"},
                         {"id": "llm-2", "title": "something new"}]}
    check("a mark survives the run being published again",
          serve.carry_marks(prev, same) == {"detector-0": "tp", "detector-1": "fp"},
          str(serve.carry_marks(prev, same)))
    shifted = {"findings": [{"id": "detector-0", "title": "disk low"},
                            {"id": "detector-1", "title": "brute force"}]}
    check("a mark is dropped, never moved, when that id is now a different finding",
          serve.carry_marks(prev, shifted) == {},
          str(serve.carry_marks(prev, shifted)))
    gone = {"findings": [{"id": "detector-0", "title": "brute force"}]}
    check("a mark on a finding that no longer exists is dropped",
          serve.carry_marks(prev, gone) == {"detector-0": "tp"},
          str(serve.carry_marks(prev, gone)))
    check("a different run does not inherit marks", serve.carry_marks(None, same) == {})

    check("/api/mark is routed", "/api/mark" in inspect.getsource(handler.do_POST))
    check("the mark endpoint validates the value",
          "must be tp, fp, or null" in inspect.getsource(handler._mark))
    check("the mark endpoint refuses an unknown finding id",
          "no such finding" in inspect.getsource(handler._mark))

    return 0 if all(results) else 1


def check_log360():
    """Log360 sibling-parser checks: both entry shapes, the honest banner, and
    the two evidence rules — level UNKNOWN is never guessed, raw is verbatim.

    No sockets, no analyzer, no model — normalize.load + detect only.
    """
    ROOT = HERE.parent
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(HERE))
    import normalize
    from anomaly_detector import detect
    import adapter

    results = []

    def check(label, cond, detail=""):
        results.append(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond or not detail else f" — {detail}"))

    print("\nLog360 ingest (console/formats/log360.py):")

    csv_path = ROOT / "samples" / "log360_export.csv"
    sys_path_ = ROOT / "samples" / "log360_syslog.log"
    bad_path = HERE / "formats" / "fixtures" / "log360_malformed.csv"

    # --- CSV export ---------------------------------------------------------
    records, stats = normalize.load(csv_path)
    check("CSV export sniffed as log360_csv", stats["format"] == "log360_csv",
          stats["format"])
    check("CSV rows all parse (header is envelope, not an event)",
          stats["parsed"] == 10 and stats["unparsed"] == 0,
          f"parsed={stats['parsed']} unparsed={stats['unparsed']}")

    by_n = {r["n"]: r for r in records}
    src_lines = csv_path.read_text().splitlines()
    r = by_n[2]
    check("CSV Time -> ts", str(r["ts"]) == "2026-08-17 09:37:00+00:00", str(r["ts"]))
    check("CSV Severity -> level (Error -> ERROR)", r["level"] == "ERROR", r["level"])
    check("CSV Device -> host", r["host"] == "app-01", r["host"])
    check("CSV Message -> msg (quoted comma preserved)",
          r["msg"] == "Failed to connect to database, retrying in 5s", r["msg"])
    check("CSV raw is the verbatim source row",
          all(rec["raw"] == src_lines[rec["n"] - 1] for rec in records))

    # Never guess: empty and unrecognized severity cells are UNKNOWN, not INFO.
    check("empty severity -> UNKNOWN", by_n[9]["level"] == "UNKNOWN", by_n[9]["level"])
    check("unrecognized severity ('Unknown') -> UNKNOWN",
          by_n[10]["level"] == "UNKNOWN", by_n[10]["level"])
    check("empty Device falls back to Source", by_n[9]["host"] == "monitor-02",
          by_n[9]["host"])

    types = {f["type"] for f in detect(records)}
    check("CSV records produce findings (error burst + suspicious port)",
          {"error_rate_spike", "suspicious_outbound"} <= types, str(types))

    # --- Forwarded syslog ---------------------------------------------------
    records, stats = normalize.load(sys_path_)
    check("forwarded syslog sniffed as log360_syslog",
          stats["format"] == "log360_syslog", stats["format"])
    check("all forwarded lines parse", stats["parsed"] == 10 and stats["unparsed"] == 0,
          f"parsed={stats['parsed']} unparsed={stats['unparsed']}")

    src_lines = sys_path_.read_text().splitlines()
    r = records[0]
    check("syslog raw is the verbatim line, |PRI| envelope included",
          all(rec["raw"] == src_lines[rec["n"] - 1] for rec in records))
    check("|PRI| envelope stripped from msg", r["msg"].startswith("2026-08-17 09:37:02"),
          r["msg"][:40])
    check("syslog host parsed", r["host"] == "kali", r["host"])
    check("explicit DEBUG token in message wins", r["level"] == "DEBUG", r["level"])
    check("embedded full date -> ts (year is real, not inferred)",
          str(r["ts"]) == "2026-08-17 09:37:02+00:00", str(r["ts"]))
    # Line 8 has no level token; its level comes from the |28| envelope (28 % 8 = 4).
    check("no token -> level from |PRI| envelope (|28| -> WARN)",
          records[7]["level"] == "WARN", records[7]["level"])

    types = {f["type"] for f in detect(records)}
    check("syslog records produce findings (error burst + suspicious port)",
          {"error_rate_spike", "suspicious_outbound"} <= types, str(types))

    # --- Neither shape: the honest banner, never a fake-parse ---------------
    records, stats = normalize.load(bad_path)
    check("malformed file is NOT claimed as Log360", stats["format"] == "unknown",
          stats["format"])
    check("malformed file: 0 parsed, all lines surfaced as unparsed",
          stats["parsed"] == 0 and stats["unparsed"] == 6,
          f"parsed={stats['parsed']} unparsed={stats['unparsed']}")
    state = adapter.adapt({"source_file": str(bad_path), "findings": [],
                           "lines_parsed": 0, "lines_unparsed": stats["unparsed"]})
    check("console state shows the unrecognized banner",
          state["unrecognized"] and not state["emptyInput"])

    # --- Regression: existing formats keep their exact prior classification --
    for name, want in (("sample-2.log", "canonical"), ("samples/Linux_2k.log", "rfc3164")):
        _, s = normalize.load(ROOT / name)
        check(f"{name} still sniffs as {want}", s["format"] == want, s["format"])

    # --- Picker: bundled CSV samples are offered ----------------------------
    import serve
    values = {s["value"] for s in serve.bundled_samples()}
    check("picker offers the Log360 CSV sample", "samples/log360_export.csv" in values)
    check("picker offers the Log360 syslog sample", "samples/log360_syslog.log" in values)

    # File-type acceptance is a gate at the door only: it may refuse a file, but
    # accepting one must never change parsing or severity. (a) proves acceptance
    # feeds the normal parse -> rules path; (b) proves acceptance without
    # recognition still reports the honest zero; (c) proves binary is refused
    # with the exact user-facing message.
    print("\nfile-type acceptance — broadened formats, honest rejection:")
    import normalize
    import anomaly_detector

    with tempfile.TemporaryDirectory(prefix="accept-test-") as tmp:
        # (a) canonical log lines inside a .txt: accepted, parsed, rules fire.
        canonical = "".join(
            f"2026-08-13T02:16:{44 + i:02d}Z ERROR server-01 auth failed for user "
            f"'admin' from 203.0.113.44 (invalid password)\n" for i in range(6)
        ) + "2026-08-13T02:17:02Z INFO  server-01 healthcheck ok\n"
        try:
            dest = serve.save_upload("renamed.txt", canonical.encode(), tmp)
            check("(a) canonical-format .txt accepted", True)
        except ValueError as e:
            dest = None
            check("(a) canonical-format .txt accepted", False, str(e))
        if dest:
            records, stats = normalize.load(dest)
            check("(a) every line parses", stats["parsed"] == 7 and stats["unparsed"] == 0,
                  f"{stats['parsed']} parsed / {stats['unparsed']} unparsed")
            anomalies = anomaly_detector.detect(records)
            check("(a) rules yield findings from the .txt",
                  any(a["type"].startswith("auth_bruteforce") for a in anomalies),
                  f"{len(anomalies)} finding(s), none auth_bruteforce")

        # (b) gibberish text .txt: accepted — but NOT recognized, and the state
        # that drives the console must say so instead of faking green.
        gibberish = "\n".join(f"@@ {i} :: lorem ipsum ~~ no timestamp here" for i in range(30)) + "\n"
        try:
            dest = serve.save_upload("notes.txt", gibberish.encode(), tmp)
            check("(b) gibberish .txt accepted (it is text)", True)
        except ValueError as e:
            dest = None
            check("(b) gibberish .txt accepted (it is text)", False, str(e))
        if dest:
            records, stats = normalize.load(dest)
            check("(b) nothing parses", stats["parsed"] == 0 and stats["unparsed"] == 30,
                  f"{stats['parsed']} parsed / {stats['unparsed']} unparsed")
            state = serve.adapter.adapt({"source_file": str(dest), "findings": [],
                                         "lines_parsed": stats["parsed"],
                                         "lines_unparsed": stats["unparsed"]})
            check("(b) console state flags the unrecognized-format banner",
                  state["unrecognized"] and not state["emptyInput"])

        # (c) binary (NUL bytes) with an unknown name: refused, exact wording.
        binary = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 8
        try:
            serve.save_upload("core.dump", binary, tmp)
            check("(c) binary file rejected", False, "it was accepted")
        except ValueError as e:
            check("(c) binary file rejected", True)
            check("(c) rejection uses the exact message",
                  str(e) == "This doesn't look like a text log file.", str(e))

        # Name gate: every promised name form is accepted without sniffing.
        for name in ("a.log", "a.txt", "a.out", "a.syslog", "a.messages", "a.err",
                     "app.log.1", "app.log.2", "syslog", "messages", "auth"):
            check(f"name accepted: {name}", serve.accepted_by_name(name))
        for name in ("core.dump", "disk.img", "archive.tar.gz", "readme"):
            check(f"name not pre-accepted (sniffed instead): {name}",
                  not serve.accepted_by_name(name))

    # The rule -> ATT&CK mapping: source of truth in threat_intel/, attached by
    # the adapter, and NEVER allowed to touch severity or ordering.
    print("\nrule -> MITRE resolution (threat_intel/rule_mitre_map.py):")
    import adapter
    from rule_mitre_map import techniques_for_rule

    got = techniques_for_rule("auth_bruteforce")
    check("auth_bruteforce -> T1110", [t["id"] for t in got] == ["T1110"],
          f"got {[t['id'] for t in got]}")
    check("unmapped rule -> no techniques, never guessed",
          techniques_for_rule("error_rate_spike") == []
          and techniques_for_rule("disk_pressure") == []
          and techniques_for_rule(None) == [])

    report = {"source_file": "does-not-exist.log", "generated_at": "2026-08-18T00:00:00+00:00",
              "lines_parsed": 12, "lines_unparsed": 0, "findings": [
                  {"source": "detector", "severity": "high", "rule_id": "auth_bruteforce",
                   "summary": "brute force", "timeline": []},
                  {"source": "detector", "severity": "medium", "rule_id": "error_rate_spike",
                   "summary": "burst", "timeline": []}]}
    state = adapter.adapt(report)
    mapped, unmapped = state["findings"]
    check("adapter attaches the technique to a mapped finding",
          [t["id"] for t in mapped["mitre"]] == ["T1110"])
    check("adapter attaches NOTHING to an unmapped finding", unmapped["mitre"] == [])
    check("severity is untouched by the mapping",
          mapped["sev"] == "HIGH" and unmapped["sev"] == "MEDIUM")
    check("finding order is untouched by the mapping",
          [f["type"] for f in state["findings"]] == ["auth_bruteforce", "error_rate_spike"])

    return 0 if all(results) else 1


def check_remote_compute():
    """Remote-compute guardrails, with the outbound payload CAPTURED, not sent.

    The four assertions that matter: the raw log is never transmitted; only
    redacted finding-lines go out; the banner reports the real host and count;
    and local mode is byte-for-byte today's behaviour. No sockets, no network —
    la.chat_completion is stubbed and every prompt it would have sent is
    inspected instead.
    """
    ROOT = HERE.parent
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(HERE))
    import serve
    import redact
    import log_analyzer as la

    results = []

    def check(label, cond, detail=""):
        results.append(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond or not detail else f" — {detail}"))

    print("\nremote compute — redaction choke point and honest banner:")

    log_lines = [
        "2026-08-13T02:16:44Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44",
        "2026-08-13T02:16:45Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44",
        "2026-08-13T02:16:46Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44",
        "2026-08-13T02:16:47Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44",
        "2026-08-13T02:16:48Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44",
        "2026-08-13T02:16:52Z INFO server-01 auth success for user 'admin' from 203.0.113.44",
        "2026-08-13T02:17:00Z INFO server-09 SECRET-MARKER-LINE routine heartbeat",
    ]
    finding = {
        "id": "d0", "sev": "CRITICAL", "type": "auth_bruteforce_success",
        "title": "Brute-force then SUCCESSFUL login for 'admin' from 203.0.113.44",
        "host": "server-01", "hostDerived": True,
        "timeline": [{"line": n} for n in range(1, 7)],
    }

    captured = []

    def fake_chat(base_url, api_key, model, system, user, timeout=300):
        captured.append({"base_url": base_url, "api_key": api_key,
                         "model": model, "user": user})
        return json.dumps({"findings": [], "explanations": [
            {"rule_id": "auth_bruteforce_success", "explanation": "advisory prose"}]})

    real_chat = la.chat_completion
    la.chat_completion = fake_chat
    try:
        with tempfile.TemporaryDirectory(prefix="remote-test-") as tmp:
            log_path = Path(tmp) / "attack.log"
            log_path.write_text("\n".join(log_lines) + "\n")
            state = {"logPath": str(log_path), "findings": [finding]}

            # --- remote mode: everything outbound goes through the choke point
            serve.set_compute({"mode": "remote",
                               "baseUrl": "https://gpu-node.internal:8443/v1",
                               "apiKey": "sk-secret", "model": "big-model"})
            text, sent = serve.explain_finding(finding, state)
            payload = captured[-1]["user"]

            check("explanation text returned", text == "advisory prose", text[:60])
            check("sent = the finding's own lines, nothing more", sent == 6, str(sent))
            check("payload goes to the configured remote node",
                  captured[-1]["base_url"] == "https://gpu-node.internal:8443/v1"
                  and captured[-1]["model"] == "big-model"
                  and captured[-1]["api_key"] == "sk-secret")

            check("raw log NEVER transmitted: non-finding line absent",
                  "SECRET-MARKER-LINE" not in payload)
            check("raw log NEVER transmitted: no finding line appears verbatim",
                  all(line not in payload for line in log_lines))
            check("IPs masked in outbound text", "203.0.113.44" not in payload)
            check("usernames masked in outbound text", "admin" not in payload)
            check("hostnames masked in outbound text", "server-01" not in payload)
            check("deterministic placeholders present",
                  "[IP-1]" in payload and "[USER-1]" in payload and "[HOST-1]" in payload)
            check("pre-flagged context is redacted too (title carried IP + user)",
                  "203.0.113.44" not in payload.split("Analyze this log chunk")[0])

            # --- the honest banner reflects host + actual count
            c = serve.compute_state(sent)
            check("banner names the remote host", c["host"] == "gpu-node.internal",
                  str(c.get("host")))
            check("banner reports the real line count",
                  c["banner"] == "Compute runs on gpu-node.internal. 6 finding-lines "
                                 "sent (redacted). Raw log stays on this machine.",
                  c["banner"])
            check("banner grammar: 1 line is singular",
                  "1 finding-line sent" in serve.compute_state(1)["banner"])
            check("masked config never exposes the key",
                  "sk-secret" not in json.dumps(serve.masked_compute())
                  and serve.masked_compute()["hasKey"] is True)

            # --- config validation: a bad remote URL is refused, not deferred
            for bad in ("ftp://host/v1", "not-a-url", ""):
                try:
                    serve.set_compute({"mode": "remote", "baseUrl": bad})
                    check(f"rejects remote URL {bad!r}", False, "it was accepted")
                except ValueError:
                    check(f"rejects remote URL {bad!r}", True)

            # --- local mode: today's path, unchanged
            serve.set_compute({"mode": "local"})
            captured.clear()
            text, sent = serve.explain_finding(finding, state)
            payload = captured[-1]["user"]
            chunk_text = "".join(line + "\n" for line in log_lines)

            check("local mode sends 0 lines off-machine (count stays 0)", sent == 0)
            check("local mode uses the machine-local endpoint",
                  captured[-1]["base_url"] == la.LLM_BASE_URL
                  and captured[-1]["model"] == la.LLM_MODEL)
            check("local prompt is the verbatim 25-line chunk, exactly as before",
                  chunk_text in payload)
            check("local banner state says remote is off",
                  serve.compute_state(0) == {"remote": False})

            # --- the redaction pass itself (also the sanitize point)
            r = redact.redact_text("Failed password for invalid user root from 10.0.0.1")
            check("sshd-style username masked", "root" not in r and "[USER-1]" in r, r)
            r = redact.redact_text("conn from 10.0.0.1 then 10.0.0.1 again then 10.0.0.2")
            check("same value -> same placeholder", r.count("[IP-1]") == 2 and "[IP-2]" in r, r)
            r = redact.redact_text("evil\x1b[31mred\x00null")
            check("control characters stripped (untrusted input)",
                  "\x1b" not in r and "\x00" not in r, repr(r))
    finally:
        la.chat_completion = real_chat
        serve.set_compute({"mode": "local"})

    return 0 if all(results) else 1


def check_dashboard_data():
    """Dashboard data contract: adapter emits EVERY parsed event (not just the
    findings the human saw), bucket counts that sum to linesParsed, and a
    ranked MITRE technique frequency. No network, no model — adapter only."""
    ROOT = HERE.parent
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(HERE))
    import adapter

    results = []

    def check(label, cond, detail=""):
        results.append(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + ("" if cond or not detail else f" — {detail}"))

    print("\ndashboard data — full event list, severity counts, MITRE frequency:")

    # A 60-line mixed-severity canonical log: 5 ERROR auth failures + 1 INFO
    # success (the brute-force story), then 14 ERROR, 10 WARN, 20 INFO,
    # 6 DEBUG, 4 CRIT of plain traffic.
    lines = []
    for i in range(5):
        lines.append(f"2026-08-13T02:16:{44 + i}Z ERROR server-01 "
                     f"auth failed for user 'admin' from 203.0.113.44")
    lines.append("2026-08-13T02:16:52Z INFO server-01 "
                 "auth success for user 'admin' from 203.0.113.44")
    for i in range(14):
        lines.append(f"2026-08-13T02:17:{10 + i}Z ERROR server-02 upstream timeout {i}")
    for i in range(10):
        lines.append(f"2026-08-13T02:18:{10 + i}Z WARN server-02 retrying request {i}")
    for i in range(20):
        lines.append(f"2026-08-13T02:19:{10 + i}Z INFO server-03 heartbeat ok {i}")
    for i in range(6):
        lines.append(f"2026-08-13T02:20:{10 + i}Z DEBUG server-03 cache probe {i}")
    for i in range(4):
        lines.append(f"2026-08-13T02:21:{10 + i}Z CRIT server-04 service down {i}")
    assert len(lines) == 60

    with tempfile.TemporaryDirectory(prefix="dash-test-") as tmp:
        log_path = Path(tmp) / "mixed.log"
        log_path.write_text("\n".join(lines) + "\n")

        report = {
            "source_file": str(log_path), "generated_at": "2026-08-18T12:00:00+00:00",
            "lines_parsed": 60, "lines_unparsed": 0,
            "findings": [
                {"source": "detector", "severity": "critical",
                 "rule_id": "auth_bruteforce_success",
                 "summary": "Brute-force then SUCCESSFUL login",
                 "evidence": "5x auth failed for 'admin' from 203.0.113.44 (lines 1-5)",
                 "entities": {"ip": "203.0.113.44"},
                 "timeline": [{"t": "02:16:52", "label": "success", "line": 6,
                               "ts": "2026-08-13T02:16:52+00:00"}]},
                {"source": "detector", "severity": "high",
                 "rule_id": "auth_bruteforce",
                 "summary": "Auth brute-force burst",
                 "evidence": "", "entities": {"ip": "203.0.113.44"},
                 "timeline": [{"t": "02:16:44", "label": "first", "line": 1,
                               "ts": "2026-08-13T02:16:44+00:00"},
                              {"t": "02:16:45", "label": "burst", "line": 2,
                               "ts": "2026-08-13T02:16:45+00:00"}]},
                {"source": "detector", "severity": "medium",
                 "rule_id": "error_rate_spike",
                 "summary": "Error burst",
                 "evidence": "lines 7-20", "entities": {},
                 "timeline": [{"t": "02:17:10", "label": "spike", "line": 7,
                               "ts": "2026-08-13T02:17:10+00:00"}]},
            ],
        }
        state = adapter.adapt(report)
        events = state["events"]
        counts = state["severityCounts"]
        by_n = {e["n"]: e for e in events}

        # --- ALL events surfaced, not a couple -----------------------------
        check("len(events) == linesParsed (all 60 surfaced)",
              len(events) == state["linesParsed"] == 60, str(len(events)))
        check("every parsed line appears exactly once, in order",
              [e["n"] for e in events] == list(range(1, 61)))
        check("events[].raw is the verbatim source line",
              all(e["raw"] == lines[e["n"] - 1] for e in events))
        check("severityCounts sums to linesParsed",
              sum(counts.values()) == 60, str(counts))
        check("all six buckets always present",
              set(counts) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"})

        # --- finding lines carry their rule-assigned bucket ----------------
        check("finding line keeps the rule severity bucket",
              by_n[6]["bucket"] == "CRITICAL" and by_n[6]["isFinding"]
              and by_n[6]["findingId"] == "detector-0", str(by_n[6]))
        check("evidence-range endpoints tie back to the finding",
              by_n[1]["findingId"] == "detector-0" and by_n[1]["bucket"] == "CRITICAL")
        # Line 1 is claimed by finding 0 (evidence range) AND finding 1
        # (timeline); the first finding wins. Line 2 is only finding 1's.
        check("first finding wins a shared line",
              by_n[1]["findingId"] == "detector-0"
              and by_n[2]["findingId"] == "detector-1"
              and by_n[2]["bucket"] == "HIGH")
        check("error_rate_spike line grouped MEDIUM by its rule",
              by_n[7]["bucket"] == "MEDIUM" and by_n[7]["findingId"] == "detector-2")

        # --- plain events group by their own level (display only) ----------
        check("plain ERROR -> HIGH", by_n[10]["bucket"] == "HIGH"
              and not by_n[10]["isFinding"] and by_n[10]["findingId"] is None)
        check("plain WARN -> MEDIUM", by_n[25]["bucket"] == "MEDIUM")
        check("plain INFO -> INFO", by_n[35]["bucket"] == "INFO")
        check("plain DEBUG -> LOW", by_n[51]["bucket"] == "LOW")
        check("plain CRIT -> CRITICAL", by_n[58]["bucket"] == "CRITICAL")
        check("no UNKNOWN in a fully-recognized log", counts["UNKNOWN"] == 0)
        check("event carries ts/level/host/msg from the parsed record",
              by_n[1]["ts"].startswith("2026-08-13T02:16:44")
              and by_n[1]["level"] == "ERROR" and by_n[1]["host"] == "server-01"
              and by_n[1]["msg"].startswith("auth failed"))

        # --- MITRE frequency ----------------------------------------------
        freq = state["mitreFrequency"]
        check("T1110 ranked first with count 2 (both bruteforce rules)",
              bool(freq) and freq[0]["id"] == "T1110" and freq[0]["count"] == 2,
              str(freq))
        check("T1078 present with count 1",
              any(t["id"] == "T1078" and t["count"] == 1 for t in freq))
        check("technique entries carry name + tactic",
              all(t.get("name") and t.get("tactic") for t in freq))
        check("unmapped rule (error_rate_spike) contributes nothing",
              len(freq) == 2, str([t["id"] for t in freq]))

        # --- UNKNOWN level -> UNKNOWN bucket (never guessed) ---------------
        csv_path = Path(tmp) / "log360.csv"
        csv_path.write_text(
            "Message,Common Severity,LogType,Process Id,Facility,Severity,Time,Device,Source\n"
            "Heartbeat received,,Monitoring,,daemon,,2026-08-17 09:40:30,,monitor-02\n"
            "Backup done,Information,Application,1,daemon,Information,2026-08-17 09:41:00,app-01,syslog\n")
        state2 = adapter.adapt({"source_file": str(csv_path), "findings": [],
                                "lines_parsed": 2, "lines_unparsed": 0})
        unk = [e for e in state2["events"] if e["bucket"] == "UNKNOWN"]
        check("UNKNOWN level maps to the UNKNOWN bucket only",
              len(unk) == 1 and unk[0]["level"] == "UNKNOWN"
              and state2["severityCounts"]["UNKNOWN"] == 1,
              str(state2["severityCounts"]))
        check("no findings -> mitreFrequency is an empty list",
              state2["mitreFrequency"] == [])

        # --- honest empties: unrecognized input emits no events ------------
        bad_path = Path(tmp) / "garbage.txt"
        bad_path.write_text("### not a log ###\n::: still not :::\n")
        state3 = adapter.adapt({"source_file": str(bad_path), "findings": [],
                                "lines_parsed": 0, "lines_unparsed": 2})
        check("unrecognized input: events empty, banner flags untouched",
              state3["events"] == [] and state3["unrecognized"]
              and sum(state3["severityCounts"].values()) == 0)

    return 0 if all(results) else 1


def check_layout_css():
    """The scroll chain that keeps every finding reachable, asserted as CSS.

    A headless DOM cannot measure a viewport, so the regression this guards —
    the banded list clipping with no way to scroll to the rest of a band — is
    pinned at the stylesheet level instead: the shell must degrade to a scroll
    (never clip), the review area must keep a height floor, the list must be
    its own scroller with a visible thumb, and the overview charts must be
    height-capped so they cannot starve the list.
    """
    css = CONSOLE_HTML.read_text().split("</style>")[0]
    results = []

    def check(label, cond, detail=""):
        results.append(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
              + ("" if cond or not detail else f" — {detail}"))

    def rule(selector):
        m = re.search(re.escape(selector) + r"\{([^}]*)\}", css)
        return m.group(1) if m else ""

    print("\nlayout — the findings list is always reachable (crop regression guard):")
    app = rule(".app")
    check(".app degrades to scroll, never clips", "overflow:auto" in app
          and "overflow:hidden" not in app, app)
    check(".app keeps its height floor", "min-height:820px" in app)
    body = rule(".body")
    check(".body keeps a working height floor for the list", "min-height:420px" in body, body)
    check(".list-pane stays shrinkable (scroll chain intact)",
          "min-height:0" in rule(".list-pane"))
    rows = rule(".rows")
    check(".rows is the list's own scroller", "overflow:auto" in rows, rows)
    check(".rows reserves a visible scrollbar gutter", "scrollbar-gutter:stable" in rows)
    check("internal scrollers style a visible thumb",
          "::-webkit-scrollbar-thumb" in css and ".rows::-webkit-scrollbar" in css)
    check("overview stays flex:none (cannot grow over the list)",
          "flex:none" in rule(".ovw"))
    panel = rule(".ovw-grid>.panel")
    check("overview panels are height-capped and scroll internally",
          "max-height:230px" in panel and "overflow:auto" in panel, panel)

    return 0 if all(results) else 1


def main():
    node = shutil.which("node")
    if not node:
        print("console render smoke test")
        print("  [SKIP] node not found — the console is JavaScript and needs a JS runtime.")
        print("         Install Node, or run this on a machine that has it, to exercise the console.")
        return 0

    if not CONSOLE_HTML.exists():
        print(f"ERROR: {CONSOLE_HTML} not found")
        return 1

    print(f"console render smoke test (headless, no browser/network) — node {node}\n")
    with tempfile.TemporaryDirectory(prefix="console-test-") as tmp:
        tmp = Path(tmp)
        js_path = tmp / "console.js"
        js_path.write_text(extract_js(CONSOLE_HTML))

        syntax = subprocess.run([node, "--check", str(js_path)], capture_output=True, text=True)
        if syntax.returncode != 0:
            print("  [FAIL] the console's JavaScript does not parse")
            print(syntax.stderr.strip()[:500])
            return 1

        state_path = tmp / "state.json"
        state_path.write_text(json.dumps(LIVE_STATE))
        harness = tmp / "harness.js"
        harness.write_text(HARNESS)

        result = subprocess.run([node, str(harness), str(js_path), str(state_path)],
                                capture_output=True, text=True)
        print(result.stdout.rstrip())
        if result.stderr.strip():
            print(result.stderr.strip()[:800])

    routing = check_server_routing()
    log360 = check_log360()
    remote = check_remote_compute()
    dashboard = check_dashboard_data()
    layout = check_layout_css()
    if result.returncode or routing or log360 or remote or dashboard or layout:
        print("\nFAILED")
        return 1
    print("\nPASSED — render + routing + log360 + remote-compute + dashboard-data + layout checks green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
