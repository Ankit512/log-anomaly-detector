#!/usr/bin/env python3
"""
test_overview.py — headless render smoke test for the SOC Overview page.

Same posture as test_console.py: the page's own JS is extracted from
overview.html and executed against a stubbed DOM, and the assertions read what
actually lands on the page. No browser, no network, no backend — state is
injected as window.OVERVIEW_DATA in the exact /api/overview contract shape.

The honest states matter most: a missing prior period shows NO delta, empty
data says so instead of drawing fake charts, unbuilt nav items say "coming
soon" instead of linking to nothing, and mock data is always labeled as such.

Usage:
  python3 console/test_overview.py
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OVERVIEW_HTML = HERE / "overview.html"

# A full state in the /api/overview contract shape, WITH deltas on two KPIs so
# both the shown-delta and the no-prior-period cases are exercised at once.
DATA = {
    "generatedAt": "2026-08-18T14:00:00Z",
    "timeWindowLabel": "Last 24 Hours",
    "kpis": {
        "total": 31, "critical": 3, "high": 22, "medium": 5, "low": 1,
        "deltas": {"total": {"pct": 12, "dir": "up"},
                   "critical": {"pct": 40, "dir": "down"},
                   "high": None, "medium": None, "low": None},
    },
    "severityDonut": [
        {"bucket": "CRITICAL", "count": 3, "pct": 10},
        {"bucket": "HIGH", "count": 22, "pct": 71},
        {"bucket": "MEDIUM", "count": 5, "pct": 16},
        {"bucket": "LOW", "count": 1, "pct": 3},
    ],
    "alertsOverTime": {"bins": [
        {"t": "2026-08-18T10:00:00Z", "critical": 1, "high": 3, "medium": 0, "low": 0},
        {"t": "2026-08-18T11:00:00Z", "critical": 0, "high": 9, "medium": 2, "low": 1},
        {"t": "2026-08-18T12:00:00Z", "critical": 2, "high": 10, "medium": 3, "low": 0},
    ]},
    "mitreTactics": [
        {"tactic": "Credential Access", "count": 23},
        {"tactic": "Initial Access", "count": 4},
        {"tactic": "Command and Control", "count": 2},
    ],
    "latestAlerts": [
        {"id": "detector-0", "time": "2026-08-18 12:41:07", "severity": "CRITICAL",
         "attackerStatus": "Breaking In", "tactics": ["Credential Access"],
         "name": "Brute-force then SUCCESSFUL login for 'admin'",
         "source": "auth.log"},
        {"id": "detector-1", "time": "2026-08-18 12:39:55", "severity": "HIGH",
         "attackerStatus": "Damaging / Stealing", "tactics": ["Command and Control"],
         "name": "Outbound to 45.153.160.2:4444 (blocked)", "source": "fw.log"},
    ],
    "ingestion": {"acceptedLabel": "LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text",
                  "files": [{"name": "auth.log", "ok": True},
                            {"name": "fw.log", "ok": True}]},
    "model": "llama3.1:8b",
}

HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const js = fs.readFileSync(process.argv[2], "utf8");
const DATA = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));

let fails = 0;
const check = (label, cond, detail) => {
  if (!cond) fails++;
  console.log(`  [${cond ? "PASS" : "FAIL"}] ${label}${!cond && detail ? " — " + detail : ""}`);
};
const clone = (o) => JSON.parse(JSON.stringify(o));

function run(overviewData) {
  let html = "";
  const stub = { set innerHTML(v) { html = v; }, get innerHTML() { return html; },
                 value: "", click: () => {}, classList: { add: () => {}, remove: () => {} },
                 scrollTo: () => {} };
  const ctx = {
    document: { getElementById: () => stub, addEventListener: () => {},
                activeElement: { tagName: "BODY" } },
    window: {}, navigator: {},
    fetch: () => Promise.reject(new Error("no backend")),
    console,
  };
  if (overviewData) ctx.window.OVERVIEW_DATA = overviewData;
  vm.createContext(ctx);
  vm.runInContext(js, ctx);
  return html;
}

console.log("1. layout renders from injected contract data:");
let h = run(DATA);
check("renders substantial markup", h.length > 4000, h.length + " chars");
check("title + subtitle", h.includes("SOC Dashboard") && h.includes("Security Overview"));
check("time-window dropdown shows the label", h.includes("Last 24 Hours"));
check("Refresh present", h.includes('data-act="refresh"'));
check("Filters present but honestly disabled",
      /disabled title="Filtering is not built yet"/.test(h));
check("no sample-data banner when real data is injected", !h.includes("Sample data"));

console.log("\n2. sidebar — nav honesty and ingestion:");
check("Overview marked active", /nav-i on"[^>]*>[\s\S]{0,500}?Overview/.test(h));
check("Alerts links to the existing console", h.includes('href="/alerts"'));
for (const item of ["Incidents", "Threat Intel", "Assets", "Reports", "Cases"]) {
  check(`${item} rendered but marked coming soon`,
        new RegExp(`soon"[^>]*disabled[^>]*>[\\s\\S]{0,400}${item}`).test(h)
        || (h.includes(item) && h.includes("coming soon")));
}
check("no unbuilt item links anywhere", (h.match(/href="/g) || []).length
      === (h.match(/href="\/alerts/g) || []).length + (h.match(/href="#"/g) || []).length);
check("upload dropzone present", h.includes("Upload Logs")
      && h.includes("Drag &amp; drop or select files"));
check("accepted formats listed", h.includes("LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text"));
check("Browse Files button", h.includes("Browse Files"));
check("ingested files listed with a check", h.includes("auth.log") && h.includes(">✓<"));
check("Clear All offered", h.includes("Clear All"));

console.log("\n3. KPI cards — deltas only when a prior period exists:");
check("all five KPI labels", ["Total Alerts", "Critical", "High", "Medium", "Low"]
      .every((k) => h.includes(k)));
check("counts rendered", h.includes(">31<") && h.includes(">22<") && h.includes(">3<"));
check("delta shown where a prior period exists",
      h.includes("12% vs previous") && h.includes("40% vs previous"));
check("up-delta reads as worse, down as better",
      /worse">\s*▲ 12%/.test(h) && /better">\s*▼ 40%/.test(h));
check("EXACTLY the two non-null deltas render (null -> nothing, never faked)",
      (h.match(/vs previous/g) || []).length === 2,
      (h.match(/vs previous/g) || []).length + " deltas");

console.log("\n4. charts — SVG, offline, numbers always as text:");
check("donut SVG with center total", h.includes("chart-donut") && h.includes(">31</text>"));
check("donut legend carries count AND percent",
      /CRITICAL <span>10%<\/span><b>3<\/b>/.test(h));
check("over-time stacked SVG present", h.includes("chart-overtime"));
// 3 bins with 2,3,3 nonzero severity segments = 8 rects
check("over-time draws one rect per nonzero segment",
      (h.match(/chart-overtime[\s\S]*?<\/svg>/)[0].match(/<rect/g) || []).length === 8);
check("over-time axis labeled with bin times", h.includes("10:00") && h.includes("12:00"));
check("over-time has a severity legend", h.includes("legend-row"));
check("tactics ranked descending",
      h.indexOf("Credential Access") < h.indexOf("Initial Access")
      && h.indexOf("Initial Access") < h.indexOf("Command and Control"));
check("one tactic bar per tactic", (h.match(/chart-tactic/g) || []).length === 3);
check("tactic counts as text", h.includes("<b>23</b>") && h.includes("<b>4</b>"));
check("tactics labeled as derived, not verdicts", h.includes("derived tags — not verdicts"));

console.log("\n5. latest alerts table:");
check("all columns present", ["Time", "Severity", "Attacker Status",
      "Primary MITRE Tactics", "Alert", "Source", "Action"].every((c) => h.includes(c)));
check("severity badge colored + labeled",
      /badge" style="background:#991b1b">CRITICAL/.test(h));
check("attacker status rendered as given", h.includes("Damaging / Stealing"));
check("attacker status explained as display grouping",
      h.includes("display aid, not a verdict"));
check("tactic chips in rows", h.includes('class="tac"'));
check("rows drill into the Alerts console", /<a href="\/alerts\?sel=[^"]*"\s+title="Open in the Alerts console, focused on this finding">View<\/a>/.test(h));

console.log("\n6. AI analyst panel:");
check("panel present with local framing", h.includes("AI Analyst")
      && h.includes("Ollama"));
check("advisory-only statement", h.includes("never changed here"));
check("highlighted quick action", h.includes("Show me the top 5 critical alerts"));
check("input + send", h.includes("Ask anything about your logs...")
      && h.includes('data-act="ask"'));
check("model footer", h.includes("Model: llama3.1:8b"));

console.log("\n7. HONESTY — omitted ops metrics and empty data:");
check("ops metrics strip is a labeled placeholder",
      h.includes("Operational metrics — coming soon"));
check("no invented MTTD/MTTR numbers",
      !/MTTD[^<]*\d/.test(h) && !/MTTR[^<]*\d/.test(h));

const empty = clone(DATA);
empty.kpis = { total: 0, critical: 0, high: 0, medium: 0, low: 0,
               deltas: { total: null, critical: null, high: null, medium: null, low: null } };
empty.severityDonut = []; empty.alertsOverTime = { bins: [] };
empty.mitreTactics = []; empty.latestAlerts = [];
const eh = run(empty);
check("empty run: honest empty states, no fake charts",
      (eh.match(/No alerts in this window/g) || []).length >= 3
      && !eh.includes("chart-donut") && !eh.includes("chart-overtime"));
check("empty run: no tactic bars invented", !eh.includes("chart-tactic")
      && eh.includes("No tactic data"));
check("empty run: zero deltas shown", !eh.includes("vs previous"));
check("empty run: KPIs honestly zero", eh.includes(">0<"));

console.log("\n8. mock fallback is labeled, never passed off as real:");
const mh = run(null);                       // no injected data, fetch fails -> mock
check("renders from the built-in mock", mh.length > 4000);
check("sample-data banner shown", mh.includes("Sample data"));

console.log(`\n${fails ? "FAILED — " + fails + " check(s)" : "PASSED — all checks green"}`);
process.exit(fails ? 1 : 0);
"""


def extract_js(html_path):
    src = html_path.read_text()
    m = re.search(r"<script>\n(.*?)\n</script>", src, re.S)
    if not m:
        print("ERROR: could not find the overview's <script> block")
        sys.exit(1)
    return m.group(1)


def check_static_html():
    """Checks on the file itself: light theme tokens, fully offline."""
    src = OVERVIEW_HTML.read_text()
    results = []

    def check(label, cond, detail=""):
        results.append(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
              + ("" if cond or not detail else f" — {detail}"))

    print("\nstatic checks — light theme, self-contained:")
    check("light background token", "--bg:#f4f5f8" in src)
    check("white cards", "--card:#ffffff" in src)
    check("validated severity palette",
          all(c in src for c in ("#991b1b", "#ea580c", "#caa204", "#166534")))
    check("no external scripts/styles/fonts (offline by construction)",
          "http://" not in src and "https://" not in src
          and "<link" not in src and 'src="' not in src.split("<script>")[0])
    check("charts are inline SVG only", "<canvas" not in src)
    return 0 if all(results) else 1


def main():
    node = shutil.which("node")
    if not node:
        print("overview render smoke test")
        print("  [SKIP] node not found — needs a JS runtime.")
        return 0
    if not OVERVIEW_HTML.exists():
        print(f"ERROR: {OVERVIEW_HTML} not found")
        return 1

    print(f"SOC overview render smoke test (headless, no browser/network) — node {node}\n")
    with tempfile.TemporaryDirectory(prefix="overview-test-") as tmp:
        tmp = Path(tmp)
        js_path = tmp / "overview.js"
        js_path.write_text(extract_js(OVERVIEW_HTML))

        syntax = subprocess.run([node, "--check", str(js_path)],
                                capture_output=True, text=True)
        if syntax.returncode != 0:
            print("  [FAIL] the overview's JavaScript does not parse")
            print(syntax.stderr.strip()[:500])
            return 1

        data_path = tmp / "data.json"
        data_path.write_text(json.dumps(DATA))
        harness = tmp / "harness.js"
        harness.write_text(HARNESS)
        result = subprocess.run([node, str(harness), str(js_path), str(data_path)],
                                capture_output=True, text=True)
        print(result.stdout.rstrip())
        if result.stderr.strip():
            print(result.stderr.strip()[:800])

    static = check_static_html()
    if result.returncode or static:
        print("\nFAILED")
        return 1
    print("\nPASSED — overview render + static checks green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
