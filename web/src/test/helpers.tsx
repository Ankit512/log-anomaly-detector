import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";
import type { ConsoleState, Finding, Metrics, OverviewData } from "@/lib/api";

export function renderApp(ui: ReactElement, { route = "/" } = {}) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Route fetch by substring match; anything unrouted 404s. A route value with
 *  `__status` responds with that HTTP status (non-2xx => ok: false). */
export function mockFetch(routes: Record<string, unknown>) {
  vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL) => {
    const u = String(url);
    for (const [k, v] of Object.entries(routes)) {
      if (u.includes(k)) {
        const { __status, ...body } = (v ?? {}) as Record<string, unknown>;
        const status = typeof __status === "number" ? __status : 200;
        return {
          ok: status >= 200 && status < 300, status,
          json: async () => (typeof __status === "number" ? body : v),
        } as Response;
      }
    }
    return { ok: false, status: 404, json: async () => ({}) } as Response;
  }));
}

export const OVERVIEW: OverviewData = {
  generatedAt: "2026-08-18T14:00:00Z",
  timeWindowLabel: "Current run · 02:14–02:20 UTC",
  kpis: {
    total: 31, critical: 3, high: 22, medium: 5, low: 1,
    deltas: { total: { pct: 12, dir: "up" }, critical: null, high: null, medium: null, low: null },
  },
  severityDonut: [
    { bucket: "CRITICAL", count: 3, pct: 10 },
    { bucket: "HIGH", count: 22, pct: 71 },
    { bucket: "MEDIUM", count: 5, pct: 16 },
    { bucket: "LOW", count: 1, pct: 3 },
  ],
  alertsOverTime: { bins: [
    { t: "2026-08-18T10:00:00Z", critical: 1, high: 3, medium: 0, low: 0 },
    { t: "2026-08-18T11:00:00Z", critical: 2, high: 9, medium: 2, low: 1 },
  ] },
  mitreTactics: [
    { tactic: "Credential Access", count: 23 },
    { tactic: "Initial Access", count: 4 },
  ],
  latestAlerts: [{
    id: "detector-0", time: "2026-08-18 12:41:07", severity: "CRITICAL",
    attackerStatus: "Breaking In", tactics: ["Credential Access"],
    name: "Brute-force then SUCCESSFUL login for 'admin'", source: "auth.log",
  }],
  ingestion: { acceptedLabel: "CSV, JSON, TXT, RAW, HTML", files: [{ name: "auth.log", ok: true }] },
  model: "llama3.1:8b",
};

/** /api/metrics as soc.metrics() emits it: incidents exist but none carry
 *  acknowledge/resolve stamps yet, so MTTD/MTTR honestly have no basis. */
export const METRICS: Metrics = {
  openIncidents: 2,
  mttdSeconds: null, mttdBasis: 0,
  mttrSeconds: null, mttrBasis: 0,
  assetsAtRisk: 3, usersAtRisk: 1, dataSources: 4,
};

export function finding(i: number, over: Partial<Finding> = {}): Finding {
  return {
    id: `detector-${i}`, sev: "HIGH", ruleSev: "HIGH", llmSev: null, delta: null,
    prov: "RULE-CAUGHT", type: "auth_bruteforce", host: `server-${i % 4}`,
    hostDerived: true, time: "02:16:52", stamp: "2026-08-13T02:16:52+00:00",
    title: `Brute-force burst #${i} from 203.0.113.${i % 250}`,
    ruleWhy: "Failures then a success.", explanation: "Investigate.",
    predicate: "failures_from(ip) >= 5", ruleRef: "anomaly_detector.py",
    occurrences: 1, mitre: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    chips: [], linesNote: null,
    lines: [{ n: 5 + i, a: "auth failed from ", hit: "203.0.113.44", b: "", crit: false }],
    timeline: [{ t: "02:16:44", label: "First failed login" }],
    ...over,
  };
}

export function consoleState(findings: Finding[], over: Partial<ConsoleState> = {}): ConsoleState {
  return {
    live: true, runId: "test-run", runParsed: "2,000 lines parsed · 0 unparsed",
    linesParsed: 2000, linesUnparsed: 0, unrecognized: false, emptyInput: false,
    findings, ...over,
  };
}
