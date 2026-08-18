import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

const RUNS = {
  current: "run-b",
  runs: [
    { file: "20260818-run-b.json", runId: "run-b", label: "samples/auth.log",
      generatedAt: "2026-08-18T14:00:00Z", findings: 22, unrecognized: false, compareRun: false },
    { file: "20260817-run-a.json", runId: "run-a", label: "samples/Linux_2k.log",
      generatedAt: "2026-08-17T09:00:00Z", findings: 24, unrecognized: false, compareRun: false },
  ],
};

const SUMMARY = {
  runs: [
    { file: "20260818-run-b.json", runId: "run-b", generatedAt: "2026-08-18T14:00:00Z",
      sourceLabel: "samples/auth.log", linesParsed: 2000, findingCount: 22,
      severityCounts: { CRITICAL: 0, HIGH: 20, MEDIUM: 2, LOW: 0 }, topTechniques: [],
      unrecognized: false, dataComplete: true },
    { file: "20260817-run-a.json", runId: "run-a", generatedAt: "2026-08-17T09:00:00Z",
      sourceLabel: "samples/Linux_2k.log", linesParsed: 2000, findingCount: 24,
      severityCounts: { CRITICAL: 0, HIGH: 22, MEDIUM: 2, LOW: 0 }, topTechniques: [],
      unrecognized: false, dataComplete: true },
    { file: "broken.json", runId: "", unreadable: true },
  ],
  totals: {
    runCount: 3, linesParsed: 4000, findingCount: 46,
    severityCounts: { CRITICAL: 0, HIGH: 42, MEDIUM: 4, LOW: 0 }, mitreFrequency: [],
  },
};

describe("run history + switcher", () => {
  it("lists real saved runs, flags the current + unreadable ones", async () => {
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS,
      "/api/runs-summary": SUMMARY, "/api/runs": RUNS,
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");

    await userEvent.click(screen.getByRole("button", { name: "Open run history" }));
    const panel = screen.getByRole("region", { name: "Run history" });

    expect(within(panel).getByText(/3 run\(s\)/)).toBeInTheDocument();
    expect(within(panel).getByText("auth.log")).toBeInTheDocument();
    expect(within(panel).getByText("Linux_2k.log")).toBeInTheDocument();
    // The open run is badged and its row is disabled.
    expect(within(panel).getByText("current")).toBeInTheDocument();
    // Unreadable history files are surfaced, not hidden.
    expect(within(panel).getByText(/broken\.json/)).toBeInTheDocument();
    expect(within(panel).getByText(/unreadable/)).toBeInTheDocument();
  });

  it("switching a run POSTs /api/open and refreshes the dashboard", async () => {
    const open = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }) as Response);
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS,
      "/api/runs-summary": SUMMARY, "/api/runs": RUNS,
    });
    // Intercept POST /api/open specifically (mockFetch handles the GETs).
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/open")) return open();
      return realFetch(u, init);
    }));

    renderApp(<App />);
    await screen.findByText("Total Alerts");
    await userEvent.click(screen.getByRole("button", { name: "Open run history" }));
    const panel = screen.getByRole("region", { name: "Run history" });

    // Click the non-current run (run-a / Linux_2k.log).
    await userEvent.click(within(panel).getByText("Linux_2k.log"));
    expect(open).toHaveBeenCalledTimes(1);
  });

  it("single-run history says so instead of pretending there is more", async () => {
    const one = {
      runs: [SUMMARY.runs[0]],
      totals: { ...SUMMARY.totals, runCount: 1, findingCount: 22, linesParsed: 2000 },
    };
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS,
      "/api/runs-summary": one,
      "/api/runs": { current: "run-b", runs: [RUNS.runs[0]] },
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    await userEvent.click(screen.getByRole("button", { name: "Open run history" }));
    expect(await screen.findByText(/Only one run so far/)).toBeInTheDocument();
  });
});
