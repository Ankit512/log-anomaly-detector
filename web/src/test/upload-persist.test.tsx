import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { useJobs } from "@/store/jobs";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

const RUNS = {
  current: "run-b",
  runs: [
    { file: "20260818-run-b.json", runId: "run-b", label: "server.csv",
      generatedAt: "2026-08-18T14:00:00Z", findings: 5, unrecognized: false, compareRun: false },
    { file: "20260817-run-a.json", runId: "run-a", label: "samples/Linux_2k.log",
      generatedAt: "2026-08-17T09:00:00Z", findings: 24, unrecognized: false, compareRun: false },
  ],
};

describe("upload runs as a persistent background job", () => {
  beforeEach(() => useJobs.getState()._reset());

  const file = new File(["Jun 14 15:16:01 combo sshd: fail\n"], "server.csv", { type: "text/csv" });

  it("keeps the upload notification visible after navigating to another page", async () => {
    // The progress poll stays 'running' so the job is in flight during the nav.
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS, "/api/runs": RUNS,
      "/api/analyze": { status: "running" },
      "/api/progress": { status: "running", phase: "rules", done: 0, total: 0 },
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");

    await userEvent.upload(screen.getByTestId("ingest-file"), file);

    // The shell-level notifier shows the running job.
    const toast = await screen.findByRole("status", { name: "Upload notification" });
    expect(within(toast).getByText("server.csv")).toBeInTheDocument();

    // Navigate to another page — the notifier (shell-level, store-backed) stays.
    await userEvent.click(screen.getByRole("link", { name: /Incidents/ }));
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Upload notification" })).toBeInTheDocument();
    expect(within(screen.getByRole("status", { name: "Upload notification" }))
      .getByText("server.csv")).toBeInTheDocument();
  }, 10000);

  it("fires a completion notification with click-to-view that opens the run", async () => {
    let progressN = 0;
    const open = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }) as Response);
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS, "/api/runs": RUNS,
      "/api/analyze": { status: "running" },
      "/api/progress": () => (progressN++ === 0
        ? { status: "running", phase: "rules", done: 0, total: 0 }
        : { status: "done", phase: "done", findings: 5 }),
    });
    // Intercept POST /api/open on top of the mocked GETs.
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) =>
      String(u).includes("/api/open") ? open() : realFetch(u, init)));

    renderApp(<App />);
    await screen.findByText("Total Alerts");
    await userEvent.upload(screen.getByTestId("ingest-file"), file);

    const view = await screen.findByRole("button", { name: "View run" }, { timeout: 6000 });
    expect(screen.getByText(/server\.csv analyzed — 5 finding\(s\)/)).toBeInTheDocument();

    await userEvent.click(view);
    await waitFor(() => expect(open).toHaveBeenCalledTimes(1));
  }, 10000);
});
