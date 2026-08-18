import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

/** The header upload follows /api/progress to the job's real outcome — a
 *  finding count on success, the job's own error on failure — instead of a
 *  fire-and-forget "started". Polling runs at 1.5s, so these tests wait. */
describe("header upload -> /api/analyze -> /api/progress", () => {
  const file = new File(["Jun 14 15:16:01 combo sshd: fail\n"], "server.csv", { type: "text/csv" });

  it("reports the analyzed finding count (and the rules-only note) on success", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/analyze": { status: "running" },
      "/api/progress": {
        status: "done", phase: "done", findings: 24,
        note: "model endpoint unreachable (http://localhost:11434/v1) — rules-only run; verdicts are complete, advisory explanations skipped",
      },
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");

    await userEvent.upload(screen.getByTestId("ingest-file"), file);
    expect(await screen.findByText(/server\.csv analyzed — 24 finding\(s\)/, undefined,
      { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText(/rules-only run; verdicts are complete/)).toBeInTheDocument();
  }, 10000);

  it("surfaces the job's own error instead of pretending it started", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/analyze": { status: "running" },
      "/api/progress": { status: "error", error: "analysis failed: unreadable input" },
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");

    await userEvent.upload(screen.getByTestId("ingest-file"), file);
    expect(await screen.findByText(/Analysis of server\.csv failed: analysis failed: unreadable input/,
      undefined, { timeout: 5000 })).toBeInTheDocument();
  }, 10000);

  it("shows a REAL progress strip (stage + bar) from /api/progress, then done", async () => {
    // The poll answer advances across calls: running@2/5 -> running@5/5 -> done.
    let n = 0;
    const steps = [
      { status: "running", phase: "explaining", done: 2, total: 5, findings: 2 },
      { status: "running", phase: "explaining", done: 5, total: 5, findings: 5 },
      { status: "done", phase: "done", findings: 5 },
    ];
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/analyze": { status: "running" },
      "/api/progress": () => steps[Math.min(n++, steps.length - 1)],
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");

    await userEvent.upload(screen.getByTestId("ingest-file"), file);

    // A real progressbar with the backend's own done/total, never a fake bar.
    const bar = await screen.findByRole("progressbar", undefined, { timeout: 5000 });
    expect(bar).toHaveAttribute("aria-valuenow", "40");
    expect(screen.getByText("explaining…")).toBeInTheDocument();

    expect(await screen.findByText(/server\.csv analyzed — 5 finding\(s\)/, undefined,
      { timeout: 5000 })).toBeInTheDocument();
  }, 10000);

  it("shows the server's rejection when the file is not accepted", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/analyze": { __status: 415, error: "This doesn't look like a text log file." },
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");

    await userEvent.upload(screen.getByTestId("ingest-file"), file);
    expect(await screen.findByText(/did not accept server\.csv/)).toBeInTheDocument();
  });
});
