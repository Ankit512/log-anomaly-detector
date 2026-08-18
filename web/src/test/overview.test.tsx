import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, consoleState, OVERVIEW, METRICS } from "./helpers";

describe("Overview page (v6)", () => {
  beforeEach(() => mockFetch({
    "/api/overview": OVERVIEW,
    "/api/metrics": METRICS,
    "/console_state.json": consoleState([], {
      sourceLabel: "samples/auth.log", runHosts: "combo",
      runWindow: "02:14–02:20 UTC", generatedAt: "2026-08-18 14:00 UTC",
      manifest: { detector_sha256: "43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05", ruleset: "v1" },
    }),
  }));

  it("renders KPIs, charts, tactics and latest alerts from /api/overview", async () => {
    renderApp(<App />);

    expect(await screen.findByText("Total Alerts")).toBeInTheDocument();
    // "31" appears in the KPI card AND the donut center — both are correct.
    expect(screen.getAllByText("31").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("22").length).toBeGreaterThanOrEqual(1);

    expect(screen.getByTestId("chart-donut")).toBeInTheDocument();
    expect(screen.getByTestId("chart-overtime")).toBeInTheDocument();
    expect(screen.getAllByTestId("chart-tactic").length).toBe(2);

    // Ranked descending: Credential Access (23) before Initial Access (4).
    const tactics = screen.getByRole("list", { name: "top attack tactics" });
    expect(tactics.textContent!.indexOf("Credential Access"))
      .toBeLessThan(tactics.textContent!.indexOf("Initial Access"));

    expect(screen.getByText(/Brute-force then SUCCESSFUL/)).toBeInTheDocument();
    expect(screen.getByText("Breaking In")).toBeInTheDocument();
    // The action column deep-links into the Alerts page.
    expect(screen.getByRole("link", { name: "View finding" }))
      .toHaveAttribute("href", "/alerts?sel=detector-0");
  });

  it("shows the run-facts line from the real adapter state", async () => {
    renderApp(<App />);
    expect(await screen.findByText("auth.log")).toBeInTheDocument();
    expect(screen.getByText(/host combo/)).toBeInTheDocument();
    expect(screen.getByText(/2,000 lines parsed · 0 unparsed/)).toBeInTheDocument();
    expect(screen.getByText(/detector 43f0560f…312d05/)).toBeInTheDocument();
  });

  it("shows a real delta ONLY where a prior period exists", async () => {
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    expect(screen.getAllByText(/vs previous/).length).toBe(1);
    expect(screen.getByText(/12% vs previous/)).toBeInTheDocument();
    // The four KPIs without a prior period say so instead of showing nothing.
    expect(screen.getAllByText("no prior run — no delta").length).toBe(4);
  });

  it("wires the ops footer to /api/metrics with honest n/a states", async () => {
    renderApp(<App />);
    await screen.findByText("Open Incidents");
    expect(screen.getByText("Open Incidents").nextElementSibling).toHaveTextContent("2");
    // No acknowledge/resolve lifecycle in the fixture -> n/a, never a number.
    expect(screen.getAllByText("n/a").length).toBe(2);
    expect(screen.getByText("Assets at Risk").nextElementSibling).toHaveTextContent("3");
    expect(screen.getByText("Data Sources").nextElementSibling).toHaveTextContent("4");
    expect(screen.getByText(/derived, never invented/)).toBeInTheDocument();
  });

  it("keeps the AI analyst advisory-only, behind the floating button", async () => {
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    // Closed on first paint so the panel never covers the dashboard.
    expect(screen.queryByText(/never changed here/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Open AI Analyst" }));
    expect(screen.getByText(/never changed here/)).toBeInTheDocument();
    expect(screen.getByText("Model: llama3.1:8b")).toBeInTheDocument();
    expect(screen.getByText("What are the recent attack patterns?")).toBeInTheDocument();
  });

  it("no run yet -> says so, never sample numbers", async () => {
    mockFetch({ "/api/overview": { error: "no run yet — analyze a log first" } });
    renderApp(<App />);
    expect(await screen.findByText(/no run yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId("chart-donut")).not.toBeInTheDocument();
  });
});
