import { screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW } from "./helpers";

describe("Overview page", () => {
  it("renders KPIs, charts, tactics and latest alerts from /api/overview", async () => {
    mockFetch({ "/api/overview": OVERVIEW });
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
  });

  it("shows a delta ONLY where a prior period exists", async () => {
    mockFetch({ "/api/overview": OVERVIEW });
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    expect(screen.getAllByText(/vs previous/).length).toBe(1);
    expect(screen.getByText(/12% vs previous/)).toBeInTheDocument();
  });

  it("keeps the honest surfaces: ops metrics placeholder + advisory AI note", async () => {
    mockFetch({ "/api/overview": OVERVIEW });
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    expect(screen.getByText(/Operational metrics — coming soon/)).toBeInTheDocument();
    expect(screen.getByText(/never changed here/)).toBeInTheDocument();
    expect(screen.getByText("Model: llama3.1:8b")).toBeInTheDocument();
  });

  it("no run yet -> says so, never sample numbers", async () => {
    mockFetch({ "/api/overview": { error: "no run yet — analyze a log first" } });
    renderApp(<App />);
    expect(await screen.findByText(/no run yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId("chart-donut")).not.toBeInTheDocument();
  });
});
