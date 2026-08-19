import { screen, waitFor } from "@testing-library/react";
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

describe("run switching via the header dropdown", () => {
  it("lists saved runs and switches via POST /api/open", async () => {
    const open = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }) as Response);
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS, "/api/runs": RUNS,
    });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) =>
      String(u).includes("/api/open") ? open() : realFetch(u, init)));

    renderApp(<App />);
    await screen.findByText("Total Alerts");

    const select = await screen.findByRole("combobox", { name: "Select run" });
    // The dropdown is the run selector: the current run is selected, both runs listed.
    expect((select as HTMLSelectElement).value).toBe("20260818-run-b.json");
    expect(screen.getByRole("option", { name: /auth\.log/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Linux_2k\.log/ })).toBeInTheDocument();

    // Selecting the other run opens it.
    await userEvent.selectOptions(select, "20260817-run-a.json");
    await waitFor(() => expect(open).toHaveBeenCalledTimes(1));
  });

  it("shows an honest label when there are no saved runs", async () => {
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS,
      "/api/runs": { current: null, runs: [] },
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    expect(await screen.findByText("No runs yet")).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Select run" })).not.toBeInTheDocument();
  });
});
