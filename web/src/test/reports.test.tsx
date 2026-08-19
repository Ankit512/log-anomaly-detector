import { screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";

describe("Reports page", () => {
  it("lists real saved reports from disk", async () => {
    mockFetch({ "/api/reports": { reports: [
      { name: "attack-2026-08-18-20260818T190301Z.html", bytes: 48213, createdAt: "2026-08-18T19:03:01+00:00" },
    ] } });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByText(/Saved reports \(1\)/)).toBeInTheDocument();
    expect(screen.getByTestId("report-row")).toBeInTheDocument();
    expect(screen.getByText(/attack-2026-08-18/)).toBeInTheDocument();
    expect(screen.getByText("47.1 KB")).toBeInTheDocument();
  });

  it("shows an honest empty state with no reports yet", async () => {
    mockFetch({ "/api/reports": { reports: [] } });
    renderApp(<App />, { route: "/reports" });
    expect(await screen.findByText(/No reports generated yet/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate report/ })).toBeInTheDocument();
  });
});
