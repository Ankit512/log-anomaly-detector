import { screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { Asset, UserEntity } from "@/lib/api";

const ASSETS: Asset[] = [
  { id: "asset-ip-203.0.113.44", name: "203.0.113.44", kind: "ip", events: 0, findings: 3, atRisk: true, lastSeen: "2026-08-13T02:18:00+00:00" },
  { id: "asset-host-app-01", name: "app-01", kind: "host", events: 143, findings: 0, atRisk: false, lastSeen: null },
];
const USERS: UserEntity[] = [
  { id: "user-admin", name: "admin", events: 6, findings: 1, atRisk: true },
];

describe("Assets page", () => {
  it("renders observed assets and users at risk from real data", async () => {
    mockFetch({ "/api/assets": { assets: ASSETS }, "/api/users": { users: USERS } });
    renderApp(<App />, { route: "/assets" });

    expect(await screen.findByText("203.0.113.44")).toBeInTheDocument();
    expect(screen.getAllByTestId("asset-row").length).toBe(2);
    expect(screen.getByTestId("user-row")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText(/1 of 2 asset\(s\) and 1 of 1 user\(s\) at risk/)).toBeInTheDocument();
  });

  it("shows the honest no-run state when the server is idle", async () => {
    mockFetch({ "/api/assets": { error: "no run yet — analyze a log first" }, "/api/users": { error: "no run yet — analyze a log first" } });
    renderApp(<App />, { route: "/assets" });
    expect(await screen.findByText(/no inventory to invent/)).toBeInTheDocument();
  });
});
