import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { Incident } from "@/lib/api";

function incident(over: Partial<Incident> = {}): Incident {
  return {
    id: "inc-abc123", runId: "test-run", entity: "203.0.113.44", entityKind: "ip",
    title: "203.0.113.44 — 2 correlated finding(s)", severity: "CRITICAL", state: "new",
    findingIds: ["detector-0", "detector-1"], findingCount: 2,
    techniques: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    attackerStatus: "Breaking In",
    createdAt: "2026-08-13T02:16:44+00:00", firstSeen: "2026-08-13T02:16:44+00:00",
    lastSeen: "2026-08-13T02:18:00+00:00", acknowledgedAt: null, resolvedAt: null,
    timeUncertain: false, ...over,
  };
}

describe("Incidents page", () => {
  it("renders the incident list from real data", async () => {
    mockFetch({ "/api/incidents": { incidents: [incident(), incident({ id: "inc-def456", entity: "app-01", entityKind: "host", severity: "HIGH", state: "acknowledged" }) ] } });
    renderApp(<App />, { route: "/incidents" });

    expect(await screen.findByText(/2 incident\(s\)/)).toBeInTheDocument();
    expect(screen.getAllByTestId("incident-row").length).toBe(2);
    expect(screen.getByText("203.0.113.44")).toBeInTheDocument();
  });

  it("shows an honest empty state when there are no incidents", async () => {
    mockFetch({ "/api/incidents": { incidents: [] } });
    renderApp(<App />, { route: "/incidents" });
    expect(await screen.findByText(/No incidents yet/)).toBeInTheDocument();
  });

  it("opens the detail with lifecycle controls and posts a state transition", async () => {
    const post = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => incident({ state: "acknowledged", acknowledgedAt: "2026-08-13T03:00:00+00:00" }),
    } as Response));
    // Route the POST /state before the list route (substring, insertion order).
    mockFetch({ "/api/incidents/inc-abc123/state": { incidents: [] }, "/api/incidents": { incidents: [incident()] } });
    // Override fetch so the state POST is observable, everything else falls through.
    const base = globalThis.fetch as unknown as typeof fetch;
    vi.stubGlobal("fetch", vi.fn((url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).includes("/state") && init?.method === "POST") return post();
      return (base as (u: RequestInfo | URL, i?: RequestInit) => Promise<Response>)(url, init);
    }));

    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    expect(await screen.findByText(/Lifecycle · analyst-owned/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "acknowledged" }));
    expect(post).toHaveBeenCalledTimes(1);
  });
});
