import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

const CASE = {
  id: "case-1", title: "Investigate 203.0.113.44", notes: "brute-force source",
  assignee: "sam", status: "open",
  links: { findings: ["detector-0"], incidents: [] },
  createdAt: "2026-08-19T09:00:00Z", updatedAt: "2026-08-19T09:00:00Z",
};

describe("Cases page (CRUD)", () => {
  it("renders real cases from /api/cases with their status", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [CASE] } });
    renderApp(<App />, { route: "/cases" });

    expect(await screen.findByText("Investigate 203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText("case-1")).toBeInTheDocument();
    expect((screen.getByLabelText("Status of case-1") as HTMLSelectElement).value).toBe("open");
    expect(screen.getByText("detector-0")).toBeInTheDocument();
  });

  it("shows an honest empty state when there are no cases", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [] } });
    renderApp(<App />, { route: "/cases" });
    expect(await screen.findByText("No cases yet")).toBeInTheDocument();
    expect(screen.getByText(/no sample cases are invented/i)).toBeInTheDocument();
  });

  it("creates a case via POST /api/cases with the typed title", async () => {
    let postBody: unknown = null;
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [] } });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/cases") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => CASE } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />, { route: "/cases" });
    await screen.findByText("No cases yet");

    await userEvent.click(screen.getByRole("button", { name: /new case/i }));
    await userEvent.type(screen.getByLabelText("Case title"), "Follow up on root logins");
    await userEvent.click(screen.getByRole("button", { name: /create case/i }));

    await waitFor(() => expect(postBody).toMatchObject({ title: "Follow up on root logins" }));
  });
});
