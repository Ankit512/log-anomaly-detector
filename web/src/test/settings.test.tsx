import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Settings page", () => {
  it("reflects the real compute config and shows honest redaction state (local)", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/compute": { mode: "local" } });
    renderApp(<App />, { route: "/settings" });

    expect(await screen.findByText("Compute location")).toBeInTheDocument();
    // The current mode is read from the backend: the Local radio is checked.
    const local = await screen.findByRole("radio", { name: /local/i });
    expect(local).toBeChecked();
    // Redaction is shown as a consequence, not a fake toggle.
    expect(screen.getByText("Outbound redaction")).toBeInTheDocument();
    expect(screen.getByText(/not applicable/)).toBeInTheDocument();
    // The analyst model comes from the real overview payload.
    expect(screen.getByText("llama3.1:8b")).toBeInTheDocument();
    // Theme is a real, working control on the page (the header also has one).
    expect(screen.getByText("Appearance")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /switch to dark/i }).length)
      .toBeGreaterThanOrEqual(1);
  });

  it("switches compute to remote via POST /api/compute", async () => {
    let postBody: unknown = null;
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/compute": { mode: "local" } });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/compute") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200,
          json: async () => ({ mode: "remote", baseUrl: "https://h/v1", model: "m", hasKey: false }) } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />, { route: "/settings" });
    await screen.findByText("Compute location");

    await userEvent.click(await screen.findByRole("radio", { name: /remote/i }));
    await userEvent.type(screen.getByLabelText("Remote base URL"), "https://h/v1");
    await userEvent.type(screen.getByLabelText("Remote model"), "m");
    await userEvent.click(screen.getByRole("button", { name: /save compute settings/i }));

    await waitFor(() => expect(postBody).toMatchObject({ mode: "remote", baseUrl: "https://h/v1", model: "m" }));
  });
});
