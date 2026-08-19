import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const NO_KEYS = { otx: false, abuseipdb: false };
const BOTH_KEYS = { otx: true, abuseipdb: true };
const EMPTY_IOCS = { items: [], total: 0, limit: 100, offset: 0 };
const NO_CONNECTORS = { connectors: [] };

describe("Enrichment — TI panel (masked keys, honest states)", () => {
  it("shows honest not-configured key status and a no-key warning", async () => {
    mockFetch({
      "/api/ti/keys": NO_KEYS,
      "/api/store/iocs": EMPTY_IOCS,
    });
    renderApp(<App />, { route: "/enrichment" });

    expect(await screen.findAllByText(/no key configured/i)).not.toHaveLength(0);
    expect(screen.getByText(/No provider key is configured yet/i)).toBeInTheDocument();
    // Honest empty IOC history.
    expect(screen.getByText(/No IOC lookups recorded yet/i)).toBeInTheDocument();
  });

  it("enrich posts the IP and renders provider verdicts from the real response", async () => {
    let postBody: unknown = null;
    const reply = (body: unknown) =>
      Promise.resolve({ ok: true, status: 200, json: async () => body } as Response);
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      const url = String(u);
      if (url.includes("/api/ti/enrich") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return reply({
          ip: "203.0.113.9",
          results: [{ id: 1, ts: "2026-08-19T17:00:00Z", ioc: "203.0.113.9", ioc_type: "ipv4",
                      provider: "OTX", score: 70, verdict: "malicious",
                      details: "{\"pulseCount\":7}", source_event_id: null }],
          errors: [], notConfigured: ["AbuseIPDB"],
        });
      }
      if (url.includes("/api/ti/keys")) return reply(BOTH_KEYS);
      if (url.includes("/api/store/iocs")) return reply(EMPTY_IOCS);
      if (url.includes("/api/runs")) return reply({ runs: [], current: null });
      return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
    }));
    renderApp(<App />, { route: "/enrichment" });

    await userEvent.type(await screen.findByLabelText(/IP address to enrich/i), "203.0.113.9");
    await userEvent.click(screen.getByRole("button", { name: /^enrich$/i }));

    await waitFor(() => expect(postBody).toEqual({ ip: "203.0.113.9" }));
    const verdict = await screen.findByText("malicious");
    const row = verdict.closest("tr")!;
    expect(within(row).getByText("OTX")).toBeInTheDocument();
    expect(within(row).getByText("70")).toBeInTheDocument();
    // A provider with no key is honestly reported as skipped.
    expect(screen.getByText(/Not configured \(skipped\): AbuseIPDB/i)).toBeInTheDocument();
  });
});

describe("OEM Engine — connectors (masked creds, real poll outcome)", () => {
  it("shows the honest empty state and the add-connector form", async () => {
    mockFetch({ "/api/oem/connectors": NO_CONNECTORS });
    renderApp(<App />, { route: "/oem" });

    expect(await screen.findByText(/No OEM connectors yet/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/API token/i)).toHaveAttribute("type", "password");
    expect(screen.getByRole("button", { name: /save connector/i })).toBeInTheDocument();
  });

  it("renders a connector's real last-run/last-error and token presence only", async () => {
    mockFetch({
      "/api/oem/connectors": {
        connectors: [{
          name: "Prod-FW-1", kind: "oem", enabled: true, interval: 30,
          lastRun: "2026-08-19T17:00:00Z", lastError: "connector base URL is still a placeholder — set the real host",
          hasConfig: true, hasToken: true,
        }],
      },
    });
    renderApp(<App />, { route: "/oem" });

    expect(await screen.findByText("Prod-FW-1")).toBeInTheDocument();
    expect(await screen.findByText("token set")).toBeInTheDocument();
    // The real poll error is surfaced, not hidden behind a fake "connected".
    expect(screen.getByText(/still a placeholder/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^disable$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /poll now/i })).toBeInTheDocument();
  });
});
