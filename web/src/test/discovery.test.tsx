import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import App from "@/App";
import type { DiscoveryStatus } from "@/lib/api";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const IDLE: DiscoveryStatus = {
  running: false, target: "", vuln: false, startedAt: null, finishedAt: null,
  error: "", hostsFound: 0, assetsStored: 0, vulnsStored: 0, nmapInstalled: true,
};
const NO_NMAP: DiscoveryStatus = { ...IDLE, nmapInstalled: false };

const EMPTY_ASSETS = { items: [], total: 0, limit: 100, offset: 0 };
const EMPTY_VULNS = { items: [], total: 0, limit: 200, offset: 0 };

describe("Discovery — nmap scan control panel", () => {
  it("shows the honest idle state, guardrail copy, and scan controls", async () => {
    mockFetch({ "/api/discovery/status": IDLE, "/api/store/assets": EMPTY_ASSETS });
    renderApp(<App />, { route: "/discovery" });

    expect(await screen.findByRole("button", { name: /discover live nodes/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /service \+ vulnerability scan/i })).toBeInTheDocument();
    // The dual-use guardrail is stated: private targets only.
    expect(screen.getByText(/Private \(RFC1918\), loopback, and link-local targets only/i)).toBeInTheDocument();
    // Honest empty state for discovered assets.
    expect(screen.getByText(/No hosts discovered yet/i)).toBeInTheDocument();
  });

  it("refuses to enable scanning and warns honestly when nmap is not installed", async () => {
    mockFetch({ "/api/discovery/status": NO_NMAP, "/api/store/assets": EMPTY_ASSETS });
    renderApp(<App />, { route: "/discovery" });

    expect(await screen.findByText(/nmap is not installed/i)).toBeInTheDocument();
    // Even with a target typed, the buttons stay disabled — nothing is faked.
    await userEvent.type(screen.getByLabelText(/target host or cidr/i), "192.168.1.0/24");
    expect(screen.getByRole("button", { name: /discover live nodes/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /service \+ vulnerability scan/i })).toBeDisabled();
  });

  it("a vulnerability scan posts the target and the vuln flag", async () => {
    let postBody: unknown = null;
    const reply = (body: unknown) =>
      Promise.resolve({ ok: true, status: 200, json: async () => body } as Response);
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      const url = String(u);
      if (url.includes("/api/discovery/scan") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return reply({ ...IDLE, running: true, target: "10.0.0.0/24", vuln: true });
      }
      if (url.includes("/api/store/assets")) return reply(EMPTY_ASSETS);
      if (url.includes("/api/discovery/status")) return reply(IDLE);
      if (url.includes("/api/runs")) return reply({ runs: [], current: null });
      return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
    }));
    renderApp(<App />, { route: "/discovery" });

    await userEvent.type(await screen.findByLabelText(/target host or cidr/i), "10.0.0.0/24");
    await userEvent.click(screen.getByRole("button", { name: /service \+ vulnerability scan/i }));

    await waitFor(() => expect(postBody).toEqual({ target: "10.0.0.0/24", vuln: true }));
  });

  it("surfaces a refused public target as the backend's honest error", async () => {
    const reply = (body: unknown, ok = true, status = 200) =>
      Promise.resolve({ ok, status, json: async () => body } as Response);
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      const url = String(u);
      if (url.includes("/api/discovery/scan") && init?.method === "POST") {
        return reply({ error: "only private/authorized targets may be scanned" }, false, 400);
      }
      if (url.includes("/api/store/assets")) return reply(EMPTY_ASSETS);
      if (url.includes("/api/discovery/status")) return reply(IDLE);
      if (url.includes("/api/runs")) return reply({ runs: [], current: null });
      return reply({}, false, 404);
    }));
    renderApp(<App />, { route: "/discovery" });

    await userEvent.type(await screen.findByLabelText(/target host or cidr/i), "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: /discover live nodes/i }));

    expect(await screen.findByText(/only private\/authorized targets may be scanned/i)).toBeInTheDocument();
  });

  it("renders discovered assets from the store", async () => {
    mockFetch({
      "/api/discovery/status": { ...IDLE, finishedAt: "2026-08-19T16:00:00Z", hostsFound: 1, assetsStored: 1 },
      "/api/store/assets": {
        items: [{
          id: 1, ts: "2026-08-19T16:00:00Z", ip: "192.168.1.10", hostname: "box.local",
          mac: "AA:BB:CC:DD:EE:FF", vendor: "Acme", os: "", ports: "443/tcp:https",
          source: "nmap", status: "up",
        }],
        total: 1, limit: 100, offset: 0,
      },
    });
    renderApp(<App />, { route: "/discovery" });

    const ipCell = await screen.findByText("192.168.1.10");
    const row = ipCell.closest("tr")!;
    expect(within(row).getByText("box.local")).toBeInTheDocument();
    expect(within(row).getByText("443/tcp:https")).toBeInTheDocument();
  });
});

describe("Vulnerabilities — store-backed table", () => {
  it("shows an honest empty state when nothing is stored", async () => {
    mockFetch({ "/api/store/vulns": EMPTY_VULNS });
    renderApp(<App />, { route: "/vulnerabilities" });
    expect(await screen.findByText(/No vulnerabilities recorded yet/i)).toBeInTheDocument();
  });

  it("renders a stored vuln with its NSE-derived severity and CVSS", async () => {
    mockFetch({
      "/api/store/vulns": {
        items: [{
          id: 5, ts: "2026-08-19T16:05:00Z", asset_ip: "192.168.1.10", name: "vulners",
          cve: "CVE-2021-23017", severity: "CRITICAL", cvss: 9.8,
          details: "CVE-2021-23017 9.8 https://vulners.com/x", source: "nmap:vulners",
          status: "OPEN",
        }, {
          id: 6, ts: "2026-08-19T16:05:00Z", asset_ip: "192.168.1.10", name: "ssl-enum",
          cve: "", severity: "", cvss: 0,
          details: "VULNERABLE: weak cipher", source: "nmap:ssl-enum", status: "OPEN",
        }],
        total: 2, limit: 200, offset: 0,
      },
    });
    renderApp(<App />, { route: "/vulnerabilities" });

    const cveCell = await screen.findByText("CVE-2021-23017");
    const row = cveCell.closest("tr")!;
    expect(within(row).getByText("CRITICAL")).toBeInTheDocument();
    expect(within(row).getByText("9.8")).toBeInTheDocument();
    // A finding with no NSE score is shown honestly as "unknown", not guessed.
    expect(screen.getByText("unknown")).toBeInTheDocument();
    // The severity framing is explicit about being CVSS-derived, not guessed.
    expect(screen.getByText(/Severity is the CVSS band NSE reported/i)).toBeInTheDocument();
  });
});
