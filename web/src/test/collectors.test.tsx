import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import App from "@/App";
import type { SyslogStatus } from "@/lib/api";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const STOPPED: SyslogStatus = {
  running: false, bind: "127.0.0.1", port: 1514, protocols: ["udp", "tcp"],
  exposed: false, receivedCount: 0, storedCount: 0,
  startedAt: null, lastEventAt: null, error: "",
};
const RUNNING_EXPOSED: SyslogStatus = {
  running: true, bind: "0.0.0.0", port: 1514, protocols: ["udp", "tcp"],
  exposed: true, receivedCount: 7, storedCount: 6,
  startedAt: "2026-08-19T15:00:00Z", lastEventAt: "2026-08-19T15:01:00Z", error: "",
};

const EMPTY_EVENTS = { items: [], total: 0, limit: 15, offset: 0 };

describe("Collectors — syslog control panel", () => {
  it("shows the honest stopped state and the start control", async () => {
    mockFetch({ "/api/syslog/status": STOPPED, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/collectors" });

    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start collector/i })).toBeInTheDocument();
    // Stop is disabled while nothing is running.
    expect(screen.getByRole("button", { name: /^stop$/i })).toBeDisabled();
    // The form seeds from the current listener config.
    expect(screen.getByLabelText("Listen port")).toHaveValue("1514");
    // Honest empty state for received events.
    expect(screen.getByText(/No syslog events received yet/)).toBeInTheDocument();
  });

  it("warns before binding 0.0.0.0 (network exposure)", async () => {
    mockFetch({ "/api/syslog/status": STOPPED, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/collectors" });
    await screen.findByText("Stopped");

    // No warning box while bound to loopback (the radio label mentions
    // exposure, but the dedicated warning copy is absent).
    expect(screen.queryByText(/send events into your store/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: /all interfaces/i }));
    expect(await screen.findByText(/send events into your store/i)).toBeInTheDocument();
  });

  it("start posts the chosen port and bind", async () => {
    let postBody: unknown = null;
    // A self-contained stub (no passthrough) so nothing leaks between tests.
    const reply = (body: unknown) =>
      Promise.resolve({ ok: true, status: 200, json: async () => body } as Response);
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      const url = String(u);
      if (url.includes("/api/syslog/start") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return reply(RUNNING_EXPOSED);
      }
      if (url.includes("/api/store/events")) return reply(EMPTY_EVENTS);
      if (url.includes("/api/syslog/status")) return reply(STOPPED);
      if (url.includes("/api/runs")) return reply({ runs: [], current: null });
      // Anything else 404s (like the shared mockFetch helper) so unrelated
      // shell queries fail cleanly instead of getting a malformed body.
      return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
    }));
    renderApp(<App />, { route: "/collectors" });
    await screen.findByText("Stopped");

    const port = screen.getByLabelText("Listen port");
    await userEvent.clear(port);
    await userEvent.type(port, "5514");
    await userEvent.click(screen.getByRole("button", { name: /start collector/i }));

    await waitFor(() => expect(postBody).toEqual({ port: 5514, bind: "127.0.0.1" }));
  });

  it("running + exposed reflects the real state with an exposure warning", async () => {
    mockFetch({
      "/api/syslog/status": RUNNING_EXPOSED,
      "/api/store/events": EMPTY_EVENTS,
    });
    renderApp(<App />, { route: "/collectors" });

    expect(await screen.findByText("Running")).toBeInTheDocument();
    // Received count is surfaced honestly.
    expect(screen.getByText("Messages received").parentElement)
      .toHaveTextContent("7");
    // The live status card warns that 0.0.0.0 is reachable from the network.
    expect(screen.getByText(/reachable\s+from the whole network/i)).toBeInTheDocument();
  });

  it("recent events show the source-reported severity and verbatim raw", async () => {
    mockFetch({
      "/api/syslog/status": RUNNING_EXPOSED,
      "/api/store/events": {
        items: [{
          id: 3, ts: "2026-08-19T15:01:00Z", source: "syslog:10.0.0.9",
          source_type: "syslog", host: "host1", src_ip: "10.0.0.9",
          severity: "ERROR", message: "disk error",
          raw: "<11>Aug 19 15:01:00 host1 svc: disk error",
        }],
        total: 1, limit: 15, offset: 0,
      },
    });
    renderApp(<App />, { route: "/collectors" });

    const rawLine = await screen.findByText("<11>Aug 19 15:01:00 host1 svc: disk error");
    const row = rawLine.closest("tr")!;
    expect(within(row).getByText("ERROR")).toBeInTheDocument();
    expect(within(row).getByText("10.0.0.9")).toBeInTheDocument();
    // Framed as source-reported, not a verdict.
    expect(screen.getByText(/source-reported/i)).toBeInTheDocument();
  });
});
