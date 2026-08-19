import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const METRICS = { events: 3, critical: 1, high: 1, assets: 0, openVulns: 0, iocHits: 0 };
const EMPTY_METRICS = { events: 0, critical: 0, high: 0, assets: 0, openVulns: 0, iocHits: 0 };
const SETTINGS = { settings: { retention_days: "90" }, secrets: {} };
const AVAILABLE = { available: true, message: "" };
const UNAVAILABLE = { available: false, message: "EVTX support needs python-evtx installed (pip install python-evtx)" };
const EMPTY_EVENTS = { items: [], total: 0, limit: 100, offset: 0 };

const EVTX_EVENTS = {
  items: [{
    id: 1, ts: "2026-08-19T10:00:00Z", source: "Microsoft-Windows-Security-Auditing",
    source_type: "evtx", host: "WIN-DC01", src_ip: "", severity: "ERROR",
    message: "Security EventID 4625", raw: "<Event>…</Event>",
    category: "Security", event_id: "4625",
  }],
  total: 1, limit: 100, offset: 0,
};

describe("History — store history, KPIs, EVTX ingest, retention", () => {
  it("shows Command-Center KPIs and an honest empty events state", async () => {
    mockFetch({
      "/api/store/metrics": EMPTY_METRICS,
      "/api/store/events": EMPTY_EVENTS,
      "/api/store/settings": SETTINGS,
      "/api/evtx/status": AVAILABLE,
    });
    renderApp(<App />, { route: "/history" });

    // KPI labels are present; the "source-reported" framing is explicit.
    expect(await screen.findByText("Open Vulns")).toBeInTheDocument();
    expect(screen.getByText("IOC Hits")).toBeInTheDocument();
    expect(screen.getAllByText("source-reported").length).toBeGreaterThan(0);
    expect(screen.getByText(/No events in the store yet/i)).toBeInTheDocument();
  });

  it("renders a stored EVTX event with its source-reported severity", async () => {
    mockFetch({
      "/api/store/metrics": METRICS,
      "/api/store/events": EVTX_EVENTS,
      "/api/store/settings": SETTINGS,
      "/api/evtx/status": AVAILABLE,
    });
    renderApp(<App />, { route: "/history" });

    const evId = await screen.findByText("4625");
    const row = evId.closest("tr")!;
    expect(within(row).getByText("evtx")).toBeInTheDocument();
    expect(within(row).getByText("ERROR")).toBeInTheDocument();
    expect(within(row).getByText("WIN-DC01")).toBeInTheDocument();
  });

  it("shows the honest install message and disables ingest when python-evtx is absent", async () => {
    mockFetch({
      "/api/store/metrics": EMPTY_METRICS,
      "/api/store/events": EMPTY_EVENTS,
      "/api/store/settings": SETTINGS,
      "/api/evtx/status": UNAVAILABLE,
    });
    renderApp(<App />, { route: "/history" });

    expect(await screen.findByText(/needs python-evtx installed/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /choose \.evtx/i })).toBeDisabled();
  });

  it("gates the destructive purge behind a typed PURGE confirmation", async () => {
    mockFetch({
      "/api/store/metrics": METRICS,
      "/api/store/events": EMPTY_EVENTS,
      "/api/store/settings": SETTINGS,
      "/api/evtx/status": AVAILABLE,
    });
    renderApp(<App />, { route: "/history" });

    const purgeBtn = await screen.findByRole("button", { name: /purge everything/i });
    expect(purgeBtn).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/type purge to confirm/i), "PURGE");
    expect(purgeBtn).toBeEnabled();
  });
});
