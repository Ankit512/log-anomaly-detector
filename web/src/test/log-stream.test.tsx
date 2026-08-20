import { act, screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, consoleState, finding } from "./helpers";

/** The Alerts page tails the current run's log over GET /api/stream (SSE).
 *  jsdom has no EventSource, so a mock stands in and the tests drive the
 *  exact named events the backend emits (log / finding / ping / gap),
 *  asserting: rows append verbatim, findings surface (and re-emits replace,
 *  not duplicate), a gap is rendered honestly, unparseable fields show n/a,
 *  and a dead stream falls back to the 5s polling with a visible notice. */

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  private listeners: Record<string, ((e: MessageEvent) => void)[]> = {};
  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }
  addEventListener(type: string, fn: (e: MessageEvent) => void) {
    (this.listeners[type] ??= []).push(fn);
  }
  close() {}
  /** Fire one named SSE event, exactly as the browser would deliver it. */
  emit(type: string, data?: unknown) {
    for (const fn of this.listeners[type] ?? []) {
      fn({ data: data === undefined ? "" : JSON.stringify(data) } as MessageEvent);
    }
  }
}

/** An `event: log` payload as serve.py emits it (contract shape, no extras). */
function logEvent(n: number, over: Partial<Record<string, unknown>> = {}) {
  return {
    n,
    ts: `2026-08-13T02:16:${40 + n}+00:00`,
    level: "ERROR",
    host: "host-1",
    msg: "something failed",
    raw: `2026-08-13T02:16:${40 + n}Z ERROR host-1 something failed`,
    bucket: "HIGH",
    ...over,
  };
}

const STATE = () =>
  consoleState([finding(0)], { logPath: "/tmp/live.log" });

async function renderAlertsWithStream() {
  vi.stubGlobal("EventSource", MockEventSource);
  mockFetch({ "/console_state.json": STATE() });
  renderApp(<App />, { route: "/alerts" });
  await screen.findByText("Live tail");
  const es = MockEventSource.instances.at(-1)!;
  act(() => es.emit("open"));
  return es;
}

describe("Alerts live stream (/api/stream SSE)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    MockEventSource.instances.length = 0;
  });

  it("connects to /api/stream with the run's logPath and shows live status", async () => {
    const es = await renderAlertsWithStream();
    expect(es.url).toBe("/api/stream?source=%2Ftmp%2Flive.log");
    expect(screen.getByTestId("stream-status")).toHaveTextContent(/streaming/);
  });

  it("appends event: log rows verbatim — line number, time, bucket, raw", async () => {
    const es = await renderAlertsWithStream();
    act(() => {
      es.emit("log", logEvent(2));
      es.emit("log", logEvent(3, { level: "WARN", bucket: "MEDIUM" }));
      es.emit("ping", {}); // keepalive must render nothing
    });

    const rows = screen.getAllByTestId("tail-row");
    expect(rows.length).toBe(2);
    expect(rows[0]).toHaveTextContent("2026-08-13T02:16:42Z ERROR host-1 something failed");
    expect(rows[0]).toHaveTextContent("02:16:42");
    expect(rows[0]).toHaveTextContent("HIGH");
    expect(rows[1]).toHaveTextContent("MEDIUM");
  });

  it("renders an unparseable line honestly: verbatim raw, UNKNOWN bucket, n/a time", async () => {
    const es = await renderAlertsWithStream();
    act(() =>
      es.emit("log", logEvent(9, {
        ts: "", level: "", host: "", msg: "",
        raw: "%% garbage the parser refused %%", bucket: "UNKNOWN",
      })));

    const row = screen.getByTestId("tail-row");
    expect(row).toHaveTextContent("%% garbage the parser refused %%");
    expect(row).toHaveTextContent("UNKNOWN");
    expect(row).toHaveTextContent("n/a");
  });

  it("surfaces event: finding in the findings table; a re-emit replaces, never duplicates", async () => {
    const es = await renderAlertsWithStream();
    const streamed = finding(0, {
      id: "stream-0", type: "auth_bruteforce",
      title: "Live burst from 198.51.100.9", occurrences: 6,
    });
    act(() => es.emit("finding", streamed));

    expect(await screen.findByText("Live burst from 198.51.100.9")).toBeInTheDocument();
    expect(screen.getByText(/2 of 2 finding\(s\)/)).toBeInTheDocument();

    // The burst grew server-side: same rule + same summary re-emitted.
    act(() => es.emit("finding", { ...streamed, id: "stream-1", occurrences: 11 }));
    expect(screen.getAllByText("Live burst from 198.51.100.9").length).toBe(1);
    expect(screen.getByText(/2 of 2 finding\(s\)/)).toBeInTheDocument();
  });

  it("renders event: gap as a visible dropped-events marker — never hidden", async () => {
    const es = await renderAlertsWithStream();
    act(() => {
      es.emit("log", logEvent(2));
      es.emit("gap", { dropped: 12 });
      es.emit("log", logEvent(40));
    });

    expect(screen.getByTestId("stream-dropped"))
      .toHaveTextContent("12 event(s) dropped under backpressure");
    expect(screen.getByTestId("gap-row"))
      .toHaveTextContent(/12 event\(s\) dropped here/);
    // Another gap accumulates the honest total.
    act(() => es.emit("gap", { dropped: 3 }));
    expect(screen.getByTestId("stream-dropped"))
      .toHaveTextContent("15 event(s) dropped under backpressure");
  });

  it("on stream error the panel says polling is the fallback (data keeps flowing via 5s refetch)", async () => {
    const es = await renderAlertsWithStream();
    expect(screen.getByTestId("stream-status")).toHaveTextContent(/streaming/);

    act(() => es.emit("error"));
    expect(screen.getByTestId("stream-status"))
      .toHaveTextContent("stream disconnected — 5s polling fallback active");
    // The polled findings table is still there — the page never went blank.
    expect(screen.getByText(/Brute-force burst #0/)).toBeInTheDocument();
  });

  it("without EventSource support the panel is honest and polling stands alone", async () => {
    // No stubbed EventSource: jsdom genuinely lacks it.
    mockFetch({ "/console_state.json": STATE() });
    renderApp(<App />, { route: "/alerts" });

    await screen.findByText("Live tail");
    expect(screen.getByTestId("stream-status"))
      .toHaveTextContent("streaming unavailable in this browser — 5s polling fallback active");
    expect(screen.getByText(/Brute-force burst #0/)).toBeInTheDocument();
  });
});
