import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiAnalyst } from "@/components/AiAnalyst";
import { api } from "@/lib/api";
import { renderApp } from "./helpers";

/** The analyst streams token-by-token over api.askStream. These tests drive
 *  that method directly (the SSE wire is covered by a live backend check),
 *  asserting progressive render, a Stop control, and an honest error. */
describe("AI Analyst streaming", () => {
  // spyOn(api, "askStream") in the render tests must not leak into the parser
  // test, which calls the REAL askStream.
  afterEach(() => vi.restoreAllMocks());

  it("renders tokens progressively as they arrive", async () => {
    const spy = vi.spyOn(api, "askStream").mockImplementation(async (_q, onDelta) => {
      onDelta("Brute-force ");
      onDelta("against root ");
      onDelta("is the top pattern.");
    });
    renderApp(<AiAnalyst model="llama3.1:8b" />);

    await userEvent.click(screen.getByRole("button", { name: "Open AI Analyst" }));
    await userEvent.click(screen.getByText("What are the recent attack patterns?"));

    expect(await screen.findByText(/Brute-force against root is the top pattern\./))
      .toBeInTheDocument();
    expect(spy).toHaveBeenCalledOnce();
  });

  it("shows a Stop control while streaming and an honest error on failure", async () => {
    // A stream that never resolves until we reject it lets us see the Stop
    // control, then simulate the backend dropping.
    const holder: { reject?: (e: unknown) => void } = {};
    vi.spyOn(api, "askStream").mockImplementation((_q, _onDelta, signal) =>
      new Promise((_res, rej) => {
        holder.reject = rej;
        signal?.addEventListener("abort", () => rej(new Error("aborted")));
      }));

    renderApp(<AiAnalyst model="llama3.1:8b" />);
    await userEvent.click(screen.getByRole("button", { name: "Open AI Analyst" }));
    await userEvent.click(screen.getByText("Summarize today's threats"));

    // While in flight: a Stop control and the elapsed/streaming line.
    expect(await screen.findByRole("button", { name: /stop/i })).toBeInTheDocument();

    // Simulate the backend dropping: an honest, non-fabricated error.
    holder.reject?.(new Error("connection lost"));
    expect(await screen.findByText(/not reachable — connection lost/)).toBeInTheDocument();
  });

  it("parses the SSE framing our backend emits (delta events then done)", async () => {
    // Feed the exact bytes serve.py writes, split ACROSS frame boundaries to
    // prove the buffering reassembles frames. A hand-rolled reader stands in
    // for res.body so the test exercises askStream's own parse loop.
    const enc = new TextEncoder();
    const parts = [
      'data: {"delta": "one ', 'two"}\n\ndata: {"del',
      'ta": "three"}\n\n', 'data: {"done": true}\n\n',
    ].map((s) => enc.encode(s));
    let i = 0;
    const reader = {
      read: async () => (i < parts.length
        ? { value: parts[i++], done: false }
        : { value: undefined, done: true }),
    };
    vi.stubGlobal("fetch", vi.fn(async () =>
      ({ ok: true, status: 200, body: { getReader: () => reader } }) as unknown as Response));

    const chunks: string[] = [];
    await api.askStream("q", (d) => chunks.push(d));
    expect(chunks.join("")).toBe("one twothree");
  });
});
