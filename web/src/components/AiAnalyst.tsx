import { useEffect, useRef, useState } from "react";
import { Bot, Send, Square, X } from "lucide-react";
import { api } from "@/lib/api";

interface Msg { who: "q" | "a" | "err"; text: string }

const EXAMPLES = [
  "Show me top 5 critical alerts",
  "What are the recent attack patterns?",
  "Summarize today's threats",
];

/** No first token within this long is treated as an honest timeout — small
 *  models on CPU are slow, but silence past this means something is wrong. */
const FIRST_TOKEN_TIMEOUT_MS = 90_000;

/** The v6 floating analyst: a bottom-right FAB opening a chat panel over
 *  /api/ask, STREAMING the reply token-by-token so a slow local model shows
 *  progress instead of hanging on "thinking…". Advisory only — the model
 *  explains, it never changes a severity or verdict — with an elapsed timer,
 *  a Stop control, and an honest timeout/error if the model never answers. */
export function AiAnalyst({ model }: { model?: string }) {
  const [open, setOpen] = useState(false);
  const [log, setLog] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [gotFirstToken, setGotFirstToken] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const startRef = useRef(0);

  // Elapsed timer while a reply streams.
  useEffect(() => {
    if (!streaming) return;
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - startRef.current) / 1000)), 250);
    return () => clearInterval(t);
  }, [streaming]);

  const stop = () => { abortRef.current?.abort(); };

  const ask = async (q: string) => {
    const question = q.trim();
    if (!question || streaming) return;
    setDraft("");
    setLog((l) => [...l, { who: "q", text: question }, { who: "a", text: "" }]);
    const answerIndex = log.length + 1; // the empty "a" slot we just appended

    const controller = new AbortController();
    abortRef.current = controller;
    startRef.current = Date.now();
    setElapsed(0);
    setGotFirstToken(false);
    setStreaming(true);

    // Honest timeout: if no first token arrives, abort and say so.
    let first = false;
    const timeout = setTimeout(() => {
      if (!first) controller.abort("timeout");
    }, FIRST_TOKEN_TIMEOUT_MS);

    try {
      await api.askStream(question, (delta) => {
        if (!first) { first = true; setGotFirstToken(true); }
        setLog((l) => {
          const next = [...l];
          const cur = next[answerIndex];
          if (cur && cur.who === "a") next[answerIndex] = { who: "a", text: cur.text + delta };
          return next;
        });
      }, controller.signal);
    } catch (e) {
      const aborted = controller.signal.aborted;
      const reason = controller.signal.reason;
      const msg = aborted
        ? (reason === "timeout"
            ? "The model did not start answering in time — it may be loading or overloaded. Try again."
            : "Stopped.")
        : `The analyst backend is not reachable — ${(e as Error).message}`;
      setLog((l) => {
        const next = [...l];
        const cur = next[answerIndex];
        // Replace an empty answer bubble with the notice; keep partial text.
        if (cur && cur.who === "a" && !cur.text) next[answerIndex] = { who: "err", text: msg };
        else next.push({ who: "err", text: msg });
        return next;
      });
    } finally {
      clearTimeout(timeout);
      setStreaming(false);
      abortRef.current = null;
    }
  };

  return (
    <div className="fixed bottom-[22px] right-[22px] z-50 flex flex-col items-end gap-2.5">
      {open && (
        <section
          aria-label="AI Analyst"
          className="flex max-h-[min(560px,calc(100vh-120px))] w-[340px] flex-col gap-[11px] rounded-lg bg-card p-4 px-[18px] shadow-[0_12px_32px_-8px_rgba(26,32,51,0.28)]"
        >
          <div className="flex items-center gap-2">
            <div className="text-sm font-semibold">AI Analyst (Ollama)</div>
            <button
              onClick={() => setOpen(false)} aria-label="Close analyst"
              className="ml-auto inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-background"
            >
              <X className="h-[15px] w-[15px]" aria-hidden />
            </button>
          </div>
          <div className="rounded-[9px] border bg-background px-[13px] py-[11px] text-[12.5px] leading-normal text-muted-foreground">
            Advisory only: the model explains findings in plain language.
            Severities and verdicts come from the deterministic rules and are
            never changed here.
          </div>
          <div aria-live="polite" className="flex min-h-[130px] flex-1 flex-col gap-2 overflow-auto text-[12.5px]">
            {log.length === 0 && (
              <div className="flex flex-col gap-2">
                <p className="text-[12.5px] leading-normal text-muted-foreground">
                  Ask me about your security data in natural language. Example:
                </p>
                {EXAMPLES.map((q) => (
                  <button
                    key={q}
                    onClick={() => ask(q)}
                    className="rounded-lg border bg-card px-2.5 py-[7px] text-left text-xs text-muted-foreground hover:border-primary hover:text-accent-foreground"
                  >
                    {q}
                  </button>
                ))}
              </div>
            )}
            {log.map((m, i) => {
              const isStreamingAnswer = streaming && m.who === "a" && i === log.length - 1;
              return (
                <div
                  key={i}
                  className={
                    m.who === "q" ? "max-w-[95%] self-end whitespace-pre-wrap rounded-[10px] bg-accent px-[11px] py-2 text-accent-foreground"
                    : m.who === "err" ? "max-w-[95%] whitespace-pre-wrap rounded-[10px] px-[11px] py-2"
                    : "max-w-[95%] whitespace-pre-wrap rounded-[10px] bg-background px-[11px] py-2 text-muted-foreground"
                  }
                  style={m.who === "err"
                    ? { background: "color-mix(in srgb, var(--sev-critical) 14%, transparent)" }
                    : undefined}
                >
                  {m.text}
                  {isStreamingAnswer && !m.text && (
                    <span className="text-muted-foreground">
                      {gotFirstToken ? "" : `waiting for the model… ${elapsed}s`}
                    </span>
                  )}
                  {isStreamingAnswer && m.text && <span className="animate-pulse">▍</span>}
                </div>
              );
            })}
          </div>
          {streaming && (
            <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
              <span className="tabular-nums">streaming · {elapsed}s</span>
              <button
                onClick={stop}
                className="ml-auto inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11.5px] hover:border-primary"
              >
                <Square className="h-3 w-3" aria-hidden /> Stop
              </button>
            </div>
          )}
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); ask(draft); }}>
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Ask anything about your logs..."
              aria-label="Ask the AI analyst"
              disabled={streaming}
              className="min-w-0 flex-1 rounded-lg border bg-card px-[11px] py-[9px] text-[13px] disabled:opacity-60"
            />
            <button
              type="submit" aria-label="Send" disabled={streaming}
              className="inline-flex w-9 items-center justify-center rounded-lg border border-primary bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-60"
            >
              <Send className="h-[15px] w-[15px]" aria-hidden />
            </button>
          </form>
          <div className="font-mono text-[11px] text-muted-foreground">
            Model: {model ?? "not configured"}
          </div>
        </section>
      )}

      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? "Close AI Analyst" : "Open AI Analyst"}
        className="inline-flex items-center gap-[9px] rounded-full border border-primary bg-card px-[18px] py-3 text-[13.5px] font-semibold shadow-card hover:bg-accent"
      >
        <Bot className="h-[17px] w-[17px] text-primary" strokeWidth={1.8} aria-hidden />
        AI Analyst
        <span className="text-[9.5px] font-medium uppercase tracking-[0.05em] text-muted-foreground">
          advisory
        </span>
      </button>
    </div>
  );
}
