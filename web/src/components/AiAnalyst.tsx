import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Bot, Send, X } from "lucide-react";
import { api } from "@/lib/api";

interface Msg { who: "q" | "a" | "err"; text: string }

const EXAMPLES = [
  "Show me top 5 critical alerts",
  "What are the recent attack patterns?",
  "Summarize today's threats",
];

/** The v6 floating analyst: a bottom-right FAB opening a chat panel over
 *  /api/ask. Advisory only — the model explains, it never changes a severity
 *  or verdict — and an unreachable backend is an honest error, not silence. */
export function AiAnalyst({ model }: { model?: string }) {
  const [open, setOpen] = useState(false);
  const [log, setLog] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");

  const askMut = useMutation({
    mutationFn: api.ask,
    onSuccess: (out) => {
      setLog((l) => [...l, out.answer
        ? { who: "a", text: out.answer }
        : { who: "err", text: out.error ?? "The analyst backend returned no answer." }]);
    },
    onError: () => {
      setLog((l) => [...l, {
        who: "err",
        text: "The analyst backend is not reachable — start the console server (and Ollama) to use this.",
      }]);
    },
  });

  const ask = (q: string) => {
    const question = q.trim();
    if (!question) return;
    setLog((l) => [...l, { who: "q", text: question }]);
    setDraft("");
    askMut.mutate(question);
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
            {log.map((m, i) => (
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
              </div>
            ))}
            {askMut.isPending && <p className="px-1 text-muted-foreground">thinking…</p>}
          </div>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); ask(draft); }}>
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Ask anything about your logs..."
              aria-label="Ask the AI analyst"
              className="min-w-0 flex-1 rounded-lg border bg-card px-[11px] py-[9px] text-[13px]"
            />
            <button
              type="submit" aria-label="Send"
              className="inline-flex w-9 items-center justify-center rounded-lg border border-primary bg-primary text-primary-foreground hover:opacity-90"
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
