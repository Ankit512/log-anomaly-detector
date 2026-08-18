import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface Msg { who: "q" | "a" | "err"; text: string }

const EXAMPLES = [
  "Show me the top 5 critical alerts",
  "Summarize this run for a handoff",
  "Which host should I look at first?",
];

/** Advisory chat over /api/ask. The model explains; it never changes a
 *  severity or verdict, and an unreachable backend is an honest error. */
export function AiAnalyst({ model }: { model?: string }) {
  const [log, setLog] = useState<Msg[]>([]);
  const [input, setInput] = useState("");

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
        text: "The analyst backend is not reachable — start the console server to use this.",
      }]);
    },
  });

  const ask = (q: string) => {
    const question = q.trim();
    if (!question) return;
    setLog((l) => [...l, { who: "q", text: question }]);
    setInput("");
    askMut.mutate(question);
  };

  return (
    <Card className="flex max-h-[calc(100vh-8rem)] flex-col">
      <CardHeader>
        <CardTitle>
          AI Analyst <span className="font-normal text-muted-foreground">Ollama · local</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex min-h-0 flex-1 flex-col gap-2.5">
        <p className="rounded-md bg-muted px-2.5 py-2 text-[11.5px] text-muted-foreground">
          Advisory only: the model explains findings in plain language. Severities
          and verdicts come from the deterministic rules and are never changed here.
        </p>
        <div className="flex flex-col gap-1.5">
          {EXAMPLES.map((q, i) => (
            <button
              key={q}
              onClick={() => ask(q)}
              className={
                i === 0
                  ? "rounded-md border border-primary bg-accent px-2.5 py-1.5 text-left text-xs font-semibold text-accent-foreground"
                  : "rounded-md border px-2.5 py-1.5 text-left text-xs text-muted-foreground hover:border-primary"
              }
            >
              {q}
            </button>
          ))}
        </div>
        <div className="min-h-24 flex-1 space-y-2 overflow-auto text-[12.5px]" aria-live="polite">
          {log.length === 0 && (
            <p className="rounded-md bg-muted px-2.5 py-2 text-muted-foreground">
              Ask about the current run — e.g. what a finding means, or where to start.
            </p>
          )}
          {log.map((m, i) => (
            <p
              key={i}
              className={
                m.who === "q" ? "ml-6 rounded-md bg-accent px-2.5 py-2"
                : m.who === "err" ? "rounded-md px-2.5 py-2"
                : "rounded-md bg-muted px-2.5 py-2 whitespace-pre-wrap"
              }
              style={m.who === "err"
                ? { background: "color-mix(in srgb, var(--sev-critical) 14%, transparent)" }
                : undefined}
            >
              {m.text}
            </p>
          ))}
          {askMut.isPending && <p className="px-2.5 text-muted-foreground">thinking…</p>}
        </div>
        <form
          className="flex gap-2"
          onSubmit={(e) => { e.preventDefault(); ask(input); }}
        >
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask anything about your logs..."
            aria-label="Ask the AI analyst"
          />
          <Button type="submit" size="icon" aria-label="Send">
            <Send className="h-4 w-4" />
          </Button>
        </form>
        <div className="font-mono text-[10.5px] text-muted-foreground">
          Model: {model ?? "not configured"}
        </div>
      </CardContent>
    </Card>
  );
}
