import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { History, X } from "lucide-react";
import { api } from "@/lib/api";
import { SEV_ORDER, sevVar } from "@/lib/severity";
import { cn } from "@/lib/utils";

/** The v6 run/version history: a header control opening a panel of the REAL
 *  saved runs (/api/runs + /api/runs-summary). Clicking a run POSTs
 *  /api/open and refreshes every query, so the whole dashboard switches to
 *  that run. Unreadable history files are shown flagged, never hidden; a
 *  single-run history says so instead of pretending there is more. */
export function RunHistory() {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const [switching, setSwitching] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: runs } = useQuery({ queryKey: ["runs"], queryFn: api.runs, enabled: open });
  const { data: summary } = useQuery({
    queryKey: ["runs-summary"], queryFn: api.runsSummary, enabled: open,
  });

  const current = runs?.runs.find((r) => r.runId === runs?.current)?.file;
  const rows = summary?.runs ?? [];
  const totals = summary?.totals;

  const switchTo = async (file: string) => {
    setSwitching(file);
    setNote("");
    const out = await api.openRun(file).catch(() => ({ ok: false as const, error: "the backend is not reachable" }));
    setSwitching(null);
    if (!out.ok) {
      setNote(`Could not open that run${out.error ? `: ${out.error}` : ""}.`);
      return;
    }
    await queryClient.invalidateQueries();
    setOpen(false);
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? "Close run history" : "Open run history"}
        aria-expanded={open}
        title="Previous analysis runs — open one to switch the dashboard to it"
        className="inline-flex cursor-pointer items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2.5 text-[13.5px] hover:bg-background"
      >
        <History className="h-4 w-4" strokeWidth={1.8} aria-hidden />
        Runs
      </button>

      {open && (
        <section
          aria-label="Run history"
          className="absolute right-0 top-full z-50 mt-2 w-[420px] max-w-[calc(100vw-40px)] rounded-lg bg-card p-4 shadow-[0_12px_32px_-8px_rgba(26,32,51,0.28)]"
        >
          <div className="flex items-center gap-2">
            <div className="text-sm font-semibold">Run history</div>
            <button
              onClick={() => setOpen(false)} aria-label="Close history"
              className="ml-auto inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-background"
            >
              <X className="h-[15px] w-[15px]" aria-hidden />
            </button>
          </div>

          {totals && totals.runCount > 0 && (
            <p className="mt-1 text-[11.5px] tabular-nums text-muted-foreground">
              {totals.runCount} run(s) · {totals.findingCount} finding(s) ·{" "}
              {totals.linesParsed.toLocaleString()} lines parsed across all runs
            </p>
          )}

          <ul aria-label="saved runs" className="mt-3 flex max-h-[min(420px,60vh)] flex-col gap-1.5 overflow-auto">
            {rows.length === 0 && (
              <li className="py-2 text-[12.5px] text-muted-foreground">
                No saved runs yet — analyze a log to start the history.
              </li>
            )}
            {rows.map((r) => {
              const isCurrent = !!current && r.file === current;
              if (r.unreadable) {
                return (
                  <li key={r.file}
                      className="rounded-md border border-dashed px-3 py-2 text-[12px] text-muted-foreground"
                      title="This history file could not be read — shown rather than hidden">
                    <span className="font-mono">{r.file}</span> — unreadable
                  </li>
                );
              }
              return (
                <li key={r.file}>
                  <button
                    onClick={() => !isCurrent && switchTo(r.file)}
                    disabled={isCurrent || switching !== null}
                    data-testid="run-row"
                    title={isCurrent
                      ? "This run is open now"
                      : `Open this run — the dashboard switches to it (${r.file})`}
                    className={cn(
                      "w-full rounded-md border px-3 py-2 text-left text-[12.5px]",
                      isCurrent
                        ? "cursor-default border-primary bg-accent"
                        : "hover:border-primary hover:bg-background",
                      switching === r.file && "opacity-60",
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span className="min-w-0 truncate font-mono font-semibold"
                            title={r.sourceLabel || r.file}>
                        {(r.sourceLabel || r.file).split("/").pop()}
                      </span>
                      {isCurrent && (
                        <span className="rounded border border-primary px-1.5 py-px text-[9.5px] font-medium uppercase tracking-wide text-accent-foreground">
                          current
                        </span>
                      )}
                      {r.unrecognized && (
                        <span className="rounded border px-1.5 py-px text-[9.5px] uppercase tracking-wide text-muted-foreground"
                              title="Format not recognized — 0 lines parsed">
                          unparsed
                        </span>
                      )}
                      <span className="ml-auto whitespace-nowrap tabular-nums text-muted-foreground">
                        {r.findingCount ?? 0} finding(s)
                      </span>
                    </span>
                    <span className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
                      <span className="font-mono">{(r.generatedAt || "").slice(0, 16).replace("T", " ")}</span>
                      {r.dataComplete !== false ? (
                        <span className="ml-auto flex items-center gap-1.5">
                          {SEV_ORDER.map((b) => {
                            const n = r.severityCounts?.[b] ?? 0;
                            return n > 0 ? (
                              <span key={b} className="flex items-center gap-1 tabular-nums">
                                <i className="h-2 w-2 rounded-full" style={{ background: sevVar(b) }} />
                                {n}
                              </span>
                            ) : null;
                          })}
                        </span>
                      ) : (
                        <span className="ml-auto"
                              title="This run predates stored severity counts — zeros are not guessed">
                          counts unavailable
                        </span>
                      )}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>

          {rows.filter((r) => !r.unreadable).length === 1 && (
            <p className="mt-2 text-[11.5px] text-muted-foreground">
              Only one run so far — analyze more logs to build a history.
            </p>
          )}
          {note && <p className="mt-2 text-[11.5px] text-muted-foreground" role="status">{note}</p>}
        </section>
      )}
    </div>
  );
}
