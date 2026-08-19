import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, TriangleAlert, X } from "lucide-react";
import { api } from "@/lib/api";
import { useJobs } from "@/store/jobs";

/** The persistent, shell-level upload notification. It reads the job store
 *  (not any page's state), so it stays put across navigation and keeps showing
 *  live progress while the user is on another page. On completion it offers a
 *  click-to-view that switches the whole dashboard to the finished run.
 *  Honest: the bar renders only when the backend reports done/total, and
 *  errors show the job's own message. */
export function IngestNotifier() {
  const current = useJobs((s) => s.current);
  const dismiss = useJobs((s) => s.dismiss);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [elapsed, setElapsed] = useState(0);

  const active = current && current.kind !== "done" && current.kind !== "error";

  // An honest elapsed readout while the analysis is in flight.
  useEffect(() => {
    if (!active || !current) return;
    setElapsed(Math.floor((Date.now() - current.startedAt) / 1000));
    const t = setInterval(
      () => setElapsed(Math.floor((Date.now() - current.startedAt) / 1000)), 1000);
    return () => clearInterval(t);
  }, [active, current?.id, current?.startedAt]);

  // When a run finishes, refresh the dashboard queries so a viewer already on
  // the Overview sees the new run without a manual refresh.
  useEffect(() => {
    if (current?.kind === "done") queryClient.invalidateQueries();
  }, [current?.id, current?.kind, queryClient]);

  if (!current || current.seen) return null;

  const viewRun = async () => {
    if (current.runFile) {
      await api.openRun(current.runFile).catch(() => {});
      await queryClient.invalidateQueries();
    }
    dismiss();
    navigate("/");
  };

  const job = current.job;
  const total = job?.total ?? 0;
  const done = job?.done ?? 0;
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : null;

  // An unrecognized/empty run finished, but parsed nothing — a warning tone,
  // never the green "success" check that would read as an all-clear.
  const tone =
    current.kind === "error" ? "var(--sev-critical)"
    : current.kind === "done" ? (current.unrecognized ? "var(--sev-medium)" : "var(--sev-low)")
    : "hsl(var(--primary))";

  return (
    <div
      role="status" aria-live="polite" aria-label="Upload notification"
      className="fixed bottom-[22px] left-[22px] z-50 w-[320px] max-w-[calc(100vw-40px)] rounded-lg bg-card p-3.5 shadow-[0_12px_32px_-8px_rgba(26,32,51,0.28)]"
    >
      <div className="flex items-start gap-2.5">
        <span className="mt-px flex-none" style={{ color: tone }}>
          {current.kind === "done"
            ? (current.unrecognized ? <TriangleAlert className="h-[18px] w-[18px]" />
                                     : <CheckCircle2 className="h-[18px] w-[18px]" />)
            : current.kind === "error" ? <TriangleAlert className="h-[18px] w-[18px]" />
            : <Loader2 className="h-[18px] w-[18px] animate-spin" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="min-w-0 truncate font-mono text-[12.5px] font-semibold" title={current.file}>
              {current.file}
            </span>
            <button
              onClick={dismiss} aria-label="Dismiss notification"
              className="ml-auto inline-flex h-5 w-5 flex-none items-center justify-center rounded text-muted-foreground hover:bg-background"
            >
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>

          {current.kind === "done" ? (
            <>
              <p className="mt-1 text-[11.5px] text-muted-foreground">{current.message}</p>
              <button
                onClick={viewRun}
                className="mt-2 rounded-md border border-primary bg-accent px-2.5 py-1 text-[11.5px] font-semibold text-accent-foreground hover:opacity-90"
              >
                View run
              </button>
            </>
          ) : current.kind === "error" ? (
            <p className="mt-1 text-[11.5px]"
               style={{ color: "var(--sev-critical)" }}>{current.message}</p>
          ) : (
            <div className="mt-1.5">
              <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
                <span>{current.kind === "uploading" ? "uploading…" : `${job?.phase ?? "working"}…`}</span>
                <span className="ml-auto tabular-nums">{elapsed}s</span>
              </div>
              {pct !== null && (
                <div className="mt-1.5 flex items-center gap-2">
                  <span
                    role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}
                    aria-label="analysis progress"
                    className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted"
                  >
                    <span className="block h-full rounded-full"
                          style={{ width: `${pct}%`, background: "hsl(var(--primary))" }} />
                  </span>
                  <span className="tabular-nums text-[11px] text-muted-foreground">{done}/{total}</span>
                </div>
              )}
              {job?.note && <p className="mt-1 text-[11px] text-muted-foreground">{job.note}</p>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
