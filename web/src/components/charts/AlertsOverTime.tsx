import type { OverviewData } from "@/lib/api";
import { SEV_ORDER, sevVar } from "@/lib/severity";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function dayLabel(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso.slice(0, 10) : `${String(d.getUTCDate()).padStart(2, "0")} ${MONTHS[d.getUTCMonth()]}`;
}

/** The v6 time chart: one flex column per hourly bin from the backend, each a
 *  bottom-up stack of severity segments, over three gridlines. The axis spans
 *  exactly the run's own bins — no invented empty range. */
export function AlertsOverTime({ data }: { data: OverviewData["alertsOverTime"] }) {
  const bins = data.bins;
  if (bins.length === 0) {
    return <p className="text-xs text-muted-foreground">No timestamped findings in this run.</p>;
  }

  const totals = bins.map((b) => b.critical + b.high + b.medium + b.low);
  const max = Math.max(...totals, 1);
  // Columns render CRITICAL-first, so the worst bucket tops the stack; the
  // legend reads bottom-to-top to match.
  const legendOrder = [...SEV_ORDER].reverse();

  const labels = [...new Set([0, Math.floor((bins.length - 1) / 2), bins.length - 1])]
    .map((i) => dayLabel(bins[i].t));

  return (
    <div>
      <div className="flex gap-[9px]">
        <div className="flex h-[168px] flex-col justify-between text-[11px] tabular-nums text-muted-foreground">
          <span>{max}</span><span>{Math.round(max / 2)}</span><span>0</span>
        </div>
        <div className="relative h-[168px] min-w-0 flex-1">
          <div className="absolute inset-x-0 top-0 border-t" />
          <div className="absolute inset-x-0 top-1/2 border-t" />
          <div className="absolute inset-x-0 bottom-0 border-t" />
          <div
            data-testid="chart-overtime" role="img" aria-label="alerts over time"
            className="absolute inset-0 flex items-end"
          >
            {bins.map((b) => (
              <div
                key={b.t}
                title={`${b.t} — ${SEV_ORDER.filter((s) => b[s.toLowerCase() as "low"] > 0)
                  .map((s) => `${s.toLowerCase()}: ${b[s.toLowerCase() as "low"]}`).join(", ") || "0"}`}
                className="flex h-full min-w-0 flex-1 flex-col justify-end px-0.5"
              >
                {SEV_ORDER.map((sev) => {
                  const n = b[sev.toLowerCase() as "critical" | "high" | "medium" | "low"];
                  return n > 0 ? (
                    <div
                      key={sev}
                      className="w-full first:rounded-t-sm"
                      style={{ height: `${(n / max) * 100}%`, background: sevVar(sev) }}
                    />
                  ) : null;
                })}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="mt-[7px] flex justify-between pl-5 text-[11.5px] text-muted-foreground">
        {labels.map((l, i) => <span key={`${l}-${i}`}>{l}</span>)}
      </div>
      <div className="mt-3.5 flex flex-wrap justify-center gap-x-[18px] gap-y-1 text-[12.5px] text-muted-foreground">
        {legendOrder.map((sev) => (
          <span key={sev} className="flex items-center gap-[7px]">
            <i className="h-2.5 w-2.5 flex-none rounded-full" style={{ background: sevVar(sev) }} />
            {sev.charAt(0) + sev.slice(1).toLowerCase()}
          </span>
        ))}
      </div>
    </div>
  );
}
