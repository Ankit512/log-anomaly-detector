import { scaleLinear } from "@visx/scale";
import { sevVar, SEV_ORDER } from "@/lib/severity";
import type { OverviewData } from "@/lib/api";

const KEYS = ["low", "medium", "high", "critical"] as const; // bottom -> top

/** Stacked bars per time bin. 2px gaps between segments and bars; every
 *  segment carries a <title> tooltip with its exact count. */
export function AlertsOverTime({ data }: { data: OverviewData["alertsOverTime"] }) {
  const bins = data.bins;
  if (!bins.length) {
    return <p className="py-4 text-muted-foreground">No alerts in this window.</p>;
  }
  const W = 320, H = 110;
  const max = Math.max(1, ...bins.map((b) => KEYS.reduce((s, k) => s + b[k], 0)));
  const y = scaleLinear({ domain: [0, max], range: [0, H - 6] });
  const bw = W / bins.length;

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[110px] w-full" preserveAspectRatio="none"
           role="img" aria-label="alerts over time" data-testid="chart-overtime">
        {bins.map((b, i) => {
          let yPos = H;
          return KEYS.map((k) => {
            const v = b[k];
            if (!v) return null;
            const h = y(v);
            yPos -= h;
            return (
              <rect
                key={`${b.t}-${k}`}
                x={(i * bw + 3).toFixed(1)}
                y={yPos.toFixed(1)}
                width={(bw - 6).toFixed(1)}
                height={Math.max(1.5, h - 2).toFixed(1)}
                rx="1.5"
                style={{ fill: sevVar(k) }}
              >
                <title>{`${b.t.slice(11, 16)} — ${k}: ${v}`}</title>
              </rect>
            );
          });
        })}
      </svg>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-muted-foreground">
        <span>{bins[0].t.slice(11, 16)}</span>
        <span>peak bin {max}</span>
        <span>{bins[bins.length - 1].t.slice(11, 16)}</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted-foreground">
        {SEV_ORDER.map((s) => (
          <span key={s} className="flex items-center gap-1.5">
            <i className="h-2 w-2 rounded-sm" style={{ background: sevVar(s) }} />
            {s.toLowerCase()}
          </span>
        ))}
      </div>
    </div>
  );
}
