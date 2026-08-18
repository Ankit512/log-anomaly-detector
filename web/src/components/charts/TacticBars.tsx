import { scaleLinear } from "@visx/scale";
import type { OverviewData } from "@/lib/api";

/** Ranked MITRE tactics, single primary hue — magnitude is bar length,
 *  identity is the row label, and the count always renders as text. */
export function TacticBars({ data }: { data: OverviewData["mitreTactics"] }) {
  if (!data.length) {
    return (
      <p className="py-4 text-muted-foreground">
        No tactic data — nothing mapped in this window.
      </p>
    );
  }
  const max = Math.max(1, ...data.map((d) => d.count));
  const x = scaleLinear({ domain: [0, max], range: [0, 100] });
  return (
    <ul className="space-y-2" aria-label="top attack tactics">
      {data.map((d) => (
        <li key={d.tactic} className="flex items-center gap-2.5 text-xs">
          <span className="w-40 flex-none truncate text-muted-foreground" title={d.tactic}>
            {d.tactic}
          </span>
          <svg viewBox="0 0 100 14" preserveAspectRatio="none" className="h-3.5 flex-1"
               role="img" aria-label={`${d.tactic}: ${d.count}`} data-testid="chart-tactic">
            <rect x="0" y="3" width={Math.max(1.5, x(d.count)).toFixed(1)} height="8" rx="2"
                  style={{ fill: "hsl(var(--primary))" }} />
          </svg>
          <b className="min-w-7 text-right tabular-nums">{d.count}</b>
        </li>
      ))}
    </ul>
  );
}
