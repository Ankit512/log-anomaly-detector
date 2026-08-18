import { Pie } from "@visx/shape";
import { Group } from "@visx/group";
import { sevVar } from "@/lib/severity";
import type { OverviewData } from "@/lib/api";

/** Donut of alerts by severity. Counts and percents always render as text in
 *  the legend — color is identity support, never the only signal. */
export function SeverityDonut({ data }: { data: OverviewData["severityDonut"] }) {
  const rows = data.filter((d) => d.count > 0);
  const total = data.reduce((s, d) => s + d.count, 0);
  if (!total) {
    return <p className="py-4 text-muted-foreground">No alerts in this window.</p>;
  }
  const size = 130, r = size / 2;
  return (
    <div className="flex flex-wrap items-center gap-5">
      <svg width={size} height={size} role="img" aria-label="alerts by severity"
           data-testid="chart-donut">
        <Group top={r} left={r}>
          <Pie
            data={rows}
            pieValue={(d) => d.count}
            outerRadius={r - 2}
            innerRadius={r - 16}
            padAngle={0.035}
          >
            {(pie) =>
              pie.arcs.map((arc) => (
                <path
                  key={arc.data.bucket}
                  d={pie.path(arc) ?? undefined}
                  style={{ fill: sevVar(arc.data.bucket) }}
                >
                  <title>{`${arc.data.bucket} — ${arc.data.count} (${arc.data.pct}%)`}</title>
                </path>
              ))
            }
          </Pie>
          <text textAnchor="middle" dy="-1" className="fill-foreground text-[22px] font-semibold">
            {total}
          </text>
          <text textAnchor="middle" dy="15" className="fill-muted-foreground text-[8.5px] tracking-widest">
            TOTAL
          </text>
        </Group>
      </svg>
      <ul className="min-w-36 space-y-1.5 text-xs" aria-label="severity legend">
        {data.map((d) => (
          <li key={d.bucket} className="flex items-center gap-2">
            <i className="h-2.5 w-2.5 flex-none rounded-sm" style={{ background: sevVar(d.bucket) }} />
            {d.bucket}
            <span className="text-muted-foreground">{d.pct}%</span>
            <b className="ml-auto tabular-nums">{d.count}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}
