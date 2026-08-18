import type { OverviewData } from "@/lib/api";
import { sevVar } from "@/lib/severity";

/** The v6 donut: thick stroked arcs carrying their own count and percent,
 *  total in the center, and a text legend beside it — color is never the only
 *  signal. All colors go through `style`/props, never SVG attributes with
 *  var() (invalid there; renders black). */
export function SeverityDonut({ data }: { data: OverviewData["severityDonut"] }) {
  const total = data.reduce((n, d) => n + d.count, 0);
  const R = 44, C = 2 * Math.PI * R;

  let off = 0;
  const segs = data.filter((d) => d.count > 0).map((d) => {
    const frac = d.count / total;
    // Mid-arc angle measured from 12 o'clock, like the -90° stroke rotation.
    const mid = (off + frac / 2) * 2 * Math.PI - Math.PI / 2;
    const seg = {
      ...d,
      stroke: sevVar(d.bucket),
      dash: `${(frac * C - 2).toFixed(1)} ${(C - frac * C + 2).toFixed(1)}`,
      offset: (-off * C).toFixed(1),
      lx: (60 + R * Math.cos(mid)).toFixed(1),
      ly: (60 + R * Math.sin(mid) + 1).toFixed(1),
      ly2: (60 + R * Math.sin(mid) + 8).toFixed(1),
    };
    off += frac;
    return seg;
  });

  if (total === 0) {
    return <p className="text-xs text-muted-foreground">No findings in this run.</p>;
  }

  return (
    <div className="flex items-center gap-3.5">
      <svg
        data-testid="chart-donut" width="118" height="118" viewBox="0 0 120 120"
        className="flex-none" role="img"
        aria-label={`alerts by severity: ${segs.map((s) => `${s.count} ${s.bucket.toLowerCase()}`).join(", ")}`}
      >
        {segs.map((s) => (
          <circle
            key={s.bucket} r={R} cx="60" cy="60" fill="none" strokeWidth="26"
            style={{ stroke: s.stroke }} strokeDasharray={s.dash}
            strokeDashoffset={s.offset} transform="rotate(-90 60 60)"
          />
        ))}
        {segs.map((s) => (
          <g key={`label-${s.bucket}`}>
            <text x={s.lx} y={s.ly} textAnchor="middle" fontSize="8.5" fontWeight="700" style={{ fill: "#fff" }}>
              {s.count}
            </text>
            <text x={s.lx} y={s.ly2} textAnchor="middle" fontSize="6" style={{ fill: "#fff" }}>
              ({s.pct}%)
            </text>
          </g>
        ))}
        <text x="60" y="59" textAnchor="middle" fontSize="19" fontWeight="700" style={{ fill: "currentColor" }}>
          {total}
        </text>
        <text x="60" y="71" textAnchor="middle" fontSize="7.5" className="fill-muted-foreground">
          Total
        </text>
      </svg>
      <ul aria-label="severity legend" className="flex min-w-0 flex-1 flex-col gap-[7px] text-xs">
        {data.map((d) => (
          <li key={d.bucket} className="flex items-center gap-[7px]">
            <i className="h-2.5 w-2.5 flex-none rounded-full" style={{ background: sevVar(d.bucket) }} />
            <span className="font-semibold">{d.bucket.charAt(0) + d.bucket.slice(1).toLowerCase()}</span>
            <span className="ml-auto whitespace-nowrap tabular-nums text-muted-foreground">
              {d.count} ({d.pct}%)
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
