import type { OverviewData } from "@/lib/api";

/** v6 tactic bars: fixed-width label, an accent bar scaled to the top count,
 *  and the count as text. Rules that map to no tactic are simply absent from
 *  the input — never bucketed into a guess. */
export function TacticBars({ data }: { data: OverviewData["mitreTactics"] }) {
  if (data.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        No MITRE-mapped findings in this run. Unmapped rules are absent rather
        than bucketed.
      </p>
    );
  }
  const max = Math.max(...data.map((t) => t.count), 1);

  return (
    <div>
      <ul aria-label="top attack tactics" className="flex flex-col gap-[11px]">
        {data.map((t) => (
          <li key={t.tactic} className="flex items-center gap-[11px] text-[13px]">
            <span title={t.tactic}
                  className="w-[132px] flex-none overflow-hidden text-ellipsis whitespace-nowrap text-muted-foreground">
              {t.tactic}
            </span>
            <svg
              data-testid="chart-tactic" viewBox="0 0 100 14" preserveAspectRatio="none"
              role="img" aria-label={`${t.tactic}: ${t.count}`} className="block h-3.5 flex-1"
            >
              <rect x="0" y="2" width={(t.count / max) * 100} height="10" rx="2"
                    style={{ fill: "hsl(var(--primary))" }} />
            </svg>
            <b className="min-w-[26px] flex-none text-right tabular-nums">{t.count}</b>
          </li>
        ))}
      </ul>
      <p className="mt-3.5 text-[11.5px] leading-normal text-muted-foreground">
        Counts are technique tags summed per tactic. A finding whose rule maps
        to no tactic is absent here rather than bucketed.
      </p>
    </div>
  );
}
