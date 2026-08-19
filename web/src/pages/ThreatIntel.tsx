import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const th = "px-2 py-2 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground";

export function ThreatIntel() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["threat-intel"],
    queryFn: api.threatIntel,
  });

  if (isLoading) return <p className="text-muted-foreground">Loading threat intel…</p>;

  if (isError || !data) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          Couldn't load threat intel — {(error as Error)?.message ?? "no data"}
        </CardContent>
      </Card>
    );
  }

  const ruleEntries = Object.entries(data.ruleTechniques);

  return (
    <div className="space-y-4">
      {/* Honest provenance line: this page surfaces what threat_intel/ already
          holds and what the rules statically map — no new intel is created. */}
      <Card className="border-dashed">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground">
          <b className="text-foreground">Surfaced, not generated.</b>{" "}
          Indicators come from an offline STIX bundle; the technique rollups are the
          static MITRE mapping each rule carries. These are <b>derived tags — not verdicts</b>,
          and nothing here changes a finding's severity.
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-[15px]">Indicators of Compromise</CardTitle>
            <p className="text-[11.5px] text-muted-foreground">
              {data.indicatorSource}
            </p>
          </CardHeader>
          <CardContent className="pt-0">
            {data.indicators.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground">
                The bundle holds no indicators.
              </p>
            ) : (
              <div className="overflow-auto rounded-md border">
                <table className="w-full">
                  <thead className="bg-card">
                    <tr className="border-b">
                      <th className={th}>Name</th>
                      <th className={th}>Pattern</th>
                      <th className={th}>Types</th>
                      <th className={th}>Valid from</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.indicators.map((ind) => (
                      <tr key={ind.id} data-testid="ioc-row" className="border-b last:border-0 align-top">
                        <td className="px-2 py-2 text-[12.5px]">{ind.name}</td>
                        <td className="px-2 py-2 font-mono text-[11px] text-accent-foreground break-all">
                          {ind.pattern}
                        </td>
                        <td className="px-2 py-2 text-[11.5px] text-muted-foreground">
                          {ind.types.join(", ") || "—"}
                        </td>
                        <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">
                          {ind.validFrom || "n/a"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-[15px]">Rule → MITRE technique map</CardTitle>
            <p className="text-[11.5px] text-muted-foreground">
              static mapping each detector rule carries — derived, not verdicts
            </p>
          </CardHeader>
          <CardContent className="space-y-3 pt-0">
            {ruleEntries.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground">No rule mappings available.</p>
            ) : (
              ruleEntries.map(([rule, techniques]) => (
                <div key={rule} className="rounded-md border p-3">
                  <div className="font-mono text-[12px] font-semibold">{rule}</div>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {techniques.map((t) => (
                      <span key={t.id}
                        className="rounded bg-accent px-1.5 py-0.5 text-[10.5px] text-accent-foreground"
                        title={`${t.id} · ${t.name} · ${t.tactic}`}>
                        {t.id} · {t.name}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-4 text-[12.5px]">
          <span className="text-muted-foreground">MITRE ATT&amp;CK offline cache:</span>
          <span
            className="rounded-full border px-2.5 py-0.5 text-[11px] font-semibold"
            style={{
              borderColor: data.attackCacheWarm ? "var(--sev-low)" : "var(--sev-medium)",
              color: data.attackCacheWarm ? "var(--sev-low)" : "var(--sev-medium)",
            }}
            title="~/.cache/mitre_attack — populated once the ATT&CK dataset has been fetched"
          >
            {data.attackCacheWarm ? "warm" : "cold — technique names come from the static map only"}
          </span>
        </CardContent>
      </Card>
    </div>
  );
}
