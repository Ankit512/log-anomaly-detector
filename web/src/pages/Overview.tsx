import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowDown, ArrowUp } from "lucide-react";
import { api, type Delta, type OverviewData } from "@/lib/api";
import { sevVar } from "@/lib/severity";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { AlertsOverTime } from "@/components/charts/AlertsOverTime";
import { TacticBars } from "@/components/charts/TacticBars";
import { AiAnalyst } from "@/components/AiAnalyst";
import { IngestionPanel } from "@/components/IngestionPanel";
import { SeverityBadge } from "@/components/ui/badge";
import { Link } from "react-router-dom";
import { useUi } from "@/store/ui";

function KpiCard({ label, count, delta, color }:
  { label: string; count: number; delta: Delta | null; color: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <i className="h-2 w-2 rounded-full" style={{ background: color }} />
          {label}
        </div>
        <div className="mt-0.5 text-[26px] font-semibold tabular-nums">{count.toLocaleString()}</div>
        {/* A delta renders ONLY when a prior period exists; null means "no
            honest base to compare against" and shows nothing. Up is worse. */}
        {delta && (
          <div className="flex items-center gap-1 text-[11px]"
               style={{ color: delta.dir === "up" ? "var(--sev-critical)" : "var(--sev-low)" }}>
            {delta.dir === "up" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />}
            {delta.pct}% vs previous
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Overview() {
  const { data, isLoading, error } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  const setTimeWindow = useUi((s) => s.setTimeWindow);

  const overview = data && !("error" in data) ? (data as OverviewData) : null;
  useEffect(() => {
    if (overview?.timeWindowLabel) setTimeWindow(overview.timeWindowLabel);
  }, [overview?.timeWindowLabel, setTimeWindow]);

  if (isLoading) return <p className="text-muted-foreground">Loading the current run…</p>;
  if (error) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          The console backend is not reachable. Start it with
          <code className="mx-1 rounded bg-muted px-1.5 py-0.5 font-mono">python3 console/serve.py</code>
          — nothing is shown here rather than sample numbers.
        </CardContent>
      </Card>
    );
  }
  if (!overview) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          {(data as { error: string } | undefined)?.error ?? "No run yet"} — analyze a log
          first (open <Link className="text-primary underline" to="/alerts">Alerts</Link> or
          upload below). No sample data is shown in its place.
        </CardContent>
      </Card>
    );
  }

  const k = overview.kpis;
  return (
    <div className="flex flex-wrap items-start gap-5">
      <div className="min-w-0 flex-1 space-y-5">
        <div className="grid grid-cols-2 gap-3.5 md:grid-cols-3 xl:grid-cols-5">
          <KpiCard label="Total Alerts" count={k.total} delta={k.deltas.total} color="hsl(var(--primary))" />
          <KpiCard label="Critical" count={k.critical} delta={k.deltas.critical} color={sevVar("CRITICAL")} />
          <KpiCard label="High" count={k.high} delta={k.deltas.high} color={sevVar("HIGH")} />
          <KpiCard label="Medium" count={k.medium} delta={k.deltas.medium} color={sevVar("MEDIUM")} />
          <KpiCard label="Low" count={k.low} delta={k.deltas.low} color={sevVar("LOW")} />
        </div>

        <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          <Card>
            <CardHeader><CardTitle>Alerts by Severity</CardTitle></CardHeader>
            <CardContent><SeverityDonut data={overview.severityDonut} /></CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Alerts Over Time</CardTitle></CardHeader>
            <CardContent><AlertsOverTime data={overview.alertsOverTime} /></CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>
                Top Attack Tactics (MITRE){" "}
                <span className="font-normal text-muted-foreground">derived tags — not verdicts</span>
              </CardTitle>
            </CardHeader>
            <CardContent><TacticBars data={overview.mitreTactics} /></CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>
              Latest Alerts{" "}
              <span className="font-normal text-muted-foreground">
                most recent first · drill into Alerts for evidence
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="border-b text-left text-[10.5px] uppercase tracking-wide text-muted-foreground">
                  <th className="px-2 py-2">Time</th><th className="px-2 py-2">Severity</th>
                  <th className="px-2 py-2">Attacker Status</th><th className="px-2 py-2">Primary MITRE Tactics</th>
                  <th className="px-2 py-2">Alert</th><th className="px-2 py-2">Source</th>
                  <th className="px-2 py-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {overview.latestAlerts.length === 0 && (
                  <tr><td colSpan={7} className="px-2 py-4 text-muted-foreground">
                    No alerts in this window.</td></tr>
                )}
                {overview.latestAlerts.map((a) => (
                  <tr key={a.id} className="border-b last:border-0 align-top">
                    <td className="whitespace-nowrap px-2 py-2 font-mono text-[11.5px] text-muted-foreground">{a.time}</td>
                    <td className="px-2 py-2"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-2 py-2">
                      <span className="whitespace-nowrap rounded border bg-muted px-2 py-0.5 text-[11px] text-muted-foreground"
                            title="Derived kill-chain grouping of this alert's MITRE tactics — a display aid, not a verdict">
                        {a.attackerStatus || "—"}
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      {a.tactics.length
                        ? a.tactics.map((t) => (
                            <span key={t} className="mb-0.5 mr-1 inline-block rounded bg-accent px-1.5 py-0.5 text-[10.5px] text-accent-foreground">{t}</span>
                          ))
                        : "—"}
                    </td>
                    <td className="px-2 py-2">{a.name}</td>
                    <td className="px-2 py-2 font-mono text-[11.5px] text-muted-foreground">{a.source || "—"}</td>
                    <td className="px-2 py-2">
                      <Link to={`/alerts?sel=${encodeURIComponent(a.id)}`} className="text-primary hover:underline">
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>

        <Card className="border-dashed">
          <CardContent className="p-4 text-[12.5px] text-muted-foreground">
            <b className="text-foreground">Operational metrics — coming soon.</b>{" "}
            Open incidents, MTTD, MTTR and asset/user risk need incident-tracking
            subsystems that do not exist yet, so nothing is shown here rather than
            an invented number.
          </CardContent>
        </Card>
      </div>

      <div className="w-full space-y-5 xl:w-80 xl:flex-none">
        <AiAnalyst model={overview.model} />
        <IngestionPanel ingestion={overview.ingestion} />
      </div>
    </div>
  );
}
