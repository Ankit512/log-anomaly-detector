import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, INCIDENT_STATES, type Incident, type IncidentState } from "@/lib/api";
import { SeverityBadge, Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** The lifecycle order is fixed (docs/soc_subsystems.md): new → acknowledged →
 *  investigating → resolved. Moving backwards is allowed (a mistaken resolve
 *  can be reopened); the backend never erases a timestamp already earned. */
const STATE_STYLE: Record<IncidentState, string> = {
  new: "border-border text-muted-foreground",
  acknowledged: "border-[color:var(--sev-medium)] text-[color:var(--sev-medium)]",
  investigating: "border-[color:var(--sev-high)] text-[color:var(--sev-high)]",
  resolved: "border-[color:var(--sev-low)] text-[color:var(--sev-low)]",
};

function StateBadge({ state }: { state: IncidentState }) {
  return <Badge className={cn("capitalize", STATE_STYLE[state])}>{state}</Badge>;
}

const th = "px-2 py-2 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground";

function IncidentDetail({ inc }: { inc: Incident }) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: (state: IncidentState) => api.setIncidentState(inc.id, state),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });

  const facts: [string, string | null][] = [
    ["Detected (earliest finding)", inc.createdAt],
    ["First seen", inc.firstSeen],
    ["Last seen", inc.lastSeen],
    ["Acknowledged", inc.acknowledgedAt],
    ["Resolved", inc.resolvedAt],
  ];

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={inc.severity} />
          <StateBadge state={inc.state} />
          <span className="font-mono text-[11px] text-muted-foreground">{inc.entityKind}</span>
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">{inc.id}</span>
        </div>
        <CardTitle className="text-[16px] leading-snug">{inc.title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border p-3">
          <div className="text-[9.5px] uppercase tracking-wide text-muted-foreground">
            Lifecycle · analyst-owned
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {INCIDENT_STATES.map((s) => (
              <Button
                key={s}
                size="sm"
                variant={s === inc.state ? "default" : "outline"}
                disabled={s === inc.state || mutation.isPending}
                onClick={() => mutation.mutate(s)}
                className="capitalize"
                title={s === inc.state ? "Current state" : `Move to ${s}`}
              >
                {s}
              </Button>
            ))}
          </div>
          {mutation.isError && (
            <p className="mt-2 text-[11.5px]" style={{ color: "var(--sev-critical)" }}>
              {(mutation.error as Error).message}
            </p>
          )}
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-md border p-3">
            <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
              Timestamps · from the log, not wall-clock
            </div>
            {facts.map(([label, val]) => (
              <div key={label} className="flex justify-between gap-3 py-0.5 text-xs">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-mono text-[11px]">{val ?? "n/a"}</span>
              </div>
            ))}
            {inc.timeUncertain && (
              <p className="mt-1.5 text-[11px] text-muted-foreground">
                A member finding had no timestamp — it joined this cluster's first group.
              </p>
            )}
          </div>

          <div className="rounded-md border p-3">
            <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
              MITRE techniques · derived tags, not verdicts
            </div>
            {inc.techniques.length ? (
              <div className="flex flex-wrap gap-1.5">
                {inc.techniques.map((t) => (
                  <span key={t.id}
                    className="rounded bg-accent px-1.5 py-0.5 text-[10.5px] text-accent-foreground"
                    title={`${t.id} · ${t.name} · ${t.tactic} — derived, does not affect severity`}>
                    {t.id}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-[11.5px] text-muted-foreground">No techniques mapped.</p>
            )}
            {inc.attackerStatus && (
              <div className="mt-2 text-[11.5px]">
                <span className="text-muted-foreground">Kill-chain phase: </span>
                <span title="Derived grouping of member tactics — a display aid, not a verdict">
                  {inc.attackerStatus}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="rounded-md border p-3">
          <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
            {inc.findingCount} correlated finding(s)
          </div>
          <div className="flex flex-wrap gap-1.5">
            {inc.findingIds.map((fid) => (
              <a key={fid} href={`/alerts?sel=${encodeURIComponent(fid)}`}
                className="rounded border px-1.5 py-0.5 font-mono text-[10.5px] hover:bg-muted"
                title="Open this finding in Alerts">
                {fid}
              </a>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function Incidents() {
  const [params, setParams] = useSearchParams();
  const [stateFilter, setStateFilter] = useState<IncidentState | "">("");
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["incidents", stateFilter],
    queryFn: () => api.incidents(stateFilter || undefined),
    refetchInterval: 5000,
  });

  const incidents = data?.incidents ?? [];
  const selId = params.get("sel");
  const selected = incidents.find((i) => i.id === selId) ?? null;

  if (isLoading) return <p className="text-muted-foreground">Loading incidents…</p>;

  if (isError) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          Couldn't load incidents — {(error as Error).message}
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select
          className="h-9 rounded-md border border-input bg-card px-2 text-sm"
          aria-label="Lifecycle filter"
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value as IncidentState | "")}
        >
          <option value="">All states</option>
          {INCIDENT_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="text-xs text-muted-foreground">
          {incidents.length} incident(s){stateFilter && ` · ${stateFilter}`} · correlated clusters of real findings
        </span>
      </div>

      {incidents.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="p-6 text-[12.5px] text-muted-foreground">
            {stateFilter
              ? `No incidents in the "${stateFilter}" state.`
              : "No incidents yet — an incident is a correlated cluster of the current run's findings. Analyze a log with findings and they'll appear here."}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <div className="overflow-auto">
            <table className="w-full">
              <thead className="bg-card">
                <tr className="border-b">
                  <th className={th}>Severity</th>
                  <th className={th}>State</th>
                  <th className={th}>Entity</th>
                  <th className={th}>Findings</th>
                  <th className={th}>Detected</th>
                  <th className={th}>Phase</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    data-testid="incident-row"
                    onClick={() => setParams({ sel: inc.id })}
                    className={cn(
                      "cursor-pointer border-b last:border-0 align-top hover:bg-muted/60",
                      selected?.id === inc.id && "bg-accent/60",
                    )}
                  >
                    <td className="px-2 py-2"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-2 py-2"><StateBadge state={inc.state} /></td>
                    <td className="px-2 py-2 font-mono text-[11.5px]">{inc.entity}</td>
                    <td className="px-2 py-2 tabular-nums text-[12.5px]">{inc.findingCount}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">
                      {inc.createdAt ?? "n/a"}
                    </td>
                    <td className="px-2 py-2 text-[12.5px] text-muted-foreground">
                      {inc.attackerStatus || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {selected && <IncidentDetail inc={selected} />}
    </div>
  );
}
