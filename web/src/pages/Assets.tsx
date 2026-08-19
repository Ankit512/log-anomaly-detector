import { useQuery } from "@tanstack/react-query";
import { api, type Asset, type UserEntity } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const th = "px-2 py-2 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground";

/** Both endpoints return {error} (HTTP 200) when the server is idle. We treat
 *  that as the honest "no run" state, distinct from "a run exists but observed
 *  no assets/users" — never conflate them into a fake-empty inventory. */
function hasError(v: unknown): v is { error: string } {
  return !!v && typeof v === "object" && "error" in v;
}

function RiskBadge({ atRisk }: { atRisk: boolean }) {
  return atRisk ? (
    <Badge style={{ borderColor: "var(--sev-high)", color: "var(--sev-high)" }}>at risk</Badge>
  ) : (
    <Badge className="border-border text-muted-foreground">clean</Badge>
  );
}

function AssetsTable({ assets }: { assets: Asset[] }) {
  return (
    <div className="overflow-auto rounded-md border">
      <table className="w-full">
        <thead className="bg-card">
          <tr className="border-b">
            <th className={th}>Asset</th>
            <th className={th}>Kind</th>
            <th className={th}>Events</th>
            <th className={th}>Findings</th>
            <th className={th}>Risk</th>
            <th className={th}>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.id} data-testid="asset-row" className="border-b last:border-0 align-top hover:bg-muted/60">
              <td className="px-2 py-2 font-mono text-[12px]">{a.name}</td>
              <td className="px-2 py-2 text-[11.5px] uppercase text-muted-foreground">{a.kind}</td>
              <td className="px-2 py-2 tabular-nums text-[12.5px]">{a.events}</td>
              <td className="px-2 py-2 tabular-nums text-[12.5px]">{a.findings}</td>
              <td className="px-2 py-2"><RiskBadge atRisk={a.atRisk} /></td>
              <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">{a.lastSeen ?? "n/a"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UsersTable({ users }: { users: UserEntity[] }) {
  return (
    <div className="overflow-auto rounded-md border">
      <table className="w-full">
        <thead className="bg-card">
          <tr className="border-b">
            <th className={th}>User</th>
            <th className={th}>Events</th>
            <th className={th}>Findings</th>
            <th className={th}>Risk</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} data-testid="user-row" className="border-b last:border-0 align-top hover:bg-muted/60">
              <td className="px-2 py-2 font-mono text-[12px]">{u.name}</td>
              <td className="px-2 py-2 tabular-nums text-[12.5px]">{u.events}</td>
              <td className="px-2 py-2 tabular-nums text-[12.5px]">{u.findings}</td>
              <td className="px-2 py-2"><RiskBadge atRisk={u.atRisk} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Assets() {
  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: api.assets, refetchInterval: 5000 });
  const usersQ = useQuery({ queryKey: ["users"], queryFn: api.users, refetchInterval: 5000 });

  if (assetsQ.isLoading || usersQ.isLoading) {
    return <p className="text-muted-foreground">Loading observed entities…</p>;
  }

  const assetsData = assetsQ.data;
  const usersData = usersQ.data;
  const idle = hasError(assetsData);

  if (idle) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          {(assetsData as { error: string }).error} — assets and users are derived only
          from entities the parser actually observed in a run. There is no inventory to invent.
        </CardContent>
      </Card>
    );
  }

  const assets = (assetsData as { assets: Asset[] } | undefined)?.assets ?? [];
  const users = hasError(usersData) ? [] : (usersData?.users ?? []);
  const assetsAtRisk = assets.filter((a) => a.atRisk).length;
  const usersAtRisk = users.filter((u) => u.atRisk).length;

  return (
    <div className="space-y-4">
      <Card className="border-dashed">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground">
          <b className="text-foreground">Observed entities only.</b>{" "}
          Hosts come from parsed events, IPs from finding entities, usernames from event
          messages and finding titles. An asset that never appeared in a log does not exist here.
          <span className="ml-1">
            {assetsAtRisk} of {assets.length} asset(s) and {usersAtRisk} of {users.length} user(s) at risk (≥1 finding).
          </span>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">Assets ({assets.length})</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          {assets.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              This run observed no hosts or IPs.
            </p>
          ) : (
            <AssetsTable assets={assets} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">Users at risk ({users.length})</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          {users.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              No usernames were extracted from this run.
            </p>
          ) : (
            <UsersTable users={users} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
