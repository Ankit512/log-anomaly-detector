import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { api, type StoreVuln } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { sevVar } from "@/lib/severity";

/** Vulnerabilities — every finding nmap's NSE vuln scripts recorded in the
 *  persistent store, newest first. Severity is derived from the CVSS score NSE
 *  reported (standard band); when NSE gives no score the severity is shown as
 *  "unknown" rather than guessed. An empty store is an honest empty state — we
 *  never seed a sample vulnerability. */

function SevBadge({ sev }: { sev: string }) {
  const label = sev ? sev.toUpperCase() : "UNKNOWN";
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold">
      <span className="inline-block h-2 w-2 rounded-full"
            style={{ backgroundColor: sev ? sevVar(sev) : "hsl(var(--muted-foreground))" }} aria-hidden />
      {sev ? label : <span className="font-normal text-muted-foreground">unknown</span>}
    </span>
  );
}

export function Vulnerabilities() {
  const { data, error } = useQuery({
    queryKey: ["vulns"], queryFn: () => api.vulns(200),
    refetchInterval: 5000,
  });
  const items: StoreVuln[] = data?.items ?? [];

  return (
    <div className="flex flex-col gap-4">
      <p className="text-[12.5px] text-muted-foreground">
        Vulnerabilities discovered by nmap NSE <span className="font-mono">vuln</span> scripts
        during a scan. Severity is the CVSS band NSE reported — an empty severity means NSE gave
        no score, shown honestly as “unknown” rather than guessed.
      </p>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to view stored vulnerabilities.
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-[15px]">
            <ShieldAlert className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
            Vulnerabilities
            {items.length > 0 && (
              <span className="text-[12px] font-normal text-muted-foreground">
                · {data?.total ?? items.length} total
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {items.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              No vulnerabilities recorded yet. Run a “Service + vulnerability scan”
              from the Discovery page against a private target — real NSE findings
              appear here.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead className="text-[11px] text-muted-foreground">
                  <tr className="border-b">
                    <th className="py-1.5 pr-3 font-medium">Found</th>
                    <th className="py-1.5 pr-3 font-medium">Asset</th>
                    <th className="py-1.5 pr-3 font-medium">Severity</th>
                    <th className="py-1.5 pr-3 font-medium">CVSS</th>
                    <th className="py-1.5 pr-3 font-medium">CVE</th>
                    <th className="py-1.5 pr-3 font-medium">Script</th>
                    <th className="py-1.5 pr-3 font-medium">Status</th>
                    <th className="py-1.5 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((v) => (
                    <tr key={v.id} className="border-b align-top">
                      <td className="py-1.5 pr-3 tabular-nums text-muted-foreground whitespace-nowrap">
                        {new Date(v.ts).toLocaleString()}
                      </td>
                      <td className="py-1.5 pr-3 font-mono">{v.asset_ip || "—"}</td>
                      <td className="py-1.5 pr-3"><SevBadge sev={v.severity} /></td>
                      <td className="py-1.5 pr-3 tabular-nums">
                        {v.cvss > 0 ? v.cvss.toFixed(1) : <span className="text-muted-foreground">—</span>}
                      </td>
                      <td className="py-1.5 pr-3 font-mono">{v.cve || <span className="text-muted-foreground">—</span>}</td>
                      <td className="py-1.5 pr-3 font-mono">{v.name || "—"}</td>
                      <td className="py-1.5 pr-3">{v.status || "OPEN"}</td>
                      <td className="py-1.5 font-mono break-all text-[11px] text-muted-foreground">
                        {v.details ? (v.details.length > 240 ? v.details.slice(0, 240) + "…" : v.details) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
