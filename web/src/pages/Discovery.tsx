import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleDot, Network, Radar, ShieldAlert, TriangleAlert } from "lucide-react";
import { api, type DiscoveryStatus, type StoreAsset } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Discovery — the control panel for real nmap network discovery + service /
 *  vulnerability scanning. This is a dual-use tool, so the page is explicit
 *  about its guardrails: only private / loopback / link-local targets are ever
 *  accepted (the backend refuses a public or publicly-resolving target with an
 *  honest error), every scan is user-initiated from here, and when nmap is not
 *  installed the backend says so rather than faking a result. Everything shown
 *  is the REAL scanner state and REAL stored assets — never a simulated node. */

const field = "w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary";

function StatusRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1">
      <span className="text-[12px] text-muted-foreground">{label}</span>
      <span className="text-right text-[12.5px] font-medium">{children}</span>
    </div>
  );
}

function ScanStatus({ status }: { status?: DiscoveryStatus }) {
  const running = !!status?.running;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <CircleDot
            className={running ? "h-4 w-4" : "h-4 w-4 text-muted-foreground"}
            style={running ? { color: "var(--sev-low)" } : undefined}
            strokeWidth={2} aria-hidden
          />
          Scan status
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col divide-y">
        <StatusRow label="State">
          <span style={{ color: running ? "var(--sev-low)" : undefined }}>
            {running ? "Scanning…" : status?.finishedAt ? "Idle (last scan complete)" : "Idle"}
          </span>
        </StatusRow>
        <StatusRow label="Target">
          <span className="font-mono">{status?.target || "—"}</span>
        </StatusRow>
        <StatusRow label="Mode">
          {status?.vuln ? "Service + vulnerability scan" : "Host discovery"}
        </StatusRow>
        <StatusRow label="Hosts found">
          <span className="tabular-nums">{status?.hostsFound ?? 0}</span>
        </StatusRow>
        <StatusRow label="Assets stored">
          <span className="tabular-nums">{status?.assetsStored ?? 0}</span>
        </StatusRow>
        <StatusRow label="Vulns stored">
          <span className="tabular-nums">{status?.vulnsStored ?? 0}</span>
        </StatusRow>
        <StatusRow label="Started">
          {status?.startedAt ? new Date(status.startedAt).toLocaleString() : "—"}
        </StatusRow>
        <StatusRow label="Finished">
          {status?.finishedAt ? new Date(status.finishedAt).toLocaleString() : running ? "in progress" : "—"}
        </StatusRow>
        {status?.error && (
          <div className="pt-2 text-[12px]" style={{ color: "var(--sev-critical)" }}>
            {status.error}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Controls({ status }: { status?: DiscoveryStatus }) {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [msg, setMsg] = useState("");
  const running = !!status?.running;

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["discovery"] });

  const scan = useMutation({
    mutationFn: (vuln: boolean) => api.discoveryScan({ target: target.trim(), vuln }),
    onSuccess: (out) => {
      setMsg(out.ok
        ? "Scan started — results appear below as nmap reports them."
        : (out.error ?? "Could not start the scan."));
      refresh();
    },
  });

  const nmapMissing = status && !status.nmapInstalled;
  const canScan = target.trim().length > 0 && !running && !scan.isPending && !nmapMissing;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Radar className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Scan a private network or host
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-[12px] text-muted-foreground">
          Runs real <span className="font-mono">nmap</span> against the target and records every
          host it observes in the persistent store. A vulnerability scan additionally runs nmap's
          NSE <span className="font-mono">vuln</span> scripts; a finding's severity is taken from the
          CVSS score NSE reports (empty when it gives none) — never keyword-guessed.
        </p>

        {nmapMissing && (
          <div className="flex items-start gap-2 rounded-md border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-critical)", color: "var(--sev-critical)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>
              <span className="font-medium">nmap is not installed.</span> Network discovery needs
              the <span className="font-mono">nmap</span> binary on this host (e.g.{" "}
              <span className="font-mono">brew install nmap</span> or{" "}
              <span className="font-mono">apt install nmap</span>). No scan can run until it is
              present — nothing here is simulated.
            </span>
          </div>
        )}

        <label className="text-[11.5px] text-muted-foreground">
          Target host or CIDR range
          <input className={field} value={target}
                 onChange={(e) => setTarget(e.target.value)}
                 aria-label="Target host or CIDR"
                 placeholder="192.168.1.0/24  ·  10.0.0.5  ·  127.0.0.1" />
          <span className="mt-0.5 block text-[11px]">
            Private (RFC1918), loopback, and link-local targets only. Public or
            internet-routable targets are refused — this scans only networks you own.
          </span>
        </label>

        <div className="flex items-start gap-2 rounded-md border p-2.5 text-[11.5px]"
             style={{ borderColor: "var(--sev-medium)", color: "var(--sev-medium)" }}>
          <ShieldAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
          <span>
            Only scan networks you are authorized to test. Every scan is initiated by you
            here — nothing runs on a timer.
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button onClick={() => scan.mutate(false)} disabled={!canScan}
            className="inline-flex items-center gap-2 rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
            <Network className="h-4 w-4" strokeWidth={1.8} aria-hidden />
            {scan.isPending ? "Starting…" : "Discover live nodes"}
          </button>
          <button onClick={() => scan.mutate(true)} disabled={!canScan}
            className="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-[12.5px] font-semibold hover:border-primary disabled:opacity-50">
            <ShieldAlert className="h-4 w-4" strokeWidth={1.8} aria-hidden />
            Service + vulnerability scan
          </button>
        </div>
        {msg && <span className="text-[12px] text-muted-foreground">{msg}</span>}
      </CardContent>
    </Card>
  );
}

function DiscoveredAssets({ running }: { running: boolean }) {
  const { data } = useQuery({
    queryKey: ["discovery", "assets"], queryFn: () => api.discoveryAssets(100),
    refetchInterval: running ? 3000 : false,
  });
  const items: StoreAsset[] = data?.items ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Network className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Discovered assets
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground">
            No hosts discovered yet. Enter a private target above and run a scan —
            hosts nmap actually observes appear here and in the assets store.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="text-[11px] text-muted-foreground">
                <tr className="border-b">
                  <th className="py-1.5 pr-3 font-medium">Seen</th>
                  <th className="py-1.5 pr-3 font-medium">IP</th>
                  <th className="py-1.5 pr-3 font-medium">Hostname</th>
                  <th className="py-1.5 pr-3 font-medium">MAC / vendor</th>
                  <th className="py-1.5 pr-3 font-medium">OS</th>
                  <th className="py-1.5 font-medium">Open ports</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} className="border-b align-top">
                    <td className="py-1.5 pr-3 tabular-nums text-muted-foreground whitespace-nowrap">
                      {new Date(a.ts).toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-3 font-mono">{a.ip || "—"}</td>
                    <td className="py-1.5 pr-3 font-mono">{a.hostname || <span className="text-muted-foreground">—</span>}</td>
                    <td className="py-1.5 pr-3 font-mono">
                      {a.mac ? `${a.mac}${a.vendor ? ` (${a.vendor})` : ""}` : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="py-1.5 pr-3">{a.os || <span className="text-muted-foreground">—</span>}</td>
                    <td className="py-1.5 font-mono break-all">{a.ports || <span className="text-muted-foreground">none open</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Discovery() {
  const { data: status, error } = useQuery({
    queryKey: ["discovery", "status"], queryFn: api.discoveryStatus,
    refetchInterval: 3000,
  });

  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <p className="text-[12.5px] text-muted-foreground">
        Real nmap-driven discovery and vulnerability scanning for networks you own.
        Everything shown is the actual scanner state and the actual hosts nmap
        observed — never a fabricated node or a fake “scanning”.
      </p>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to run a discovery scan.
        </p>
      )}
      <Controls status={status} />
      <ScanStatus status={status} />
      <DiscoveredAssets running={!!status?.running} />
    </div>
  );
}
