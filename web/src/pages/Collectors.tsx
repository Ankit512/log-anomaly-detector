import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Antenna, CircleDot, Radio, TriangleAlert } from "lucide-react";
import { api, type SyslogStatus } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Collectors — the control panel for the live syslog listener (UDP + TCP).
 *  Every value shown is the REAL listener state polled from /api/syslog/status;
 *  received messages land in the persistent store verbatim and their severity
 *  is the source's own syslog PRI level, never a guess. Binding 0.0.0.0 exposes
 *  the port to the network, so it is an explicit opt-in with a clear warning. */

const field = "w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary";

function StatusRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1">
      <span className="text-[12px] text-muted-foreground">{label}</span>
      <span className="text-right text-[12.5px] font-medium">{children}</span>
    </div>
  );
}

function LiveStatus({ status }: { status?: SyslogStatus }) {
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
          Listener status
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col divide-y">
        <StatusRow label="State">
          <span style={{ color: running ? "var(--sev-low)" : undefined }}>
            {running ? "Running" : "Stopped"}
          </span>
        </StatusRow>
        <StatusRow label="Bind / port">
          <span className="font-mono">{status ? `${status.bind}:${status.port}` : "—"}</span>
        </StatusRow>
        <StatusRow label="Protocols">
          <span className="font-mono">{status?.protocols?.join(" + ").toUpperCase() || "UDP + TCP"}</span>
        </StatusRow>
        <StatusRow label="Messages received">
          <span className="tabular-nums">{status?.receivedCount ?? 0}</span>
        </StatusRow>
        <StatusRow label="Stored (new, deduped)">
          <span className="tabular-nums">{status?.storedCount ?? 0}</span>
        </StatusRow>
        <StatusRow label="Started">
          {running && status?.startedAt ? new Date(status.startedAt).toLocaleString() : "—"}
        </StatusRow>
        <StatusRow label="Last message">
          {status?.lastEventAt ? new Date(status.lastEventAt).toLocaleString() : "none yet"}
        </StatusRow>
        {status?.error && (
          <div className="pt-2 text-[12px]" style={{ color: "var(--sev-critical)" }}>
            {status.error}
          </div>
        )}
        {running && status?.exposed && (
          <div className="mt-2 flex items-start gap-2 rounded-md border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-critical)", color: "var(--sev-critical)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>
              Bound to <span className="font-mono">0.0.0.0</span> — this port is reachable
              from the whole network. Anyone who can route to this host can send events
              into your store. Bind to <span className="font-mono">127.0.0.1</span> unless
              you intend to collect from other machines.
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Controls({ status }: { status?: SyslogStatus }) {
  const queryClient = useQueryClient();
  const [port, setPort] = useState("1514");
  const [bind, setBind] = useState<"127.0.0.1" | "0.0.0.0">("127.0.0.1");
  const [msg, setMsg] = useState("");

  // Seed the form from the last-used / current listener config when it first
  // arrives — but never once the user has touched the form, so neither the
  // first async load nor a later background poll clobbers what they typed.
  const touched = useRef(false);
  const seeded = useRef(false);
  useEffect(() => {
    if (!status || seeded.current || touched.current) return;
    seeded.current = true;
    setPort(String(status.port));
    setBind(status.bind === "0.0.0.0" ? "0.0.0.0" : "127.0.0.1");
  }, [status]);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["syslog"] });

  const start = useMutation({
    mutationFn: () => api.syslogStart({ port: Number(port), bind }),
    onSuccess: (out) => {
      setMsg(out.ok ? "Collector started." : (out.error ?? "Could not start."));
      refresh();
    },
  });
  const stop = useMutation({
    mutationFn: () => api.syslogStop(),
    onSuccess: () => { setMsg("Collector stopped."); refresh(); },
  });

  const running = !!status?.running;
  const portNum = Number(port);
  const portValid = Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Antenna className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Syslog collector (UDP + TCP)
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-[12px] text-muted-foreground">
          Receives syslog messages on the port below and records each one in the
          persistent store, verbatim. Severity comes from the syslog PRI the
          sender chose — the collector never invents a level.
        </p>

        <label className="text-[11.5px] text-muted-foreground">
          Listen port
          <input className={field} value={port} inputMode="numeric"
                 onChange={(e) => { touched.current = true; setPort(e.target.value.replace(/[^0-9]/g, "")); }}
                 aria-label="Listen port" placeholder="1514" />
          {!portValid && (
            <span className="mt-0.5 block text-[11px]" style={{ color: "var(--sev-critical)" }}>
              Port must be 1–65535.
            </span>
          )}
          <span className="mt-0.5 block text-[11px]">
            1514 is unprivileged; port 514 (the syslog default) needs root — put a
            relay in front, or use 1514 and point senders at it.
          </span>
        </label>

        <fieldset className="flex flex-col gap-1.5">
          <legend className="text-[11.5px] text-muted-foreground">Bind address</legend>
          <label className="flex items-center gap-2 text-[13px]">
            <input type="radio" name="syslog-bind" value="127.0.0.1"
                   checked={bind === "127.0.0.1"} onChange={() => { touched.current = true; setBind("127.0.0.1"); }} />
            <span className="font-medium">Loopback</span>
            <span className="font-mono text-[11.5px] text-muted-foreground">127.0.0.1</span>
            <span className="text-[11.5px] text-muted-foreground">— only this machine (safe default)</span>
          </label>
          <label className="flex items-center gap-2 text-[13px]">
            <input type="radio" name="syslog-bind" value="0.0.0.0"
                   checked={bind === "0.0.0.0"} onChange={() => { touched.current = true; setBind("0.0.0.0"); }} />
            <span className="font-medium">All interfaces</span>
            <span className="font-mono text-[11.5px] text-muted-foreground">0.0.0.0</span>
            <span className="text-[11.5px]" style={{ color: "var(--sev-medium)" }}>— exposes the port to the network</span>
          </label>
        </fieldset>

        {bind === "0.0.0.0" && (
          <div className="flex items-start gap-2 rounded-md border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-medium)", color: "var(--sev-medium)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>
              Binding <span className="font-mono">0.0.0.0</span> lets any host that can reach
              this machine send events into your store. Only do this on a trusted network,
              behind a firewall. Prefer loopback for local testing.
            </span>
          </div>
        )}

        <div className="flex items-center gap-2">
          <button onClick={() => start.mutate()} disabled={start.isPending || !portValid}
            className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
            {start.isPending ? "Starting…" : running ? "Restart" : "Start collector"}
          </button>
          <button onClick={() => stop.mutate()} disabled={stop.isPending || !running}
            className="rounded-md border px-3 py-1.5 text-[12.5px] font-semibold hover:border-primary disabled:opacity-50">
            Stop
          </button>
          {msg && <span className="text-[12px] text-muted-foreground">{msg}</span>}
        </div>

        <details className="text-[11.5px] text-muted-foreground">
          <summary className="cursor-pointer">How to send it a test message</summary>
          <pre className="mt-1.5 overflow-x-auto rounded-md border bg-background p-2 font-mono text-[11px]">
{`# UDP
logger -n 127.0.0.1 -P ${portValid ? portNum : 1514} -d "test from logger"
echo '<13>hello syslog' | nc -u -w1 127.0.0.1 ${portValid ? portNum : 1514}

# TCP
echo '<11>disk error on host1' | nc -w1 127.0.0.1 ${portValid ? portNum : 1514}`}
          </pre>
        </details>
      </CardContent>
    </Card>
  );
}

function RecentEvents({ running }: { running: boolean }) {
  const { data } = useQuery({
    queryKey: ["syslog", "events"], queryFn: () => api.syslogEvents(15),
    refetchInterval: running ? 3000 : false,
  });
  const items = data?.items ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Radio className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Recent received events
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground">
            No syslog events received yet. Start the collector and send it a
            message — received lines appear here and in the events store.
          </p>
        ) : (
          <>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Severity shown is the sender's own syslog level (source-reported),
              not a verdict. <span className="font-mono">raw</span> is the exact line received.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead className="text-[11px] text-muted-foreground">
                  <tr className="border-b">
                    <th className="py-1.5 pr-3 font-medium">Time</th>
                    <th className="py-1.5 pr-3 font-medium">From</th>
                    <th className="py-1.5 pr-3 font-medium">Host</th>
                    <th className="py-1.5 pr-3 font-medium">Severity</th>
                    <th className="py-1.5 font-medium">Raw</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((e) => (
                    <tr key={e.id} className="border-b align-top">
                      <td className="py-1.5 pr-3 tabular-nums text-muted-foreground whitespace-nowrap">
                        {new Date(e.ts).toLocaleTimeString()}
                      </td>
                      <td className="py-1.5 pr-3 font-mono">{e.src_ip || "—"}</td>
                      <td className="py-1.5 pr-3 font-mono">{e.host || "—"}</td>
                      <td className="py-1.5 pr-3 font-medium">{e.severity || <span className="text-muted-foreground">none</span>}</td>
                      <td className="py-1.5 font-mono break-all">{e.raw}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function Collectors() {
  const { data: status, error } = useQuery({
    queryKey: ["syslog", "status"], queryFn: api.syslogStatus,
    refetchInterval: 3000,
  });

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-3xl text-[12.5px] text-muted-foreground">
        A live syslog collector: point network devices, Linux/Windows agents, or a
        relay at it and their messages stream into the persistent store in real
        time. Everything shown here is the real listener state — never a fake
        “running”.
      </p>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to control the collector.
        </p>
      )}
      {/* Config and live status sit side by side on wide screens (so the page
          fills its width) and stack on narrow ones. items-start keeps each card
          its natural height instead of stretching to match the taller one. */}
      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <Controls status={status} />
        <LiveStatus status={status} />
      </div>
      <RecentEvents running={!!status?.running} />
    </div>
  );
}
