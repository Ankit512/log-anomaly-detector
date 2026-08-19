import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cable, Plug, RefreshCw } from "lucide-react";
import { api, type OemConnector } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** OEM / API Engine — read-only connectors that poll a vendor's events API
 *  (Cisco Firepower, Ruckus SmartZone, ManageEngine Log360, or a generic
 *  endpoint) into the persistent store. Vendor tokens are user-supplied and
 *  stored masked — the page only shows whether a token is set. `lastRun` /
 *  `lastError` are the REAL poll outcome; an event's severity is the level the
 *  vendor reported, never guessed. A placeholder base URL is never called. */

const field = "w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary";

const TEMPLATES: Record<string, { vendor: string; baseUrl: string; eventsPath: string }> = {
  "Cisco Firepower": { vendor: "cisco", baseUrl: "https://FIREPOWER", eventsPath: "/api/fdm/v6/events" },
  "Ruckus SmartZone": { vendor: "ruckus", baseUrl: "https://SMARTZONE", eventsPath: "/wsg/api/public/v11_0/events" },
  "ManageEngine Log360": { vendor: "log360", baseUrl: "https://LOG360", eventsPath: "/api/v2/events" },
  "Generic API": { vendor: "generic", baseUrl: "", eventsPath: "/events" },
};

function AddConnector() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("Cisco Firepower");
  const [vendor, setVendor] = useState(TEMPLATES["Cisco Firepower"].vendor);
  const [baseUrl, setBaseUrl] = useState(TEMPLATES["Cisco Firepower"].baseUrl);
  const [eventsPath, setEventsPath] = useState(TEMPLATES["Cisco Firepower"].eventsPath);
  const [interval, setInterval] = useState("60");
  const [token, setToken] = useState("");
  const [msg, setMsg] = useState("");

  const applyTemplate = (t: string) => {
    setName(t);
    const tpl = TEMPLATES[t];
    if (tpl) { setVendor(tpl.vendor); setBaseUrl(tpl.baseUrl); setEventsPath(tpl.eventsPath); }
  };

  const create = useMutation({
    mutationFn: () => api.oemCreateConnector({
      name: name.trim(),
      config: { vendor, baseUrl: baseUrl.trim(), eventsPath: eventsPath.trim() },
      interval: Number(interval) || 60,
      token: token.trim() || undefined,
    }),
    onSuccess: (out) => {
      setMsg(out.ok ? "Connector saved." : (out.error ?? "Could not save."));
      setToken("");
      queryClient.invalidateQueries({ queryKey: ["oem"] });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Plug className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Add / update a connector
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <label className="text-[11.5px] text-muted-foreground">
          Template
          <select className={field} value={name in TEMPLATES ? name : "Generic API"}
                  onChange={(e) => applyTemplate(e.target.value)} aria-label="Template">
            {Object.keys(TEMPLATES).map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="text-[11.5px] text-muted-foreground">
          Connector name
          <input className={field} value={name} onChange={(e) => setName(e.target.value)} aria-label="Connector name" />
        </label>
        <div className="grid grid-cols-2 gap-2">
          <label className="text-[11.5px] text-muted-foreground">
            Vendor
            <input className={field} value={vendor} onChange={(e) => setVendor(e.target.value)} aria-label="Vendor" />
          </label>
          <label className="text-[11.5px] text-muted-foreground">
            Poll interval (s)
            <input className={field} value={interval} inputMode="numeric"
                   onChange={(e) => setInterval(e.target.value.replace(/[^0-9]/g, ""))} aria-label="Poll interval seconds" />
          </label>
        </div>
        <label className="text-[11.5px] text-muted-foreground">
          Base URL
          <input className={field} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                 aria-label="Base URL" placeholder="https://firepower.example.com" />
          <span className="mt-0.5 block text-[11px]">
            Replace any placeholder host (e.g. <span className="font-mono">FIREPOWER</span>) with your
            real appliance — a placeholder URL is never called.
          </span>
        </label>
        <label className="text-[11.5px] text-muted-foreground">
          Events path
          <input className={field} value={eventsPath} onChange={(e) => setEventsPath(e.target.value)} aria-label="Events path" />
        </label>
        <label className="text-[11.5px] text-muted-foreground">
          API token (stored masked, never returned)
          <input className={field} type="password" value={token} autoComplete="off"
                 onChange={(e) => setToken(e.target.value)} aria-label="API token" placeholder="Bearer token…" />
        </label>
        <div className="flex items-center gap-2">
          <button onClick={() => create.mutate()} disabled={!name.trim() || create.isPending}
            className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
            {create.isPending ? "Saving…" : "Save connector"}
          </button>
          {msg && <span className="text-[12px] text-muted-foreground">{msg}</span>}
        </div>
      </CardContent>
    </Card>
  );
}

function ConnectorRow({ c }: { c: OemConnector }) {
  const queryClient = useQueryClient();
  const [msg, setMsg] = useState("");
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["oem"] });

  const toggle = useMutation({
    mutationFn: () => api.oemCreateConnector({
      name: c.name, config: {}, enabled: !c.enabled,
    }),
    onSuccess: refresh,
  });
  const poll = useMutation({
    mutationFn: () => api.oemPoll(c.name),
    onSuccess: (r) => {
      setMsg(r.ok ? `Polled — stored ${r.stored} event(s).` : `Poll failed: ${r.error}`);
      refresh();
    },
    onError: (e: Error) => setMsg(e.message),
  });

  return (
    <div className="flex flex-col gap-1.5 border-b py-2.5 last:border-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-medium text-[13px]">{c.name}</span>
        <span className="text-[11px] text-muted-foreground">vendor {c.kind}</span>
        <span className="text-[11.5px]" style={{ color: c.enabled ? "var(--sev-low)" : undefined }}>
          {c.enabled ? "enabled" : "disabled"}
        </span>
        <span className="text-[11px] text-muted-foreground">every {c.interval ?? 60}s</span>
        <span className="text-[11px] text-muted-foreground">{c.hasToken ? "token set" : "no token"}</span>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-0.5 text-[11px] text-muted-foreground">
        <span>last run: {c.lastRun ? new Date(c.lastRun).toLocaleString() : "never"}</span>
        {c.lastError && <span style={{ color: "var(--sev-critical)" }}>last error: {c.lastError}</span>}
      </div>
      <div className="flex items-center gap-2">
        <button onClick={() => toggle.mutate()} disabled={toggle.isPending}
          className="rounded-md border px-2.5 py-1 text-[11.5px] font-semibold hover:border-primary disabled:opacity-50">
          {c.enabled ? "Disable" : "Enable"}
        </button>
        <button onClick={() => poll.mutate()} disabled={poll.isPending}
          className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11.5px] font-semibold hover:border-primary disabled:opacity-50">
          <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
          {poll.isPending ? "Polling…" : "Poll now"}
        </button>
        {msg && <span className="text-[11.5px] text-muted-foreground">{msg}</span>}
      </div>
    </div>
  );
}

function ConnectorList() {
  const { data } = useQuery({ queryKey: ["oem", "connectors"], queryFn: api.oemConnectors, refetchInterval: 5000 });
  const items = data?.connectors ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Cable className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Connectors
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground">
            No OEM connectors yet. Add one above — when enabled and pointed at a real vendor API,
            the engine polls it on its interval and records events in the store.
          </p>
        ) : (
          <div className="flex flex-col">
            {items.map((c) => <ConnectorRow key={c.name} c={c} />)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function OemEngine() {
  const { error } = useQuery({ queryKey: ["oem", "connectors"], queryFn: api.oemConnectors });
  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <p className="text-[12.5px] text-muted-foreground">
        Read-only OEM/API connectors that poll a vendor's events feed into the persistent store.
        Credentials are user-supplied and stored masked; last-run and last-error are the real poll
        outcome — never a fabricated “connected”.
      </p>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to manage connectors.
        </p>
      )}
      <AddConnector />
      <ConnectorList />
    </div>
  );
}
