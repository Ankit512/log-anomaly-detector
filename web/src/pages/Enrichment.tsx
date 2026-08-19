import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Search, ShieldCheck, TriangleAlert } from "lucide-react";
import { api, type StoreIoc, type TiEnrichResult } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Enrichment — look up an IP against external threat-intel providers (OTX and
 *  AbuseIPDB) using YOUR API keys. Keys are stored write-only (masked): the
 *  page only ever learns whether a key is present. A provider with no key is
 *  reported as not-configured and never called; a verdict/score always comes
 *  from the provider's real response — never keyword-guessed. */

const field = "w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary";

function verdictColor(verdict: string): string | undefined {
  const v = verdict.toLowerCase();
  if (v === "malicious") return "var(--sev-critical)";
  if (v === "suspicious") return "var(--sev-medium)";
  if (v === "clean") return "var(--sev-low)";
  return undefined;
}

function KeyField({ which, label, configured }: { which: "otx" | "abuseipdb"; label: string; configured: boolean }) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState("");
  const save = useMutation({
    mutationFn: () => api.setTiKey(which, value),
    onSuccess: () => { setValue(""); queryClient.invalidateQueries({ queryKey: ["ti"] }); },
  });
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2 text-[12.5px]">
        <span className="font-medium">{label}</span>
        {configured ? (
          <span className="inline-flex items-center gap-1" style={{ color: "var(--sev-low)" }}>
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden /> key configured
          </span>
        ) : (
          <span className="text-muted-foreground">no key configured</span>
        )}
      </div>
      <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (value.trim()) save.mutate(); }}>
        <input className={field} type="password" value={value} autoComplete="off"
               onChange={(e) => setValue(e.target.value)}
               aria-label={`${label} API key`}
               placeholder={configured ? "Replace stored key…" : "Paste API key…"} />
        <button type="submit" disabled={!value.trim() || save.isPending}
          className="whitespace-nowrap rounded-md border px-3 py-1.5 text-[12.5px] font-semibold hover:border-primary disabled:opacity-50">
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </form>
    </div>
  );
}

function KeysCard({ otx, abuseipdb }: { otx: boolean; abuseipdb: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <KeyRound className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Provider keys
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-[12px] text-muted-foreground">
          Your API keys are stored write-only and never sent back to the browser — this page
          only shows whether each is set. Enrichment calls go only to the provider you supplied
          a key for.
        </p>
        <KeyField which="otx" label="AlienVault OTX" configured={otx} />
        <KeyField which="abuseipdb" label="AbuseIPDB" configured={abuseipdb} />
      </CardContent>
    </Card>
  );
}

function EnrichPanel({ anyKey }: { anyKey: boolean }) {
  const queryClient = useQueryClient();
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<TiEnrichResult | null>(null);
  const [err, setErr] = useState("");

  const enrich = useMutation({
    mutationFn: () => api.tiEnrich(ip.trim()),
    onSuccess: (r) => {
      setResult(r); setErr(r.error ?? "");
      queryClient.invalidateQueries({ queryKey: ["ti", "iocs"] });
    },
    onError: (e: Error) => { setErr(e.message); setResult(null); },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Search className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Enrich an IP
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!anyKey && (
          <div className="flex items-start gap-2 rounded-md border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-medium)", color: "var(--sev-medium)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>No provider key is configured yet. Add an OTX or AbuseIPDB key above — until
              then a lookup honestly reports every provider as not-configured.</span>
          </div>
        )}
        <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (ip.trim()) enrich.mutate(); }}>
          <input className={field} value={ip} onChange={(e) => setIp(e.target.value)}
                 aria-label="IP address to enrich" inputMode="numeric"
                 placeholder="203.0.113.9" />
          <button type="submit" disabled={!ip.trim() || enrich.isPending}
            className="inline-flex items-center gap-2 whitespace-nowrap rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
            <Search className="h-4 w-4" strokeWidth={1.8} aria-hidden />
            {enrich.isPending ? "Enriching…" : "Enrich"}
          </button>
        </form>

        {err && <p className="text-[12px]" style={{ color: "var(--sev-critical)" }}>{err}</p>}

        {result && !result.error && (
          <div className="flex flex-col gap-2 text-[12px]">
            {result.notConfigured.length > 0 && (
              <p className="text-muted-foreground">
                Not configured (skipped): {result.notConfigured.join(", ")}
              </p>
            )}
            {result.errors.map((e) => (
              <p key={e.provider} style={{ color: "var(--sev-critical)" }}>
                {e.provider}: {e.error}
              </p>
            ))}
            {result.results.length === 0 && result.errors.length === 0 && result.notConfigured.length > 0 && (
              <p className="text-muted-foreground">No provider was called — add a key to enrich.</p>
            )}
            {result.results.length > 0 && (
              <table className="w-full text-left">
                <thead className="text-[11px] text-muted-foreground">
                  <tr className="border-b">
                    <th className="py-1.5 pr-3 font-medium">Provider</th>
                    <th className="py-1.5 pr-3 font-medium">Verdict</th>
                    <th className="py-1.5 pr-3 font-medium">Score</th>
                    <th className="py-1.5 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {result.results.map((r) => (
                    <tr key={r.provider} className="border-b align-top">
                      <td className="py-1.5 pr-3 font-medium">{r.provider}</td>
                      <td className="py-1.5 pr-3 font-semibold" style={{ color: verdictColor(r.verdict) }}>
                        {r.verdict}
                      </td>
                      <td className="py-1.5 pr-3 tabular-nums">{r.score}</td>
                      <td className="py-1.5 font-mono break-all text-[11px] text-muted-foreground">{r.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function IocHistory() {
  const { data } = useQuery({ queryKey: ["ti", "iocs"], queryFn: () => api.iocs(100) });
  const items: StoreIoc[] = data?.items ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-[15px]">Recent IOC lookups</CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground">
            No IOC lookups recorded yet. Enrich an IP above — real provider results appear here
            and in the IOC store.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="text-[11px] text-muted-foreground">
                <tr className="border-b">
                  <th className="py-1.5 pr-3 font-medium">Time</th>
                  <th className="py-1.5 pr-3 font-medium">IOC</th>
                  <th className="py-1.5 pr-3 font-medium">Provider</th>
                  <th className="py-1.5 pr-3 font-medium">Verdict</th>
                  <th className="py-1.5 font-medium">Score</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.id} className="border-b align-top">
                    <td className="py-1.5 pr-3 tabular-nums text-muted-foreground whitespace-nowrap">
                      {new Date(i.ts).toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-3 font-mono">{i.ioc}</td>
                    <td className="py-1.5 pr-3">{i.provider}</td>
                    <td className="py-1.5 pr-3 font-semibold" style={{ color: verdictColor(i.verdict) }}>{i.verdict}</td>
                    <td className="py-1.5 tabular-nums">{i.score}</td>
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

export function Enrichment() {
  const { data: keys, error } = useQuery({ queryKey: ["ti", "keys"], queryFn: api.tiKeys });
  const otx = !!keys?.otx, abuseipdb = !!keys?.abuseipdb;

  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <p className="text-[12.5px] text-muted-foreground">
        Threat-intelligence enrichment against external providers using your own API keys. Every
        verdict and score shown is the provider's real response — never a fabricated or
        keyword-guessed result.
      </p>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to run enrichment.
        </p>
      )}
      <KeysCard otx={otx} abuseipdb={abuseipdb} />
      <EnrichPanel anyKey={otx || abuseipdb} />
      <IocHistory />
    </div>
  );
}
