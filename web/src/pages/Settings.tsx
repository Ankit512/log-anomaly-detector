import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cpu, Moon, ShieldCheck, Sun } from "lucide-react";
import { api, type ComputeConfig, type OverviewData } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useUi } from "@/store/ui";

/** Settings — only the knobs that genuinely do something. Compute location and
 *  its redaction consequence (the real /api/compute you can set), the analyst
 *  model/endpoint shown honestly, and theme. No invented switches: every value
 *  here reflects real backend or client state. */

const field = "w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary";

function ComputeSettings() {
  const queryClient = useQueryClient();
  const { data: compute, isLoading, error } = useQuery<ComputeConfig>({
    queryKey: ["compute"], queryFn: api.getCompute,
  });

  const [mode, setMode] = useState<"local" | "remote">("local");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [msg, setMsg] = useState("");

  // Seed the form from the real current config once it loads.
  useEffect(() => {
    if (!compute) return;
    setMode(compute.mode);
    setBaseUrl(compute.baseUrl ?? "");
    setModel(compute.model ?? "");
  }, [compute]);

  const save = useMutation({
    mutationFn: () => api.setCompute(
      mode === "local" ? { mode } : { mode, baseUrl, model, apiKey }),
    onSuccess: (out) => {
      if (!out.ok) { setMsg(out.error ?? "Could not save."); return; }
      setMsg("Saved."); setApiKey("");
      queryClient.invalidateQueries({ queryKey: ["compute"] });
      queryClient.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <Cpu className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Compute location
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {isLoading && <p className="text-[12.5px] text-muted-foreground">Loading current config…</p>}
        {error && <p className="text-[12.5px] text-muted-foreground">Backend not reachable — start the console server.</p>}
        {compute && (
          <>
            <p className="text-[12px] text-muted-foreground">
              Detection ALWAYS runs locally — this only changes where the advisory
              LLM explanations compute. Currently:{" "}
              <span className="font-semibold text-foreground">{compute.mode}</span>.
            </p>
            <div className="flex flex-col gap-2">
              {(["local", "remote"] as const).map((m) => (
                <label key={m} className="flex items-center gap-2 text-[13px]">
                  <input type="radio" name="compute-mode" value={m}
                         checked={mode === m} onChange={() => setMode(m)} />
                  <span className="font-medium">{m === "local" ? "Local" : "Remote"}</span>
                  <span className="text-[11.5px] text-muted-foreground">
                    {m === "local"
                      ? "nothing leaves this machine"
                      : "explanations call an OpenAI-compatible endpoint (redacted first)"}
                  </span>
                </label>
              ))}
            </div>

            {mode === "remote" && (
              <div className="flex flex-col gap-2 rounded-md border bg-background p-3">
                <label className="text-[11.5px] text-muted-foreground">Base URL (must end in /v1)
                  <input className={field} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                         aria-label="Remote base URL" placeholder="https://host:port/v1" />
                </label>
                <label className="text-[11.5px] text-muted-foreground">Model
                  <input className={field} value={model} onChange={(e) => setModel(e.target.value)}
                         aria-label="Remote model" placeholder="model name" />
                </label>
                <label className="text-[11.5px] text-muted-foreground">
                  API key {compute.hasKey && <span className="text-foreground">(a key is currently set — leave blank to keep it)</span>}
                  <input className={field} type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                         aria-label="Remote API key" placeholder="sk-…" autoComplete="off" />
                </label>
                <p className="text-[11px] text-muted-foreground">
                  The key is sent to the backend but never returned to the browser.
                </p>
              </div>
            )}

            <div className="flex items-center gap-2">
              <button onClick={() => save.mutate()} disabled={save.isPending}
                className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
                {save.isPending ? "Saving…" : "Save compute settings"}
              </button>
              {msg && <span className="text-[12px] text-muted-foreground">{msg}</span>}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function RedactionInfo({ compute }: { compute?: ComputeConfig }) {
  const remote = compute?.mode === "remote";
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-[15px]">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Outbound redaction
        </CardTitle>
      </CardHeader>
      <CardContent className="text-[12.5px] leading-normal text-muted-foreground">
        Redaction is a consequence of compute location, not a separate toggle —
        so it is shown here honestly rather than as a switch that does nothing.
        {remote ? (
          <> It is <span className="font-semibold text-foreground">active</span>: with
          remote compute, finding summaries and your analyst questions pass through
          the redaction choke point (<span className="font-mono">console/redact.py</span>)
          before leaving this machine. Raw log lines never leave at all.</>
        ) : (
          <> It is <span className="font-semibold text-foreground">not applicable</span> right
          now: compute is local, so nothing is sent anywhere and there is nothing to redact.
          Switch to remote above and redaction engages automatically.</>
        )}
      </CardContent>
    </Card>
  );
}

function AnalystModel() {
  const { data } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  const { data: compute } = useQuery<ComputeConfig>({ queryKey: ["compute"], queryFn: api.getCompute });
  const overview = data && !("error" in data) ? (data as OverviewData) : null;
  const model = compute?.mode === "remote" ? compute.model : overview?.model;

  return (
    <Card>
      <CardHeader><CardTitle className="text-[15px]">Analyst model</CardTitle></CardHeader>
      <CardContent className="flex flex-col gap-1 text-[12.5px] text-muted-foreground">
        <div>Model:{" "}
          <span className="font-mono text-foreground">{model || "not reported (analyze a run first)"}</span></div>
        {compute?.mode === "remote"
          ? <div>Endpoint: <span className="font-mono text-foreground">{compute.baseUrl || "—"}</span></div>
          : <div>Endpoint: local (the model configured for the console server).</div>}
        <p className="mt-1 text-[11px]">
          The model only explains findings in plain language. It never sets or
          changes a severity or verdict — those are the deterministic rules.
        </p>
      </CardContent>
    </Card>
  );
}

function ThemeSetting() {
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);
  const dark = theme === "dark";
  return (
    <Card>
      <CardHeader><CardTitle className="text-[15px]">Appearance</CardTitle></CardHeader>
      <CardContent className="flex items-center gap-3">
        <span className="text-[12.5px] text-muted-foreground">
          Theme: <span className="font-semibold text-foreground">{dark ? "Dark" : "Light"}</span>{" "}
          — saved for your next visit.
        </span>
        <button onClick={toggleTheme}
          aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
          className="ml-auto inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-[12.5px] hover:border-primary">
          {dark ? <Sun className="h-4 w-4" aria-hidden /> : <Moon className="h-4 w-4" aria-hidden />}
          Switch to {dark ? "light" : "dark"}
        </button>
      </CardContent>
    </Card>
  );
}

export function Settings() {
  const { data: compute } = useQuery<ComputeConfig>({ queryKey: ["compute"], queryFn: api.getCompute });
  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <p className="text-[12.5px] text-muted-foreground">
        Only settings that genuinely do something are shown — each reflects real
        backend or client state, nothing decorative.
      </p>
      <ComputeSettings />
      <RedactionInfo compute={compute} />
      <AnalystModel />
      <ThemeSetting />
    </div>
  );
}
