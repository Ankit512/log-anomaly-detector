/** Typed client for the EXISTING Python console API (serve.py, 127.0.0.1:8765).
 *  Every shape below mirrors what the backend actually emits today — nothing
 *  here invents fields the server does not send. The Phase B SOC subsystems
 *  (console/soc.py, contract in docs/soc_subsystems.md) are consumed only
 *  where a page exists for them: the Overview's ops footer reads /api/metrics,
 *  which aggregates incidents, assets, users and run history server-side. */

export interface Delta { pct: number; dir: "up" | "down" }

export interface OverviewData {
  generatedAt: string;
  timeWindowLabel: string;
  kpis: {
    total: number; critical: number; high: number; medium: number; low: number;
    deltas: Record<"total" | "critical" | "high" | "medium" | "low", Delta | null>;
  };
  severityDonut: { bucket: string; count: number; pct: number }[];
  alertsOverTime: { bins: { t: string; critical: number; high: number; medium: number; low: number }[] };
  mitreTactics: { tactic: string; count: number }[];
  latestAlerts: {
    id: string; time: string; severity: string; attackerStatus: string;
    tactics: string[]; name: string; source: string;
  }[];
  ingestion: { acceptedLabel: string; files: { name: string; ok: boolean }[] };
  model: string;
}

/** /api/overview returns {error} instead of data when no run exists yet. */
export type OverviewResponse = OverviewData | { error: string };

export interface EvidenceLine { n: number | string; a: string; hit: string; b: string; crit?: boolean }

export interface Finding {
  id: string;
  sev: string;
  ruleSev: string;
  llmSev: string | null;
  delta: string | null;
  prov: string;
  type: string;
  host: string;
  hostDerived: boolean;
  time: string;
  stamp: string;
  title: string;
  ruleWhy: string;
  explanation: string;
  predicate: string;
  ruleRef: string;
  occurrences: number;
  mitre?: { id: string; name: string; tactic: string }[];
  chips: { text: string }[];
  lines: EvidenceLine[];
  linesNote: string | null;
  timeline: { t: string; label: string; line?: number; dot?: string }[];
}

export interface ConsoleState {
  idle?: boolean;
  live?: boolean;
  runId?: string;
  runWindow?: string;
  runHosts?: string;
  runParsed?: string;
  generatedAt?: string;
  linesParsed?: number;
  linesUnparsed?: number;
  unrecognized?: boolean;
  emptyInput?: boolean;
  compareRun?: boolean;
  findings: Finding[];
  manifest?: { detector_sha256?: string | null; ruleset?: string | null } & Record<string, unknown>;
  sourceLabel?: string;
  /** Set when the model endpoint was down: the run is rules-only (verdicts
   *  complete, advisory explanations skipped) and this says so. */
  llmNote?: string | null;
}

/** /api/progress — the running analysis job, polled after POST /api/analyze. */
export interface AnalyzeJob {
  status: "idle" | "running" | "done" | "error";
  phase?: string;
  done?: number;
  total?: number;
  findings?: number;
  label?: string;
  error?: string | null;
  note?: string | null;
  etaSeconds?: number | null;
  partialReady?: boolean;
}

/** /api/metrics — soc.metrics(): every value is derived or null, never guessed.
 *  mttd/mttr are null until incidents carry real acknowledge/resolve stamps;
 *  the *Basis fields say how many incidents each mean is computed from. */
export interface Metrics {
  openIncidents: number;
  mttdSeconds: number | null; mttdBasis: number;
  mttrSeconds: number | null; mttrBasis: number;
  assetsAtRisk: number | null;
  usersAtRisk: number | null;
  dataSources: number;
}

export interface RunSummary {
  file: string; runId: string; label: string; generatedAt: string;
  findings: number; unrecognized: boolean; compareRun: boolean; marked?: number;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  overview: () => getJson<OverviewResponse>("/api/overview"),
  consoleState: () => getJson<ConsoleState>(`/console_state.json?t=${Date.now()}`),
  runsSummary: () => getJson<{ runs: RunSummary[] }>("/api/runs-summary"),
  metrics: () => getJson<Metrics>("/api/metrics"),
  progress: () => getJson<AnalyzeJob>("/api/progress"),

  ask: async (question: string): Promise<{ answer?: string; error?: string }> => {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    return res.json();
  },

  analyzeUpload: async (file: File): Promise<{ ok: boolean; error?: string }> => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/analyze", { method: "POST", body: form });
    if (res.ok || res.status === 202) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },
};
