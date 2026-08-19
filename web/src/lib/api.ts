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

/** /api/runs — saved runs as navigation entries, newest first, plus which
 *  one is currently open. */
export interface RunEntry {
  file: string; runId: string; label: string; generatedAt: string;
  findings: number; unrecognized: boolean; compareRun: boolean; marked?: number;
}

/** /api/runs-summary — the whole history in one shape. A history file that
 *  cannot be read appears flagged `unreadable` (never silently dropped); a
 *  run predating stored severity counts is `dataComplete: false` and
 *  contributes zeros, never guesses. */
export interface RunsSummaryEntry {
  file: string; runId: string;
  generatedAt?: string; sourceLabel?: string;
  linesParsed?: number; findingCount?: number;
  severityCounts?: Record<string, number>;
  topTechniques?: { id: string; name: string; tactic: string; count: number }[];
  unrecognized?: boolean; dataComplete?: boolean; unreadable?: boolean;
}

export interface RunsSummary {
  runs: RunsSummaryEntry[];
  totals: {
    runCount: number; linesParsed: number; findingCount: number;
    severityCounts: Record<string, number>;
    mitreFrequency: { id: string; name: string; tactic: string; count: number }[];
  };
}

// --- Phase C (Incidents / Threat Intel / Assets / Reports) ---
// Shapes mirror console/soc.py exactly (contract: docs/soc_subsystems.md).
// Every value is derived from real findings/events/files or is null — the UI
// renders null as n/a and an absent inventory as an honest empty state.

export interface Technique { id: string; name: string; tactic: string }

/** Analyst lifecycle: the ONLY mutable part of an incident. Rules still own
 *  severity — `severity` here is the max member verdict, a display rollup. */
export type IncidentState = "new" | "acknowledged" | "investigating" | "resolved";
export const INCIDENT_STATES: IncidentState[] =
  ["new", "acknowledged", "investigating", "resolved"];

export interface Incident {
  id: string;
  runId: string;
  entity: string;
  entityKind: "ip" | "host" | "rule";
  title: string;
  severity: string;              // max member severity — display aggregation
  state: IncidentState;
  findingIds: string[];
  findingCount: number;
  techniques: Technique[];
  attackerStatus: string;        // "" when unmapped
  createdAt: string | null;      // earliest finding time = detection
  firstSeen: string | null;
  lastSeen: string | null;
  acknowledgedAt: string | null; // stamped by the analyst, else null
  resolvedAt: string | null;
  timeUncertain: boolean;
}

export interface Asset {
  id: string; name: string; kind: "host" | "ip";
  events: number; findings: number; atRisk: boolean;
  lastSeen: string | null;
}

export interface UserEntity {
  id: string; name: string; events: number; findings: number; atRisk: boolean;
}

export interface ThreatIndicator {
  id: string; name: string; pattern: string;
  types: string[]; validFrom: string;
}

export interface ThreatIntel {
  indicators: ThreatIndicator[];
  indicatorSource: string;
  ruleTechniques: Record<string, Technique[]>;
  attackCacheWarm: boolean;
}

export interface Report { name: string; bytes: number; createdAt: string }

/** Both /api/assets and /api/users return {error} (HTTP 200) when the server
 *  is idle — an empty inventory is indistinguishable from "nothing at risk". */
type OrError<T> = T | { error: string };

// --- Cases (Phase C) ---
export type CaseStatus = "open" | "investigating" | "closed";
export const CASE_STATUSES: CaseStatus[] = ["open", "investigating", "closed"];

export interface Case {
  id: string;
  title: string;
  notes: string;
  assignee: string;
  status: CaseStatus;
  links: { findings: string[]; incidents: string[] };
  createdAt: string;
  updatedAt: string;
}

export interface CaseCreate {
  title: string;
  notes?: string;
  assignee?: string;
  links?: { findings?: string[]; incidents?: string[] };
}

export type CasePatch = Partial<Pick<Case, "title" | "notes" | "assignee" | "status">>;

// --- Settings (Phase C) ---
/** Masked compute config from /api/compute — the key is never exposed, only
 *  whether one is set (`hasKey`). Remote fields are absent when mode is local. */
export interface ComputeConfig {
  mode: "local" | "remote";
  baseUrl?: string;
  model?: string;
  hasKey?: boolean;
}

export interface ComputeInput {
  mode: "local" | "remote";
  baseUrl?: string;
  model?: string;
  apiKey?: string;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  overview: () => getJson<OverviewResponse>("/api/overview"),
  consoleState: () => getJson<ConsoleState>(`/console_state.json?t=${Date.now()}`),
  runs: () => getJson<{ runs: RunEntry[]; current?: string | null }>("/api/runs"),
  runsSummary: () => getJson<RunsSummary>("/api/runs-summary"),
  metrics: () => getJson<Metrics>("/api/metrics"),
  progress: () => getJson<AnalyzeJob>("/api/progress"),

  /** Load a saved run back into the dashboard (POST /api/open). */
  openRun: async (file: string): Promise<{ ok: boolean; error?: string }> => {
    const res = await fetch("/api/open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file }),
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  ask: async (question: string): Promise<{ answer?: string; error?: string }> => {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    return res.json();
  },

  /** Stream the analyst reply token-by-token over SSE. `onDelta` fires per
   *  chunk; resolves when the model sends `done`. Pass an AbortSignal to
   *  cancel — the backend stops when the connection drops. Errors (unreachable
   *  model, HTTP failure, or an `error` event) reject honestly. */
  askStream: async (
    question: string,
    onDelta: (text: string) => void,
    signal?: AbortSignal,
  ): Promise<void> => {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, stream: true }),
      signal,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error ?? `HTTP ${res.status}`);
    }
    if (!res.body) throw new Error("this browser cannot read a streamed reply");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // SSE frames are separated by a blank line.
      let sep: number;
      while ((sep = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const line = frame.split("\n").find((l) => l.startsWith("data:"));
        if (!line) continue;
        const evt = JSON.parse(line.slice(5).trim()) as
          { delta?: string; done?: boolean; error?: string };
        if (evt.error) throw new Error(evt.error);
        if (evt.done) return;
        if (evt.delta) onDelta(evt.delta);
      }
    }
  },

  analyzeUpload: async (file: File): Promise<{ ok: boolean; error?: string }> => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/analyze", { method: "POST", body: form });
    if (res.ok || res.status === 202) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  // --- Phase C endpoints ---
  incidents: (state?: IncidentState) =>
    getJson<{ incidents: Incident[] }>(
      `/api/incidents${state ? `?state=${state}` : ""}`),
  incident: (id: string) => getJson<OrError<Incident>>(`/api/incidents/${id}`),

  /** Analyst lifecycle transition (POST /api/incidents/<id>/state). Returns the
   *  updated incident; 400 (bad state) / 404 (unknown id) reject honestly. */
  setIncidentState: async (id: string, state: IncidentState): Promise<Incident> => {
    const res = await fetch(`/api/incidents/${id}/state`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    return body as Incident;
  },

  assets: () => getJson<OrError<{ assets: Asset[] }>>("/api/assets"),
  users: () => getJson<OrError<{ users: UserEntity[] }>>("/api/users"),
  threatIntel: () => getJson<ThreatIntel>("/api/threat-intel"),

  reports: () => getJson<{ reports: Report[] }>("/api/reports"),

  /** Generate a report for the CURRENT run (POST /api/reports). 409 when no run
   *  is loaded — the exporter has nothing real to render. */
  generateReport: async (): Promise<Report> => {
    const res = await fetch("/api/reports", { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    return body as Report;
  },

  // --- Cases (Phase C) ---
  // Analyst-entered records in cases.json: GET list, POST create (title
  // required), PATCH one by id. The store is the only writer; nothing is
  // derived — an empty store honestly means no cases.
  listCases: () => getJson<{ cases: Case[] }>("/api/cases"),

  createCase: async (input: CaseCreate): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  patchCase: async (id: string, patch: CasePatch): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch(`/api/cases/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  // --- Settings (Phase C) ---
  // The masked compute config (never the API key itself). Only real,
  // effective knobs — mode local/remote, and for remote the base URL/model.
  getCompute: () => getJson<ComputeConfig>("/api/compute"),

  setCompute: async (input: ComputeInput): Promise<{ ok: boolean; config?: ComputeConfig; error?: string }> => {
    const res = await fetch("/api/compute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, config: body as ComputeConfig }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },
};
