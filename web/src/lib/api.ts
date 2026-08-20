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
  /** Absolute path of the analyzed log on the server — the value GET
   *  /api/stream accepts for tailing the CURRENT run's log (the backend
   *  whitelist is bundled samples + an exact match on this path). */
  logPath?: string;
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

/** Downloadable export formats served by GET /api/export. Each is a real
 *  serialization of the CURRENT run's findings (console/export.py) — no
 *  fabricated rows. `label`/`ext` drive the Download panel controls. */
export type ExportFormat = "csv" | "html" | "xml" | "json" | "md";
export const EXPORT_FORMATS: { format: ExportFormat; label: string; ext: string }[] = [
  { format: "csv", label: "CSV", ext: "csv" },
  { format: "json", label: "JSON", ext: "json" },
  { format: "xml", label: "XML", ext: "xml" },
  { format: "html", label: "HTML", ext: "html" },
  { format: "md", label: "Markdown", ext: "md" },
];

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

// --- Live syslog collector (socf-syslog) ---
// The real state of the background UDP/TCP listener. `exposed` is true only
// when bound to 0.0.0.0 (reachable from the network) — the UI warns on it.
export interface SyslogStatus {
  running: boolean;
  bind: string;
  port: number;
  protocols: string[];
  exposed: boolean;
  receivedCount: number;
  storedCount: number;
  startedAt: string | null;
  lastEventAt: string | null;
  error: string;
}
export interface SyslogStart {
  port: number;
  bind: string;
}

// One row from the persistent store's `events` table (the fields the collector
// panel shows to confirm received syslog actually landed). `severity` is the
// SOURCE-REPORTED level, never a verdict.
export interface StoreEvent {
  id: number;
  ts: string;
  source: string;
  source_type: string;
  host: string;
  src_ip: string;
  severity: string;
  message: string;
  raw: string;
  // Present on the full events read (History page); optional so the syslog
  // panel's narrower use keeps type-checking.
  category?: string;
  event_id?: string;
  user?: string;
  dst_ip?: string;
  action?: string;
}
export interface StoreEventsPage {
  items: StoreEvent[];
  total: number;
  limit: number;
  offset: number;
}

// --- nmap discovery + vuln scan (socf-discovery) ---
// The REAL state of the scanner. This is a dual-use tool: only private/
// loopback/link-local targets are ever accepted (the backend refuses a public
// or publicly-resolving target with an honest 400), every scan is user-
// initiated, and when nmap is not installed the backend returns an honest
// error — never a simulated result. Results land in the persistent store and
// are read back through /api/store/{assets,vulns}.
export interface DiscoveryStatus {
  running: boolean;
  target: string;
  vuln: boolean;
  startedAt: string | null;
  finishedAt: string | null;
  error: string;
  hostsFound: number;
  assetsStored: number;
  vulnsStored: number;
  nmapInstalled: boolean;
}
export interface DiscoveryScanInput {
  target: string;
  vuln?: boolean;
}

// One row from the store's `assets` table — a host nmap actually observed.
export interface StoreAsset {
  id: number;
  ts: string;
  ip: string;
  hostname: string;
  mac: string;
  vendor: string;
  os: string;
  ports: string;
  source: string;
  status: string;
}
export interface StoreAssetsPage {
  items: StoreAsset[];
  total: number;
  limit: number;
  offset: number;
}

// One row from the store's `vulnerabilities` table. `severity` is derived from
// the NSE-reported CVSS band (empty when NSE gave no score) — never guessed.
export interface StoreVuln {
  id: number;
  ts: string;
  asset_ip: string;
  name: string;
  cve: string;
  severity: string;
  cvss: number;
  details: string;
  source: string;
  status: string;
}
export interface StoreVulnsPage {
  items: StoreVuln[];
  total: number;
  limit: number;
  offset: number;
}

// --- TI enrichment + OEM polling (socf-ti-oem) ---
// All keys/tokens are user-supplied and stored secret-masked — the browser only
// ever learns whether one is present (hasKey/hasToken), never the value.
// Verdicts/severity come from the provider's / vendor's real response.
export interface TiKeyStatus { otx: boolean; abuseipdb: boolean }

// One row from the store's `iocs` table — a real provider lookup result.
export interface StoreIoc {
  id: number;
  ts: string;
  ioc: string;
  ioc_type: string;
  provider: string;
  score: number;
  verdict: string;
  details: string;
  source_event_id: number | null;
}
export interface StoreIocsPage {
  items: StoreIoc[]; total: number; limit: number; offset: number;
}

/** POST /api/ti/enrich result. A provider with no key set is listed in
 *  `notConfigured` (not called); a failed call is in `errors` with the real
 *  reason; only real hits are in `results`. `error` is set for an invalid IP. */
export interface TiEnrichResult {
  ip: string;
  error?: string;
  results: StoreIoc[];
  errors: { provider: string; error: string }[];
  notConfigured: string[];
}

/** Browser-safe OEM connector view — presence flags only, never the config
 *  blob or the token. `lastRun`/`lastError` are the REAL poll outcome. */
export interface OemConnector {
  name: string;
  kind: string;
  enabled: boolean;
  interval: number | null;
  lastRun: string | null;
  lastError: string;
  hasConfig: boolean;
  hasToken: boolean;
}
export interface OemConnectorInput {
  name: string;
  config: { vendor?: string; baseUrl?: string; eventsPath?: string };
  enabled?: boolean;
  interval?: number;
  token?: string;
}
export interface OemPollResult {
  name: string; ok: boolean; stored: number; error: string;
}

// --- EVTX ingest + history/retention (socf-evtx-history) ---
// Command-Center KPI counts from store.metrics(). `critical`/`high` count
// SOURCE-REPORTED severities, not anomaly verdicts — label them as such.
export interface StoreMetrics {
  events: number; critical: number; high: number;
  assets: number; openVulns: number; iocHits: number;
}

/** Public settings view: non-secret values, plus which secret keys are set. */
export interface PublicSettings {
  settings: Record<string, string>;
  secrets: Record<string, boolean>;
}

export interface EvtxStatus { available: boolean; message: string }
export interface EvtxIngestResult {
  stored: number; parsed: number; skipped: number; file?: string;
}

/** Filters for the history events read (all optional). */
export interface HistoryQuery {
  q?: string; severity?: string; source_type?: string; host?: string;
  limit?: number; offset?: number;
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

  /** Ingest a log from a public URL: the backend fetches it (http/https only,
   *  SSRF/size/text-gated) and runs the SAME analyze pipeline. A bad or unsafe
   *  URL comes back as an honest 400 with the real reason. */
  analyzeUrl: async (url: string): Promise<{ ok: boolean; error?: string }> => {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
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

  /** URL of a downloadable export of the CURRENT run in `format` (GET
   *  /api/export). The backend sets Content-Disposition: attachment and a
   *  <runId>.<ext> filename; used as an <a href download>. 409 when idle. */
  exportUrl: (format: ExportFormat) => `/api/export?format=${format}`,

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

  // --- Syslog collector (socf-syslog) ---
  // Poll the REAL listener state; start/stop the background UDP+TCP listener.
  // A failed start (bad/privileged port, in use) comes back as an honest error.
  syslogStatus: () => getJson<SyslogStatus>("/api/syslog/status"),

  /** Recent events from the persistent store, filtered to the syslog collector,
   *  newest first — used to confirm received messages actually landed. */
  syslogEvents: (limit = 15) =>
    getJson<StoreEventsPage>(`/api/store/events?source_type=syslog&limit=${limit}`),

  syslogStart: async (input: SyslogStart): Promise<{ ok: boolean; status?: SyslogStatus; error?: string }> => {
    const res = await fetch("/api/syslog/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: body as SyslogStatus }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  syslogStop: async (): Promise<{ ok: boolean; status?: SyslogStatus; error?: string }> => {
    const res = await fetch("/api/syslog/stop", { method: "POST" });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: body as SyslogStatus }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  // --- nmap discovery + vuln scan (socf-discovery) ---
  // Poll the REAL scanner state; launch a scan (always user-initiated). A
  // refused target (public / not private) or a missing nmap comes back as an
  // honest error, never a fake OK. Discovered assets/vulns are read back from
  // the persistent store.
  discoveryStatus: () => getJson<DiscoveryStatus>("/api/discovery/status"),

  discoveryScan: async (
    input: DiscoveryScanInput,
  ): Promise<{ ok: boolean; status?: DiscoveryStatus; error?: string }> => {
    const res = await fetch("/api/discovery/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: body as DiscoveryStatus }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Discovered hosts from the persistent store (assets table), newest first. */
  discoveryAssets: (limit = 100) =>
    getJson<StoreAssetsPage>(`/api/store/assets?source=nmap&limit=${limit}`),

  /** Vulnerabilities from the persistent store, newest first. Severity is the
   *  NSE-reported CVSS band (empty = unknown), never keyword-guessed. */
  vulns: (limit = 200) =>
    getJson<StoreVulnsPage>(`/api/store/vulns?limit=${limit}`),

  // --- TI enrichment + OEM polling (socf-ti-oem) ---
  // Keys/tokens are user-supplied and stored masked; the browser only sees
  // presence. Verdicts come from real provider/vendor responses — never faked.
  tiKeys: () => getJson<TiKeyStatus>("/api/ti/keys"),

  /** Enrich one IP via every configured provider. An unconfigured provider is
   *  reported (not called); a failed call carries the real error; only real
   *  hits are stored + returned. Read the full IOC history from /api/store/iocs. */
  tiEnrich: async (ip: string): Promise<TiEnrichResult> => {
    const res = await fetch("/api/ti/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok && !(body as TiEnrichResult).ip) {
      throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    }
    return body as TiEnrichResult;
  },

  /** Store an IOC lookup value (masked secret) via the store settings endpoint.
   *  Used to save the OTX / AbuseIPDB API keys — the value is write-only. */
  setTiKey: async (which: "otx" | "abuseipdb", value: string): Promise<TiKeyStatus> => {
    const key = which === "otx" ? "otx_api_key" : "abuseipdb_api_key";
    await fetch("/api/store/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, value }),
    });
    return getJson<TiKeyStatus>("/api/ti/keys");
  },

  /** IOC lookups from the persistent store, newest first. A verdict of
   *  malicious/suspicious is a hit; the score is the provider's real number. */
  iocs: (limit = 200) =>
    getJson<StoreIocsPage>(`/api/store/iocs?limit=${limit}`),

  oemConnectors: () => getJson<{ connectors: OemConnector[] }>("/api/oem/connectors"),

  oemCreateConnector: async (
    input: OemConnectorInput,
  ): Promise<{ ok: boolean; connector?: OemConnector; error?: string }> => {
    const res = await fetch("/api/oem/connectors", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, connector: body as OemConnector }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Poll one connector now. A placeholder base URL or a failed call is an
   *  honest error that stores nothing — never a fabricated event. */
  oemPoll: async (name: string): Promise<OemPollResult> => {
    const res = await fetch("/api/oem/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    return body as OemPollResult;
  },

  // --- EVTX ingest + history/retention (socf-evtx-history) ---
  /** Whether the optional python-evtx parser is installed. When false, an .evtx
   *  ingest returns an honest install message rather than a fake parse. */
  evtxStatus: () => getJson<EvtxStatus>("/api/evtx/status"),

  /** Ingest a Windows .evtx file into the store. A missing python-evtx library
   *  comes back as an honest error — never a simulated parse. */
  evtxIngest: async (file: File): Promise<{ ok: boolean; result?: EvtxIngestResult; error?: string }> => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/evtx/ingest", { method: "POST", body: form });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, result: body as EvtxIngestResult }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Persistent history events (filter/paginate). Empty table -> honest empty. */
  historyEvents: (query: HistoryQuery = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== "" && v !== null) qs.set(k, String(v));
    }
    if (!qs.has("limit")) qs.set("limit", "100");
    return getJson<StoreEventsPage>(`/api/store/events?${qs.toString()}`);
  },

  /** Command-Center KPI counts (store.metrics). */
  storeMetrics: () => getJson<StoreMetrics>("/api/store/metrics"),

  /** The store's public settings (retention_days lives here). */
  storeSettings: () => getJson<PublicSettings>("/api/store/settings"),

  setRetentionDays: async (days: number): Promise<PublicSettings> => {
    const res = await fetch("/api/store/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: "retention_days", value: String(days) }),
    });
    return res.json() as Promise<PublicSettings>;
  },

  /** Retention purge of history older than N days (default: stored retention). */
  storeCleanup: async (days?: number): Promise<{ deleted: Record<string, number>; retentionDays: number }> => {
    const res = await fetch("/api/store/cleanup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(days === undefined ? {} : { days }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    return body as { deleted: Record<string, number>; retentionDays: number };
  },

  /** DESTRUCTIVE full wipe of all data tables. Requires {confirm:true}; the UI
   *  gates this behind a typed confirmation. */
  storePurge: async (): Promise<{ purged: Record<string, number> }> => {
    const res = await fetch("/api/store/purge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    return body as { purged: Record<string, number> };
  },
};
