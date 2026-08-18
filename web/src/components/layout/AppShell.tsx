import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Bell, Calendar, FileText, Filter, Folder, House, LogOut, Monitor,
  RefreshCw, Settings, Shield, ShieldCheck, TriangleAlert, Upload,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useUi } from "@/store/ui";
import { cn } from "@/lib/utils";

/** The uniform v6 shell: every route renders inside this exact frame, so the
 *  sidebar, header, and page container are identical across the app. */

export const NAV = [
  { to: "/", label: "Overview", icon: House, ready: true },
  { to: "/alerts", label: "Alerts", icon: Bell, ready: true },
  { to: "/incidents", label: "Incidents", icon: TriangleAlert, ready: false },
  { to: "/threat-intel", label: "Threat Intel", icon: Shield, ready: false },
  { to: "/assets", label: "Assets", icon: Monitor, ready: false },
  { to: "/reports", label: "Reports", icon: FileText, ready: false },
  { to: "/cases", label: "Cases", icon: Folder, ready: false },
  { to: "/settings", label: "Settings", icon: Settings, ready: false },
] as const;

const TITLES: Record<string, string> = {
  "/": "SOC Dashboard", "/alerts": "Alerts", "/incidents": "Incidents",
  "/threat-intel": "Threat Intel", "/assets": "Assets", "/reports": "Reports",
  "/cases": "Cases", "/settings": "Settings",
};

function Sidebar() {
  return (
    <aside className="flex w-[172px] flex-none flex-col border-r bg-card px-3 py-[18px]">
      <div className="px-2.5 pb-[22px]">
        <ShieldCheck className="h-[34px] w-[34px] text-primary" strokeWidth={1.8} role="img" aria-label="itsoc" />
      </div>
      <nav aria-label="Main" className="flex flex-col gap-[3px]">
        {NAV.map(({ to, label, icon: Icon, ready }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            title={ready ? undefined : "Not built yet — the page says so honestly"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-[11px] rounded-md px-[11px] py-[9px] text-[13.5px] text-muted-foreground hover:bg-background",
                isActive && "bg-accent font-semibold text-accent-foreground hover:bg-accent",
              )
            }
          >
            <Icon className="h-[17px] w-[17px] flex-none" strokeWidth={1.8} aria-hidden />
            {label}
          </NavLink>
        ))}
        <button
          disabled
          title="No session system yet — nothing behind this item"
          className="mt-8 flex cursor-not-allowed items-center gap-[11px] rounded-md px-[11px] py-[9px] text-left text-[13.5px] text-muted-foreground opacity-55"
        >
          <LogOut className="h-[17px] w-[17px] flex-none" strokeWidth={1.8} aria-hidden />
          Logout
        </button>
      </nav>
    </aside>
  );
}

/** How often the header polls /api/progress while an analysis runs. */
const PROGRESS_POLL_MS = 1500;
const PROGRESS_POLL_MAX = 400; // ~10 minutes — after that, say so honestly

/** Header upload: the design's primary action, posting to the real
 *  /api/analyze compute path, then following /api/progress to the actual
 *  outcome. Feedback is honest text — success with the finding count, or the
 *  job's own error — never a fire-and-forget "started". */
function UploadButton({ onNote }: { onNote: (note: string) => void }) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);

  const waitForJob = async (name: string) => {
    for (let i = 0; i < PROGRESS_POLL_MAX; i++) {
      await new Promise((r) => setTimeout(r, PROGRESS_POLL_MS));
      const job = await api.progress().catch(() => null);
      if (!job) return { status: "error" as const, error: "the backend stopped answering" };
      if (job.status !== "running") return job;
      onNote(`Analyzing ${name}… ${job.phase ?? "working"}`
        + (job.total ? ` ${job.done ?? 0}/${job.total}` : "")
        + (job.note ? ` — ${job.note}` : ""));
    }
    return { status: "error" as const, error: "timed out waiting for the analysis" };
  };

  const upload = async (files: FileList | null) => {
    if (!files?.length || busy) return;
    setBusy(true);
    try {
      // One analysis at a time (the backend enforces it): files go through
      // sequentially, each becoming a run; the last one is the current run.
      for (const file of Array.from(files)) {
        onNote(`Uploading ${file.name}…`);
        const out = await api.analyzeUpload(file)
          .catch(() => ({ ok: false as const, error: "the backend is not reachable" }));
        if (!out.ok) {
          onNote(`The server did not accept ${file.name}${out.error ? `: ${out.error}` : ""}.`);
          continue;
        }
        const job = await waitForJob(file.name);
        if (job.status === "error") {
          onNote(`Analysis of ${file.name} failed: ${job.error ?? "unknown error"}`);
          continue;
        }
        await queryClient.invalidateQueries();
        onNote(`${file.name} analyzed — ${job.findings ?? 0} finding(s)`
          + (job.note ? ` · ${job.note}` : "") + ". Open Alerts for evidence.");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <label
      title="Accepted: LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text. Analyzed locally by the rules engine; results open in Alerts"
      className={cn(
        "inline-flex cursor-pointer items-center gap-2 whitespace-nowrap rounded-[10px] border border-primary bg-primary px-[15px] py-2.5 text-[13.5px] font-semibold text-primary-foreground hover:opacity-90",
        busy && "cursor-progress opacity-70",
      )}
    >
      <Upload className="h-4 w-4" strokeWidth={1.8} aria-hidden />
      {busy ? "Analyzing…" : "Upload Logs"}
      <input
        type="file" multiple className="hidden" data-testid="ingest-file"
        aria-label="Upload logs" disabled={busy}
        onChange={(e) => { upload(e.target.files); e.target.value = ""; }}
      />
    </label>
  );
}

const chip = "inline-flex items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2.5 text-[13.5px]";

function Header() {
  const { pathname } = useLocation();
  const timeWindow = useUi((s) => s.timeWindow);
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div>
        <h1 className="text-[26px] font-bold leading-tight tracking-[-0.015em]">
          {TITLES[pathname] ?? "itsoc"}
        </h1>
        <div className="mt-px text-sm font-medium text-accent-foreground">Security Overview</div>
      </div>
      <div className="ml-auto flex flex-wrap items-center gap-2.5">
        <UploadButton onNote={setNote} />
        <span
          className={cn(chip, "text-muted-foreground")}
          title="The current run's own window. History-window filtering does not exist yet, so this states what is shown rather than offering a choice."
        >
          <Calendar className="h-4 w-4" strokeWidth={1.8} aria-hidden />
          {timeWindow}
        </span>
        <button className={cn(chip, "cursor-pointer hover:bg-background")}
                onClick={() => queryClient.invalidateQueries()}>
          <RefreshCw className="h-4 w-4" strokeWidth={1.8} aria-hidden />
          Refresh
        </button>
        <button disabled title="Filtering is not built yet — alert filters live on the Alerts page"
                className={cn(chip, "cursor-not-allowed opacity-50")}>
          <Filter className="h-4 w-4" strokeWidth={1.8} aria-hidden />
          Filters
        </button>
        <ThemeToggle />
      </div>
      {note && <p className="w-full text-xs text-muted-foreground" role="status">{note}</p>}
    </div>
  );
}

/** The run-facts line under the Overview header — every segment is read from
 *  the adapter state or the overview payload; absent facts are omitted, never
 *  filled in. Overview-only: Alerts carries its own run banner. */
function RunFacts() {
  const { data: state } = useQuery({ queryKey: ["consoleState"], queryFn: api.consoleState });
  const { data: ov } = useQuery({ queryKey: ["overview"], queryFn: api.overview });

  if (!state || state.idle || !state.findings) return null;
  const sha = state.manifest?.detector_sha256;
  const model = ov && !("error" in ov) ? ov.model : null;
  const meta = [
    state.runWindow, state.manifest?.ruleset && `ruleset ${state.manifest.ruleset}`,
    model, state.generatedAt && `generated ${state.generatedAt}`,
  ].filter(Boolean);

  return (
    <div className="flex flex-wrap items-center gap-x-[18px] gap-y-1.5 text-[11.5px] text-muted-foreground">
      {state.sourceLabel && (
        <span title={state.sourceLabel}
              className="cursor-help border-b border-dotted font-mono text-[12.5px] font-semibold text-foreground">
          {state.sourceLabel.split("/").pop()}
        </span>
      )}
      {state.runHosts && <span>host {state.runHosts}</span>}
      {state.runParsed && <span className="tabular-nums">{state.runParsed}</span>}
      {meta.length > 0 && (
        <span className="font-mono text-[10.5px]">
          {meta.map(String).join(" · ")}
          {sha && <span title={`detector_sha256 ${sha}`}> · detector {sha.slice(0, 8)}…{sha.slice(-6)}</span>}
        </span>
      )}
      {state.llmNote && (
        <span title={state.llmNote} className="cursor-help border-b border-dotted">
          rules-only run — explanations skipped (model offline)
        </span>
      )}
    </div>
  );
}

export function AppShell() {
  const { pathname } = useLocation();
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col gap-4 px-[22px] py-5">
        <Header />
        {pathname === "/" && <RunFacts />}
        <Outlet />
      </main>
    </div>
  );
}
