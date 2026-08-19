import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Antenna, Bell, FileText, Filter, Folder, House, Link as LinkIcon, LogOut, Monitor,
  Radar, RefreshCw, Settings, Shield, ShieldAlert, ShieldCheck, TriangleAlert, Upload,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Dialog } from "@/components/ui/dialog";
import { RunHistory } from "@/components/RunHistory";
import { RunDropdown } from "@/components/RunDropdown";
import { IngestNotifier } from "@/components/IngestNotifier";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useJobs } from "@/store/jobs";
import { isBlobPageUrl, rawFileUrl } from "@/lib/rawUrl";
import { cn } from "@/lib/utils";

/** The uniform v6 shell: every route renders inside this exact frame, so the
 *  sidebar, header, and page container are identical across the app. */

export const NAV = [
  { to: "/", label: "Overview", icon: House, ready: true },
  { to: "/alerts", label: "Alerts", icon: Bell, ready: true },
  { to: "/incidents", label: "Incidents", icon: TriangleAlert, ready: true },
  { to: "/threat-intel", label: "Threat Intel", icon: Shield, ready: true },
  { to: "/assets", label: "Assets", icon: Monitor, ready: true },
  // socf-discovery: nmap network discovery + vulnerability scanning.
  { to: "/discovery", label: "Discovery", icon: Radar, ready: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, ready: true },
  { to: "/reports", label: "Reports", icon: FileText, ready: true },
  { to: "/cases", label: "Cases", icon: Folder, ready: true },
  // socf-syslog: live syslog collector control panel.
  { to: "/collectors", label: "Collectors", icon: Antenna, ready: true },
  { to: "/settings", label: "Settings", icon: Settings, ready: true },
] as const;

const TITLES: Record<string, string> = {
  "/": "SOC Dashboard", "/alerts": "Alerts", "/incidents": "Incidents",
  "/threat-intel": "Threat Intel", "/assets": "Assets",
  "/discovery": "Discovery", "/vulnerabilities": "Vulnerabilities",
  "/reports": "Reports",
  "/cases": "Cases", "/collectors": "Collectors", "/settings": "Settings",
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
        <NavLink
          to="/logout"
          title="Local single-user tool — no server session; clears local UI state"
          className={({ isActive }) =>
            cn(
              "mt-8 flex items-center gap-[11px] rounded-md px-[11px] py-[9px] text-left text-[13.5px] text-muted-foreground hover:bg-background",
              isActive && "bg-accent font-semibold text-accent-foreground hover:bg-accent",
            )
          }
        >
          <LogOut className="h-[17px] w-[17px] flex-none" strokeWidth={1.8} aria-hidden />
          Logout
        </NavLink>
      </nav>
    </aside>
  );
}

/** Header upload: the design's primary action, posting to the real
 *  /api/analyze path. It hands the file to the shell-level job store, which
 *  runs the analysis as a BACKGROUND job and drives the persistent
 *  IngestNotifier — so the upload survives navigating away from the Overview. */
const ACCEPTED_TITLE =
  "Accepted: LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text. Analyzed locally by the rules engine; results open in Alerts";

/** Two-mode ingest dialog: a local file OR a pasted public URL. Both feed the
 *  same background job store + IngestNotifier — the source is the only
 *  difference. URL validity/safety is enforced by the backend (honest error in
 *  the notifier); here we only sanity-check the shape before submitting. */
function UploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const startUpload = useJobs((s) => s.startUpload);
  const startUrl = useJobs((s) => s.startUrl);
  const [mode, setMode] = useState<"file" | "link">("file");
  const [url, setUrl] = useState("");

  // A repo "blob" URL is a web page, not the file — convert it to the raw URL
  // so the fetch gets the log instead of 500 lines of HTML.
  const isBlob = isBlobPageUrl(url);

  const submitUrl = () => {
    const u = rawFileUrl(url);
    if (!u.trim()) return;
    startUrl(u);         // the notifier takes over; a bad URL is an honest error
    setUrl("");
    onClose();
  };

  const seg = (active: boolean) => cn(
    "flex-1 rounded-md px-3 py-1.5 text-[12.5px] font-medium",
    active ? "bg-card shadow-card" : "text-muted-foreground hover:text-foreground",
  );

  return (
    <Dialog open={open} onClose={onClose} title="Add logs to analyze">
      <div className="mb-3 flex gap-1 rounded-lg bg-background p-1">
        <button className={seg(mode === "file")} onClick={() => setMode("file")}>
          Upload from this computer
        </button>
        <button className={seg(mode === "link")} onClick={() => setMode("link")}>
          Attach a link
        </button>
      </div>

      {mode === "file" ? (
        <div className="flex flex-col gap-2">
          <label
            title={ACCEPTED_TITLE}
            className="flex cursor-pointer flex-col items-center gap-1 rounded-lg border border-dashed px-4 py-6 text-center text-[12.5px] text-muted-foreground hover:border-primary"
          >
            <Upload className="h-5 w-5" strokeWidth={1.6} aria-hidden />
            <span className="text-[13px] font-semibold text-foreground">Choose a log file</span>
            Analyzed locally — the file never leaves this machine.
            <input
              type="file" multiple className="hidden" data-testid="ingest-file"
              aria-label="Upload logs"
              onChange={(e) => {
                if (e.target.files?.length) { startUpload(e.target.files); onClose(); }
                e.target.value = "";
              }}
            />
          </label>
          <p className="text-[11px] text-muted-foreground">{ACCEPTED_TITLE}</p>
        </div>
      ) : (
        <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); submitUrl(); }}>
          <label className="text-[11.5px] text-muted-foreground">
            Public URL of a raw log file
            <input
              className="mt-1 w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary"
              value={url} onChange={(e) => setUrl(e.target.value)}
              aria-label="Log file URL" placeholder="https://raw.githubusercontent.com/…/app.log"
              inputMode="url" autoComplete="off"
            />
          </label>
          {isBlob && (
            <p className="text-[11px]" style={{ color: "var(--sev-medium)" }}>
              That’s a web-page link, not the raw file — we’ll fetch the raw
              version instead: <span className="break-all font-mono">{rawFileUrl(url)}</span>
            </p>
          )}
          <p className="text-[11px] text-muted-foreground">
            The server fetches it (http/https only, public hosts, size- and
            text-gated) and runs the same analysis. A page that isn’t a text log
            is rejected honestly.
          </p>
          <div>
            <button type="submit" disabled={!url.trim()}
              className="inline-flex items-center gap-2 rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
              <LinkIcon className="h-4 w-4" strokeWidth={1.8} aria-hidden /> Fetch &amp; analyze
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function UploadButton() {
  const busy = useJobs((s) => s.busy);
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title={ACCEPTED_TITLE}
        className={cn(
          "inline-flex cursor-pointer items-center gap-2 whitespace-nowrap rounded-[10px] border border-primary bg-primary px-[15px] py-2.5 text-[13.5px] font-semibold text-primary-foreground hover:opacity-90",
          busy && "cursor-progress opacity-70",
        )}
      >
        <Upload className="h-4 w-4" strokeWidth={1.8} aria-hidden />
        {busy ? "Analyzing…" : "Upload Logs"}
      </button>
      <UploadDialog open={open} onClose={() => setOpen(false)} />
    </>
  );
}

const chip = "inline-flex items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2.5 text-[13.5px]";

function Header() {
  const { pathname } = useLocation();
  const queryClient = useQueryClient();

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div>
        <h1 className="text-[26px] font-bold leading-tight tracking-[-0.015em]">
          {TITLES[pathname] ?? "itsoc"}
        </h1>
        <div className="mt-px text-sm font-medium text-accent-foreground">Security Overview</div>
      </div>
      <div className="ml-auto flex flex-wrap items-center gap-2.5">
        <UploadButton />
        <RunDropdown />
        <RunHistory />
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
      {/* Shell-level: the upload runs as a background job and its notification
          persists across navigation, independent of any page. */}
      <IngestNotifier />
    </div>
  );
}
