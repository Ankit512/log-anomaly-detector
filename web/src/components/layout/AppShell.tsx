import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  LayoutGrid, TriangleAlert, Siren, ShieldHalf, Server, FileText,
  FolderKanban, Settings, LogOut, RefreshCw, Search,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useUi } from "@/store/ui";
import { cn } from "@/lib/utils";

/** The uniform shell: every route renders inside this exact frame, so the
 *  sidebar, topbar, and page container are identical across the app. */

export const NAV = [
  { to: "/", label: "Overview", icon: LayoutGrid, ready: true },
  { to: "/alerts", label: "Alerts", icon: TriangleAlert, ready: true },
  { to: "/incidents", label: "Incidents", icon: Siren, ready: false },
  { to: "/threat-intel", label: "Threat Intel", icon: ShieldHalf, ready: false },
  { to: "/assets", label: "Assets", icon: Server, ready: false },
  { to: "/reports", label: "Reports", icon: FileText, ready: false },
  { to: "/cases", label: "Cases", icon: FolderKanban, ready: false },
  { to: "/settings", label: "Settings", icon: Settings, ready: false },
] as const;

const TITLES: Record<string, string> = {
  "/": "SOC Dashboard", "/alerts": "Alerts", "/incidents": "Incidents",
  "/threat-intel": "Threat Intel", "/assets": "Assets", "/reports": "Reports",
  "/cases": "Cases", "/settings": "Settings",
};

function Sidebar() {
  return (
    <aside className="flex w-56 flex-none flex-col gap-1 border-r bg-card p-3">
      <div className="mb-3 flex items-center gap-2.5 px-2 pt-1">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-[15px] font-bold text-primary-foreground">S</div>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold">itsoc</div>
          <div className="text-[10.5px] text-muted-foreground">security operations</div>
        </div>
      </div>
      <nav aria-label="Main" className="flex flex-col gap-0.5">
        {NAV.map(({ to, label, icon: Icon, ready }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] text-muted-foreground hover:bg-muted",
                isActive && "bg-accent font-semibold text-accent-foreground",
              )
            }
          >
            <Icon className="h-4 w-4" aria-hidden />
            {label}
            {!ready && (
              <span className="ml-auto rounded border px-1 py-px text-[8.5px] uppercase tracking-wide text-muted-foreground">
                soon
              </span>
            )}
          </NavLink>
        ))}
        <button
          disabled
          title="No session system yet — nothing behind this item"
          className="flex cursor-not-allowed items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] text-muted-foreground opacity-50"
        >
          <LogOut className="h-4 w-4" aria-hidden />
          Logout
          <span className="ml-auto rounded border px-1 py-px text-[8.5px] uppercase tracking-wide">soon</span>
        </button>
      </nav>
    </aside>
  );
}

function Topbar() {
  const { pathname } = useLocation();
  const timeWindow = useUi((s) => s.timeWindow);
  const search = useUi((s) => s.search);
  const setSearch = useUi((s) => s.setSearch);
  const queryClient = useQueryClient();

  return (
    <header className="flex flex-none flex-wrap items-center gap-3 border-b bg-card/50 px-5 py-3">
      <div>
        <h1 className="text-lg font-semibold leading-tight">{TITLES[pathname] ?? "itsoc"}</h1>
        <div className="text-xs text-muted-foreground">Security Overview</div>
      </div>
      <div className="ml-auto flex items-center gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" aria-hidden />
          <Input
            className="w-52 pl-8"
            placeholder="Search (coming soon)"
            aria-label="Global search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            disabled
            title="Global search needs a backend index — a later phase"
          />
        </div>
        {/* The label is what the backend actually serves: the current run's
            own window. History-window filtering is a later, honest feature. */}
        <span className="rounded-md border bg-card px-2.5 py-1.5 text-xs text-muted-foreground" title="Data window">
          {timeWindow}
        </span>
        <Button variant="outline" size="sm" onClick={() => queryClient.invalidateQueries()}>
          <RefreshCw className="h-4 w-4" aria-hidden /> Refresh
        </Button>
        <ThemeToggle />
      </div>
    </header>
  );
}

export function AppShell() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="min-w-0 flex-1 p-5">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
