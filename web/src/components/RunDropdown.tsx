import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Calendar } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/** The header run/version selector — the v6 time-range dropdown repurposed as
 *  the primary run switcher. Each saved run is an option (source + timestamp,
 *  newest first); choosing one POSTs /api/open and refreshes every query so
 *  the whole Overview switches to it. Honest: options are only real saved
 *  runs, unparsed runs are labelled, and a single-run history says so. The
 *  RunHistory popover remains as the richer per-run detail view. */
export function RunDropdown() {
  const queryClient = useQueryClient();
  const [switching, setSwitching] = useState(false);

  const { data: runs } = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const list = runs?.runs ?? [];
  const current = runs?.runs.find((r) => r.runId === runs?.current)?.file ?? "";

  const label = (r: (typeof list)[number]) => {
    const name = (r.label || r.file).split("/").pop() ?? r.file;
    const when = (r.generatedAt || "").slice(0, 16).replace("T", " ");
    return `${name}${when ? ` · ${when}` : ""}${r.unrecognized ? " · unparsed" : ""}`;
  };

  const onChange = async (file: string) => {
    if (!file || file === current) return;
    setSwitching(true);
    const out = await api.openRun(file).catch(() => ({ ok: false as const }));
    setSwitching(false);
    if (out.ok) await queryClient.invalidateQueries();
  };

  // No runs yet: a plain, honest label instead of an empty dropdown.
  if (list.length === 0) {
    return (
      <span className="inline-flex items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2.5 text-[13.5px] text-muted-foreground"
            title="No saved runs yet — analyze a log to start the history">
        <Calendar className="h-4 w-4" strokeWidth={1.8} aria-hidden />
        No runs yet
      </span>
    );
  }

  return (
    <span className={cn(
      "relative inline-flex items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2.5 text-[13.5px]",
      switching && "opacity-70",
    )}
          title={list.length === 1
            ? "The only saved run so far — analyze more logs to switch between runs"
            : "Switch the dashboard to a previous run"}>
      <Calendar className="h-4 w-4 flex-none" strokeWidth={1.8} aria-hidden />
      <select
        aria-label="Select run"
        value={current}
        disabled={switching}
        onChange={(e) => onChange(e.target.value)}
        className="max-w-[220px] cursor-pointer truncate bg-transparent pr-1 text-[13.5px] outline-none"
      >
        {list.map((r) => (
          <option key={r.file} value={r.file}>{label(r)}</option>
        ))}
      </select>
    </span>
  );
}
