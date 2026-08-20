import { useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import {
  createColumnHelper, flexRender, getCoreRowModel, getFilteredRowModel,
  getSortedRowModel, useReactTable, type Row,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { api, type Finding } from "@/lib/api";
import { useLogStream, type LogStream } from "@/lib/useLogStream";
import { sevVar, SEV_ORDER } from "@/lib/severity";
import { SeverityBadge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UnrecognizedBanner } from "@/components/UnrecognizedBanner";
import { cn } from "@/lib/utils";

const col = createColumnHelper<Finding>();

const columns = [
  col.accessor("sev", {
    header: "Severity",
    cell: (c) => <SeverityBadge severity={c.getValue()} />,
    sortingFn: (a, b) =>
      SEV_ORDER.indexOf(b.original.sev as never) - SEV_ORDER.indexOf(a.original.sev as never),
  }),
  col.accessor("time", {
    header: "Time",
    cell: (c) => <span className="font-mono text-[11.5px] text-muted-foreground">{c.getValue() || "—"}</span>,
  }),
  col.accessor("type", {
    header: "Rule",
    cell: (c) => <span className="font-mono text-[11.5px]">{c.getValue()}</span>,
  }),
  col.accessor("host", { header: "Host" }),
  col.accessor((f) => (f.mitre ?? []).map((m) => m.id).join(" "), {
    id: "mitre",
    header: "ATT&CK",
    cell: (c) =>
      c.row.original.mitre?.length
        ? c.row.original.mitre.map((m) => (
            <span key={m.id} className="mr-1 rounded bg-accent px-1.5 py-0.5 text-[10.5px] text-accent-foreground"
                  title={`${m.id} · ${m.name} · ${m.tactic} — derived, does not affect severity`}>
              {m.id}
            </span>
          ))
        : null,
  }),
  col.accessor("title", { header: "Finding" }),
];

/** Virtualize only past this row count: below it, plain rendering is simpler,
 *  and a small list should never depend on measured viewport height. */
const VIRTUALIZE_AT = 100;

/** Live tail of the current run's log via GET /api/stream (SSE). Streaming
 *  AUGMENTS the 5s polling — when the stream is down the panel says so and
 *  polling carries on; nothing is interpolated client-side. A gap marker is
 *  rendered wherever the server dropped events under backpressure: hiding it
 *  would fake a quiet log. */
function LiveTail({ stream }: { stream: LogStream }) {
  const recent = stream.rows.slice(-200);
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center gap-2.5">
          <CardTitle className="text-[14px]">Live tail</CardTitle>
          {stream.connected ? (
            <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground"
                  data-testid="stream-status">
              <span aria-hidden className="h-2 w-2 rounded-full"
                    style={{ background: "var(--sev-low)" }} />
              streaming — lines appear as the log grows
            </span>
          ) : (
            <span className="text-[11px] text-muted-foreground" data-testid="stream-status">
              {stream.unsupported
                ? "streaming unavailable in this browser — "
                : "stream disconnected — "}
              5s polling fallback active
            </span>
          )}
          {stream.dropped > 0 && (
            <span className="ml-auto rounded-md border px-2 py-0.5 text-[11px] font-semibold"
                  style={{
                    borderColor: "var(--sev-high)",
                    background: "color-mix(in srgb, var(--sev-high) 14%, transparent)",
                  }}
                  data-testid="stream-dropped">
              {stream.dropped} event(s) dropped under backpressure
            </span>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No new lines yet — the tail starts at the end of the current log and
            shows only what arrives after connecting.
          </p>
        ) : (
          <div className="max-h-[30vh] overflow-auto rounded-md border bg-muted/50 font-mono text-[11.5px]"
               data-testid="live-tail">
            {recent.map((row, i) =>
              row.kind === "gap" ? (
                <div key={`gap-${i}`} data-testid="gap-row"
                     className="border-b px-3 py-1 text-[11px] font-semibold last:border-0"
                     style={{ background: "color-mix(in srgb, var(--sev-high) 12%, transparent)" }}>
                  {row.dropped} event(s) dropped here (stream backpressure) — the log
                  itself is intact; a reconnect resumes from the last delivered line
                </div>
              ) : (
                <div key={row.event.n} data-testid="tail-row"
                     className="flex gap-3 border-b px-3 py-1 last:border-0">
                  <span className="w-12 flex-none text-right text-muted-foreground">
                    {row.event.n}
                  </span>
                  <span className="w-[72px] flex-none text-muted-foreground">
                    {row.event.ts ? row.event.ts.slice(11, 19) : "n/a"}
                  </span>
                  <span className="w-[72px] flex-none font-semibold"
                        style={{ color: sevVar(row.event.bucket) }}>
                    {row.event.bucket}
                  </span>
                  <span className="flex-1 whitespace-pre-wrap break-all">{row.event.raw}</span>
                </div>
              ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.sev} />
          <span className="font-mono text-[11px] text-muted-foreground">{f.type}</span>
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">{f.stamp}</span>
        </div>
        <CardTitle className="text-[16px] leading-snug">{f.title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-md border p-3">
            <div className="text-[9.5px] uppercase tracking-wide text-muted-foreground">Rule verdict · authoritative</div>
            <div className="mt-0.5 font-semibold" style={{ color: sevVar(f.sev) }}>{f.ruleSev}</div>
            <p className="mt-1 text-xs text-muted-foreground">{f.ruleWhy}</p>
          </div>
          <div className="rounded-md border p-3">
            <div className="text-[9.5px] uppercase tracking-wide text-muted-foreground">Plain-language explanation · advisory</div>
            <p className="mt-1 text-xs text-muted-foreground">
              {f.explanation || "Explanation pending — the deterministic verdict above is already final."}
            </p>
          </div>
        </div>

        {f.lines.length > 0 && (
          <div>
            <div className="mb-1 flex items-baseline gap-2">
              <h4 className="text-[13px] font-semibold">Evidence</h4>
              <span className="text-[11px] text-muted-foreground">
                {f.linesNote ?? "verbatim from the source log — nothing generated"}
              </span>
            </div>
            <div className="overflow-x-auto rounded-md border bg-muted/50 font-mono text-[11.5px]">
              {f.lines.map((l, i) => (
                <div key={i} className="flex gap-3 px-3 py-1"
                     style={l.crit ? { background: "color-mix(in srgb, var(--sev-critical) 10%, transparent)" } : undefined}>
                  <span className="w-10 flex-none text-right text-muted-foreground">{l.n}</span>
                  <span className="whitespace-pre-wrap break-all">
                    {l.a}
                    {l.hit && (
                      <mark className="rounded-sm px-0.5" style={{ background: "color-mix(in srgb, var(--sev-high) 35%, transparent)" }}>
                        {l.hit}
                      </mark>
                    )}
                    {l.b}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3 md:grid-cols-2">
          {f.predicate && (
            <div className="rounded-md border p-3">
              <div className="text-[9.5px] uppercase tracking-wide text-muted-foreground">Rule predicate that fired</div>
              <pre className="mt-1 whitespace-pre-wrap font-mono text-[11.5px] text-accent-foreground">{f.predicate}</pre>
              <div className="mt-1.5 font-mono text-[10.5px] text-muted-foreground">{f.ruleRef}</div>
            </div>
          )}
          {f.timeline.length > 0 && (
            <div className="rounded-md border p-3">
              <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">Event sequence</div>
              {f.timeline.map((t, i) => (
                <div key={i} className="flex gap-2.5 py-0.5 text-xs">
                  <span className="w-16 flex-none font-mono text-[10.5px] text-muted-foreground">{t.t}</span>
                  <span>{t.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export function Alerts() {
  const { data, isLoading } = useQuery({
    queryKey: ["console-state"],
    queryFn: api.consoleState,
    refetchInterval: 5000,
  });
  const [params, setParams] = useSearchParams();
  const [filter, setFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");

  // Live SSE tail of the run's log. Streams only when the state names its
  // source file; otherwise the hook is inert and 5s polling stands alone.
  const stream = useLogStream(data && !data.idle ? data.logPath : undefined);

  const allFindings = useMemo(() => {
    const base = data?.findings ?? [];
    // Streamed findings the loaded run does not already show. Same rule +
    // same summary = the same detector verdict, so those are not repeated.
    const live = stream.findings.filter(
      (f) => !base.some((b) => b.type === f.type && b.title === f.title));
    return [...base, ...live];
  }, [data, stream.findings]);

  const findings = useMemo(
    () => (sevFilter ? allFindings.filter((f) => f.sev === sevFilter) : allFindings),
    [allFindings, sevFilter]);

  const table = useReactTable({
    data: findings,
    columns,
    state: { globalFilter: filter },
    onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;
  const selId = params.get("sel");
  const selected = findings.find((f) => f.id === selId) ?? null;

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtual = rows.length > VIRTUALIZE_AT;
  const virtualizer = useVirtualizer({
    count: virtual ? rows.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 44,
    overscan: 12,
  });

  if (isLoading) return <p className="text-muted-foreground">Loading the current run…</p>;

  if (!data || data.idle) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          No run yet — analyze a log from the Overview's ingestion panel (or the
          legacy console). Findings will appear here.
        </CardContent>
      </Card>
    );
  }

  const renderRow = (row: Row<Finding>) => (
    <tr
      key={row.id}
      onClick={() => setParams({ sel: row.original.id })}
      className={cn(
        "cursor-pointer border-b last:border-0 hover:bg-muted/60 align-top",
        selected?.id === row.original.id && "bg-accent/60",
      )}
      data-testid="alert-row"
    >
      {row.getVisibleCells().map((cell) => (
        <td key={cell.id} className="px-2 py-2 text-[12.5px]">
          {flexRender(cell.column.columnDef.cell, cell.getContext())}
        </td>
      ))}
    </tr>
  );

  return (
    <div className="space-y-4">
      <UnrecognizedBanner state={data} />

      {data.logPath && <LiveTail stream={stream} />}

      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="w-72"
          placeholder="Filter findings…"
          aria-label="Filter findings"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <select
          className="h-9 rounded-md border border-input bg-card px-2 text-sm"
          aria-label="Severity filter"
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
        >
          <option value="">All severities</option>
          {SEV_ORDER.map((s) => <option key={s}>{s}</option>)}
        </select>
        <span className="text-xs text-muted-foreground">
          {rows.length} of {allFindings.length} finding(s) · {data.runParsed ?? ""}
        </span>
      </div>

      <Card>
        <div ref={scrollRef} className="max-h-[52vh] overflow-auto" data-testid="alerts-scroll">
          <table className="w-full">
            <thead className="sticky top-0 bg-card">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id} className="border-b text-left text-[10.5px] uppercase tracking-wide text-muted-foreground">
                  {hg.headers.map((h) => (
                    <th key={h.id} className="cursor-pointer px-2 py-2 select-none"
                        onClick={h.column.getToggleSortingHandler()}>
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {{ asc: " ▲", desc: " ▼" }[h.column.getIsSorted() as string] ?? null}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {virtual ? (
                <>
                  {virtualizer.getVirtualItems().length > 0 && (
                    <tr style={{ height: virtualizer.getVirtualItems()[0].start }} aria-hidden />
                  )}
                  {virtualizer.getVirtualItems().map((vi) => renderRow(rows[vi.index]))}
                  {virtualizer.getVirtualItems().length > 0 && (
                    <tr aria-hidden style={{
                      height: virtualizer.getTotalSize()
                        - (virtualizer.getVirtualItems().at(-1)!.end),
                    }} />
                  )}
                </>
              ) : (
                rows.map(renderRow)
              )}
              {rows.length === 0 && (
                <tr><td colSpan={columns.length} className="px-3 py-5 text-muted-foreground">
                  {data.findings.length === 0
                    ? (data.unrecognized || data.emptyInput
                       ? "Nothing was analyzed, so there are no findings to show."
                       : "All clear — 0 anomalies. Every rule evaluated; nothing crossed a threshold.")
                    : "Nothing matches this filter."}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {selected && <FindingDetail f={selected} />}
    </div>
  );
}
