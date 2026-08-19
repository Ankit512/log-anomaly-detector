import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, EXPORT_FORMATS } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Download, FileText } from "lucide-react";

const th = "px-2 py-2 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground";

function kb(bytes: number) {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
}

/** One control per export format. When a run is loaded each is a real
 *  <a href download> that hits GET /api/export?format=X — the backend answers
 *  with Content-Disposition: attachment, so the browser saves <runId>.<ext>.
 *  With no run loaded the controls are honestly disabled (the endpoint would
 *  409); we never offer a download that would produce an empty file. */
function DownloadPanel({ hasRun }: { hasRun: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-[15px]">Download the current run</CardTitle>
        <p className="text-[11.5px] text-muted-foreground">
          The real findings, severities and MITRE tags this run produced — no fabricated rows.
        </p>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex flex-wrap items-center gap-2" data-testid="download-panel">
          {EXPORT_FORMATS.map(({ format, label }) =>
            hasRun ? (
              <a
                key={format}
                href={api.exportUrl(format)}
                download
                data-testid={`download-${format}`}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border bg-card px-3 py-2",
                  "text-[12.5px] font-medium hover:bg-muted",
                )}
                title={`Download this run as ${label} (${format})`}
              >
                <Download className="h-4 w-4" strokeWidth={1.8} aria-hidden />
                {label}
              </a>
            ) : (
              <span
                key={format}
                data-testid={`download-${format}`}
                aria-disabled="true"
                className={cn(
                  "inline-flex cursor-not-allowed items-center gap-1.5 rounded-md border bg-card px-3 py-2",
                  "text-[12.5px] font-medium opacity-50",
                )}
                title="No run loaded — analyze a log first, then export"
              >
                <Download className="h-4 w-4" strokeWidth={1.8} aria-hidden />
                {label}
              </span>
            ),
          )}
        </div>
        {!hasRun && (
          <p className="mt-2 text-[11.5px] text-muted-foreground">
            No run loaded — analyze a log from the Overview, then download it here.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export function Reports() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["reports"],
    queryFn: api.reports,
  });
  const { data: state } = useQuery({ queryKey: ["console-state"], queryFn: api.consoleState });
  const hasRun = !!state && !state.idle;

  const generate = useMutation({
    mutationFn: api.generateReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });

  const reports = data?.reports ?? [];

  return (
    <div className="space-y-4">
      <Card className="border-dashed">
        <CardContent className="flex flex-wrap items-center gap-3 p-4 text-[12.5px] text-muted-foreground">
          <span>
            <b className="text-foreground">Real files only.</b>{" "}
            Every row is a report that exists on disk in <code className="font-mono">console/.soc/reports/</code>.
            Generating renders the <b>current run</b> through the standalone exporter — nothing is listed that wasn't produced.
          </span>
          <div className="ml-auto flex flex-col items-end gap-1">
            <Button
              onClick={() => generate.mutate()}
              disabled={generate.isPending}
              title="Render the currently loaded run into a saved HTML report"
            >
              <FileText className="h-4 w-4" strokeWidth={1.8} aria-hidden />
              {generate.isPending ? "Generating…" : "Generate report"}
            </Button>
            {generate.isError && (
              <span className="text-[11.5px]" style={{ color: "var(--sev-critical)" }}>
                {(generate.error as Error).message === "no run to report on yet"
                  ? "No run loaded — analyze a log first, then generate."
                  : (generate.error as Error).message}
              </span>
            )}
            {generate.isSuccess && (
              <span className="text-[11.5px]" style={{ color: "var(--sev-low)" }}>
                Saved {generate.data.name}
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      <DownloadPanel hasRun={hasRun} />

      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">Saved reports ({reports.length})</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          {isLoading ? (
            <p className="text-[12.5px] text-muted-foreground">Loading reports…</p>
          ) : isError ? (
            <p className="text-[12.5px] text-muted-foreground">
              Couldn't load reports — {(error as Error).message}
            </p>
          ) : reports.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              No reports generated yet — use “Generate report” above to render the current run.
            </p>
          ) : (
            <div className="overflow-auto rounded-md border">
              <table className="w-full">
                <thead className="bg-card">
                  <tr className="border-b">
                    <th className={th}>Report</th>
                    <th className={th}>Size</th>
                    <th className={th}>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.name} data-testid="report-row" className="border-b last:border-0 align-top hover:bg-muted/60">
                      <td className="px-2 py-2 font-mono text-[11.5px] break-all">{r.name}</td>
                      <td className="px-2 py-2 tabular-nums text-[12.5px]">{kb(r.bytes)}</td>
                      <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">{r.createdAt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
