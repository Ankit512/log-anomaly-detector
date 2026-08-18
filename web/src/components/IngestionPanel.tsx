import { useRef, useState } from "react";
import { Check, Upload } from "lucide-react";
import { api, type OverviewData } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Upload zone posting to the EXISTING /api/analyze. Analysis progress lives
 *  on the Alerts side; this panel only starts it and says so honestly. */
export function IngestionPanel({ ingestion }: { ingestion?: OverviewData["ingestion"] }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [note, setNote] = useState(
    "Files are analyzed locally by the rules engine; open Alerts to review results.",
  );
  const [hot, setHot] = useState(false);

  const upload = async (files: FileList | null) => {
    const file = files?.[0];
    if (!file) return;
    const out = await api.analyzeUpload(file).catch(() => ({ ok: false as const, error: "no backend" }));
    setNote(out.ok
      ? "Analysis started — open Alerts to watch progress and review findings."
      : `The server did not accept this file${out.error ? `: ${out.error}` : ""}.`);
  };

  return (
    <Card>
      <CardHeader><CardTitle>Data Ingestion</CardTitle></CardHeader>
      <CardContent className="space-y-2.5">
        <button
          className={`w-full rounded-lg border-[1.5px] border-dashed px-3 py-5 text-center text-xs text-muted-foreground ${hot ? "border-primary bg-accent" : ""}`}
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setHot(true); }}
          onDragLeave={() => setHot(false)}
          onDrop={(e) => { e.preventDefault(); setHot(false); upload(e.dataTransfer.files); }}
        >
          <Upload className="mx-auto mb-1 h-4 w-4" aria-hidden />
          <span className="block text-[12.5px] font-semibold text-foreground">Upload Logs</span>
          Drag &amp; drop or select files
          <span className="mt-0.5 block text-[10.5px]">
            Accepted: {ingestion?.acceptedLabel ?? "CSV, JSON, TXT, RAW, HTML"}
          </span>
        </button>
        <input ref={fileRef} type="file" multiple hidden data-testid="ingest-file"
               onChange={(e) => upload(e.target.files)} />
        <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
          Browse Files
        </Button>
        {(ingestion?.files?.length ?? 0) > 0 && (
          <ul className="space-y-1">
            {ingestion!.files.map((f) => (
              <li key={f.name} className="flex items-center gap-2 rounded bg-muted px-2 py-1 text-xs text-muted-foreground">
                <Check className="h-3.5 w-3.5" style={{ color: "var(--sev-low)" }} aria-hidden />
                {f.name}
              </li>
            ))}
          </ul>
        )}
        <p className="text-[11px] text-muted-foreground">{note}</p>
      </CardContent>
    </Card>
  );
}
