import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderKanban, Pencil, Plus, X } from "lucide-react";
import { api, CASE_STATUSES, type Case, type CaseStatus } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";

/** Cases — analyst-entered investigation records (cases.json). Full CRUD over
 *  the real /api/cases endpoints: this is the one subsystem whose data is
 *  honestly stored because the analyst types it. No derivation, no invented
 *  rows — an empty store shows an honest empty state. */

const STATUS_STYLE: Record<CaseStatus, { label: string; color: string }> = {
  open: { label: "Open", color: "hsl(var(--primary))" },
  investigating: { label: "Investigating", color: "var(--sev-medium)" },
  closed: { label: "Closed", color: "hsl(var(--muted-foreground))" },
};

function StatusPill({ status }: { status: CaseStatus }) {
  const s = STATUS_STYLE[status];
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium"
          style={{ color: s.color, borderColor: s.color }}>
      <i className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

const field = "w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary";

function CreateCase() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [assignee, setAssignee] = useState("");
  const [notes, setNotes] = useState("");
  const [err, setErr] = useState("");

  const create = useMutation({
    mutationFn: () => api.createCase({ title, assignee, notes }),
    onSuccess: (out) => {
      if (!out.ok) { setErr(out.error ?? "Could not create the case."); return; }
      setTitle(""); setAssignee(""); setNotes(""); setErr(""); setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 rounded-[10px] border border-primary bg-primary px-[15px] py-2.5 text-[13.5px] font-semibold text-primary-foreground hover:opacity-90">
        <Plus className="h-4 w-4" strokeWidth={1.8} aria-hidden /> New case
      </button>
    );
  }

  return (
    <Card>
      <CardContent className="p-4">
        <form
          className="flex flex-col gap-2.5"
          onSubmit={(e) => { e.preventDefault(); if (title.trim()) create.mutate(); }}
        >
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold">New case</span>
            <button type="button" onClick={() => { setOpen(false); setErr(""); }}
                    aria-label="Cancel new case"
                    className="ml-auto inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-background">
              <X className="h-[15px] w-[15px]" aria-hidden />
            </button>
          </div>
          <label className="text-[11.5px] text-muted-foreground">Title (required)
            <input className={field} value={title} onChange={(e) => setTitle(e.target.value)}
                   aria-label="Case title" placeholder="e.g. Investigate brute-force from 203.0.113.44" />
          </label>
          <label className="text-[11.5px] text-muted-foreground">Assignee
            <input className={field} value={assignee} onChange={(e) => setAssignee(e.target.value)}
                   aria-label="Case assignee" placeholder="who is looking at this" />
          </label>
          <label className="text-[11.5px] text-muted-foreground">Notes
            <textarea className={`${field} min-h-[64px] resize-y`} value={notes}
                      onChange={(e) => setNotes(e.target.value)} aria-label="Case notes" />
          </label>
          {err && <p className="text-[12px]" style={{ color: "var(--sev-critical)" }}>{err}</p>}
          <div className="flex items-center gap-2">
            <button type="submit" disabled={!title.trim() || create.isPending}
              className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
              {create.isPending ? "Creating…" : "Create case"}
            </button>
            <span className="text-[11px] text-muted-foreground">Status starts as “open”.</span>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function CaseRow({ c }: { c: Case }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(c.title);
  const [assignee, setAssignee] = useState(c.assignee);
  const [notes, setNotes] = useState(c.notes);
  const [err, setErr] = useState("");

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["cases"] });

  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchCase>[1]) => api.patchCase(c.id, p),
    onSuccess: (out) => {
      if (!out.ok) { setErr(out.error ?? "Could not save."); return; }
      setErr(""); setEditing(false); invalidate();
    },
  });

  const links = [...c.links.findings, ...c.links.incidents];

  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            {editing ? (
              <input className={field} value={title} onChange={(e) => setTitle(e.target.value)}
                     aria-label={`Edit title of ${c.id}`} />
            ) : (
              <div className="text-[14px] font-semibold">{c.title}</div>
            )}
            <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{c.id}</div>
          </div>
          {/* Status is a live select — changing it PATCHes immediately. */}
          <label className="flex items-center gap-2">
            <span className="sr-only">Status of {c.id}</span>
            <StatusPill status={c.status} />
            <select
              aria-label={`Status of ${c.id}`}
              value={c.status}
              disabled={patch.isPending}
              onChange={(e) => patch.mutate({ status: e.target.value as CaseStatus })}
              className="rounded-md border bg-card px-1.5 py-1 text-[12px] outline-none"
            >
              {CASE_STATUSES.map((s) => <option key={s} value={s}>{STATUS_STYLE[s].label}</option>)}
            </select>
          </label>
          {!editing && (
            <button onClick={() => setEditing(true)} aria-label={`Edit ${c.id}`}
                    className="inline-flex h-7 w-7 items-center justify-center rounded-md border text-muted-foreground hover:border-primary">
              <Pencil className="h-3.5 w-3.5" aria-hidden />
            </button>
          )}
        </div>

        {editing ? (
          <div className="mt-3 flex flex-col gap-2">
            <label className="text-[11.5px] text-muted-foreground">Assignee
              <input className={field} value={assignee} onChange={(e) => setAssignee(e.target.value)}
                     aria-label={`Edit assignee of ${c.id}`} />
            </label>
            <label className="text-[11.5px] text-muted-foreground">Notes
              <textarea className={`${field} min-h-[64px] resize-y`} value={notes}
                        onChange={(e) => setNotes(e.target.value)} aria-label={`Edit notes of ${c.id}`} />
            </label>
            {err && <p className="text-[12px]" style={{ color: "var(--sev-critical)" }}>{err}</p>}
            <div className="flex items-center gap-2">
              <button
                onClick={() => title.trim() && patch.mutate({ title, assignee, notes })}
                disabled={!title.trim() || patch.isPending}
                className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
                {patch.isPending ? "Saving…" : "Save"}
              </button>
              <button onClick={() => { setEditing(false); setTitle(c.title); setAssignee(c.assignee); setNotes(c.notes); setErr(""); }}
                      className="rounded-md border px-3 py-1.5 text-[12.5px] hover:border-primary">
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <>
            {c.notes && <p className="mt-2 whitespace-pre-wrap text-[12.5px] text-muted-foreground">{c.notes}</p>}
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
              {c.assignee && <span>Assignee: <span className="text-foreground">{c.assignee}</span></span>}
              <span>Created {c.createdAt.slice(0, 16).replace("T", " ")}</span>
              <span>Updated {c.updatedAt.slice(0, 16).replace("T", " ")}</span>
              {links.length > 0 && (
                <span className="flex flex-wrap items-center gap-1">
                  Linked:
                  {links.map((l) => (
                    <span key={l} className="rounded border px-1.5 py-px font-mono text-[10.5px]">{l}</span>
                  ))}
                </span>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function Cases() {
  const { data, isLoading, error } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const cases = data?.cases ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[12.5px] text-muted-foreground">
          Investigation cases you create — stored locally in <span className="font-mono">cases.json</span>.
          This is analyst-entered data, not derived from findings.
        </p>
        <div className="ml-auto"><CreateCase /></div>
      </div>

      {isLoading && <p className="text-muted-foreground">Loading cases…</p>}
      {error && (
        <Card className="border-dashed"><CardContent className="p-6 text-[12.5px] text-muted-foreground">
          The console backend is not reachable — start it with
          <code className="mx-1 rounded bg-muted px-1.5 py-0.5 font-mono">python3 console/serve.py</code>.
        </CardContent></Card>
      )}
      {!isLoading && !error && cases.length === 0 && (
        <Card className="border-dashed"><CardContent className="p-8 text-center">
          <FolderKanban className="mx-auto mb-2 h-6 w-6 text-muted-foreground" strokeWidth={1.6} aria-hidden />
          <div className="text-[15px] font-semibold">No cases yet</div>
          <p className="mx-auto mt-1 max-w-md text-[12.5px] text-muted-foreground">
            Create a case to track an investigation. Nothing is shown here until
            you add one — no sample cases are invented.
          </p>
        </CardContent></Card>
      )}

      <div className="flex flex-col gap-3">
        {cases.map((c) => <CaseRow key={c.id} c={c} />)}
      </div>
    </div>
  );
}
