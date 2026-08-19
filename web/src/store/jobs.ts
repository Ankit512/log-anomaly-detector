import { create } from "zustand";
import { api, type AnalyzeJob } from "@/lib/api";

/** Background upload/analysis job state, lifted OUT of any page so it survives
 *  navigation: the shell reads it for a persistent side notification, and the
 *  job keeps running (and completes) whether or not the Overview is mounted.
 *  Honest throughout — `job` is the last real /api/progress snapshot, progress
 *  shows a bar only when the backend gives done/total, and completion carries
 *  the finished run's file so the notification can switch to it. */

export type IngestKind = "uploading" | "running" | "done" | "error";

export interface IngestJob {
  id: number;
  file: string;
  kind: IngestKind;
  job?: AnalyzeJob;       // last /api/progress snapshot, verbatim
  message?: string;       // human line for done/error
  runFile?: string | null; // the saved run to open from the completion toast
  /** A finished run whose format was not parsed — a warning, not an error and
   *  not a clean "0 findings". Drives the notifier's honest tone + copy. */
  unrecognized?: boolean;
  startedAt: number;      // for an honest elapsed readout
  seen?: boolean;         // dismissed / acknowledged by the user
}

const PROGRESS_POLL_MS = 1500;
const PROGRESS_POLL_MAX = 400; // ~10 minutes, then say so honestly

interface JobsState {
  current: IngestJob | null;
  busy: boolean;
  startUpload: (files: FileList | File[], now?: number) => Promise<void>;
  /** Ingest a pasted URL — the backend fetches it and runs the same pipeline. */
  startUrl: (url: string, now?: number) => Promise<void>;
  dismiss: () => void;
  /** test-only reset so the module-global store doesn't leak across cases. */
  _reset: () => void;
}

let counter = 0;

export const useJobs = create<JobsState>((set, get) => {
  /** Run one ingestion end-to-end: kick it off (upload OR URL), then poll
   *  /api/progress to the real outcome. The ONLY difference between a file and
   *  a link is `kick` and the label — progress, completion, click-to-view and
   *  honest errors are identical. */
  const runOne = async (label: string, startingKind: IngestKind,
                        kick: () => Promise<{ ok: boolean; error?: string }>, now: number) => {
    const id = ++counter;
    const base: IngestJob = { id, file: label, kind: startingKind, startedAt: now };
    set({ current: base });

    const out = await kick().catch(() => ({ ok: false as const, error: "the backend is not reachable" }));
    if (!out.ok) {
      set({ current: { ...base, kind: "error",
        message: `The server did not accept ${label}${out.error ? `: ${out.error}` : ""}.` } });
      return;
    }

    let final: AnalyzeJob | { status: "error"; error: string } | null = null;
    for (let i = 0; i < PROGRESS_POLL_MAX; i++) {
      await new Promise((r) => setTimeout(r, PROGRESS_POLL_MS));
      const snap = await api.progress().catch(() => null);
      if (!snap) { final = { status: "error", error: "the backend stopped answering" }; break; }
      if (snap.status !== "running") { final = snap; break; }
      set({ current: { ...base, kind: "running", job: snap } });
    }
    if (!final) final = { status: "error", error: "timed out waiting for the analysis" };

    if (final.status === "error") {
      set({ current: { ...base, kind: "error",
        message: `Analysis of ${label} failed: ${final.error ?? "unknown error"}` } });
      return;
    }

    // The finished run is the current one; capture its file so the completion
    // toast can re-open it even if the user switched away.
    const runs = await api.runs().catch(() => null);
    const runFile = runs?.runs.find((r) => r.runId === runs.current)?.file ?? null;

    // Distinguish "nothing parsed" from "nothing found" — an unrecognized or
    // empty run is NOT a clean 0-findings result, so it must not say "analyzed
    // — 0 findings". The parse facts live in console_state, not the job.
    const st = await api.consoleState().catch(() => null);
    const findings = final.findings ?? st?.findings?.length ?? 0;
    let message: string;
    let unrecognized = false;
    if (st?.unrecognized) {
      unrecognized = true;
      const total = (st.linesParsed ?? 0) + (st.linesUnparsed ?? 0);
      message = `Couldn't parse ${label} — 0${total ? ` of ${total.toLocaleString()}` : ""} lines recognized (unsupported format).`;
    } else if (st?.emptyInput) {
      unrecognized = true;
      message = `${label} had no analyzable content — nothing was read.`;
    } else if (findings === 0) {
      message = `${label} analyzed — 0 findings; nothing matched the rules.`;
    } else {
      message = `${label} analyzed — ${findings} finding(s).`;
    }
    if (final.note) message += ` · ${final.note}`;

    set({ current: { ...base, kind: "done", job: final, runFile, unrecognized, message } });
  };

  return {
    current: null,
    busy: false,

    startUpload: async (files, now = Date.now()) => {
      const list = Array.from(files);
      if (!list.length || get().busy) return;
      set({ busy: true });
      try {
        // One analysis at a time (backend enforces it): sequential, last wins.
        for (const file of list) {
          await runOne(file.name, "uploading", () => api.analyzeUpload(file), now);
        }
      } finally {
        set({ busy: false });
      }
    },

    startUrl: async (url, now = Date.now()) => {
      const trimmed = url.trim();
      if (!trimmed || get().busy) return;
      set({ busy: true });
      try {
        // Label by the URL's last path segment, falling back to the host.
        let label = trimmed;
        try {
          const u = new URL(trimmed);
          label = u.pathname.split("/").filter(Boolean).pop() || u.hostname;
        } catch { /* not a parseable URL — the backend returns an honest 400 */ }
        await runOne(label, "uploading", () => api.analyzeUrl(trimmed), now);
      } finally {
        set({ busy: false });
      }
    },

    dismiss: () => set((s) => (s.current ? { current: { ...s.current, seen: true } } : {})),
    _reset: () => set({ current: null, busy: false }),
  };
});
