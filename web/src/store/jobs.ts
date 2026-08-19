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
  startedAt: number;      // for an honest elapsed readout
  seen?: boolean;         // dismissed / acknowledged by the user
}

const PROGRESS_POLL_MS = 1500;
const PROGRESS_POLL_MAX = 400; // ~10 minutes, then say so honestly

interface JobsState {
  current: IngestJob | null;
  busy: boolean;
  startUpload: (files: FileList | File[], now?: number) => Promise<void>;
  dismiss: () => void;
  /** test-only reset so the module-global store doesn't leak across cases. */
  _reset: () => void;
}

let counter = 0;

export const useJobs = create<JobsState>((set, get) => ({
  current: null,
  busy: false,

  startUpload: async (files, now = Date.now()) => {
    const list = Array.from(files);
    if (!list.length || get().busy) return;
    set({ busy: true });
    try {
      // One analysis at a time (backend enforces it): sequential, last wins.
      for (const file of list) {
        const id = ++counter;
        const base: IngestJob = { id, file: file.name, kind: "uploading", startedAt: now };
        set({ current: base });

        const out = await api.analyzeUpload(file)
          .catch(() => ({ ok: false as const, error: "the backend is not reachable" }));
        if (!out.ok) {
          set({ current: { ...base, kind: "error",
            message: `The server did not accept ${file.name}${out.error ? `: ${out.error}` : ""}.` } });
          continue;
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
            message: `Analysis of ${file.name} failed: ${final.error ?? "unknown error"}` } });
          continue;
        }

        // The finished run is the current one; capture its file so the
        // completion toast can re-open it even if the user switched away.
        const runs = await api.runs().catch(() => null);
        const runFile = runs?.runs.find((r) => r.runId === runs.current)?.file ?? null;
        set({ current: { ...base, kind: "done", job: final, runFile,
          message: `${file.name} analyzed — ${final.findings ?? 0} finding(s)`
            + (final.note ? ` · ${final.note}` : "") + "." } });
      }
    } finally {
      set({ busy: false });
    }
  },

  dismiss: () => set((s) => (s.current ? { current: { ...s.current, seen: true } } : {})),
  _reset: () => set({ current: null, busy: false }),
}));
