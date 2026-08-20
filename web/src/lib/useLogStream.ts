/** Live tail of the current run's raw log over GET /api/stream (SSE).
 *
 *  Shapes below mirror the backend contract EXACTLY (console/serve.py,
 *  docs/soc_subsystems.md "Phase D design") — nothing here invents fields:
 *
 *    event: log      {n, ts, level, host, msg, raw, bucket}  id: <line#>
 *    event: finding  the full adapter.adapt() Finding shape, id "stream-<seq>";
 *                    MAY re-emit for the same rule as its burst grows
 *    event: ping     keepalive every ~15s — ignored
 *    event: gap      {dropped: N} — backpressure drop, surfaced, never hidden
 *
 *  The stream AUGMENTS the 5s polling; it never replaces it. When the stream
 *  is down (or the browser has no EventSource) `connected` stays false and
 *  the caller keeps its polling fallback — an honest degraded mode, not a
 *  silent one. A native EventSource reconnects on its own and replays nothing:
 *  the browser sends Last-Event-ID and the server resumes after that line.
 */

import { useEffect, useRef, useState } from "react";
import type { Finding } from "@/lib/api";

export type StreamBucket =
  | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";

/** `event: log` payload. `ts`/`level`/`host`/`msg` are "" when the parser
 *  could not read the line (the line still arrives, bucket UNKNOWN, with the
 *  verbatim raw) — render those as n/a, never as fabricated values. */
export interface StreamLogEvent {
  n: number;
  ts: string;
  level: string;
  host: string;
  msg: string;
  raw: string;
  bucket: StreamBucket;
}

/** One row of the live tail, in arrival order. A gap row is the honest
 *  record that the server dropped N events under backpressure. */
export type TailRow =
  | { kind: "log"; event: StreamLogEvent }
  | { kind: "gap"; dropped: number };

/** Rendered rows are capped so an all-day tail cannot grow without bound;
 *  the cap trims OLDEST rows, mirroring the server's own queue policy. */
const TAIL_CAP = 500;

export interface LogStream {
  rows: TailRow[];
  /** Streamed findings, newest last. A re-emitted finding (same rule, same
   *  title — the burst grew) replaces its older version in place. */
  findings: Finding[];
  /** True only while the SSE connection is open — the UI shows the polling
   *  fallback state whenever this is false. */
  connected: boolean;
  /** Running total of server-dropped events, from `event: gap`. */
  dropped: number;
  /** True when this browser cannot stream at all (no EventSource). */
  unsupported: boolean;
}

export function useLogStream(source: string | undefined): LogStream {
  const [rows, setRows] = useState<TailRow[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [connected, setConnected] = useState(false);
  const [dropped, setDropped] = useState(0);
  const unsupported = typeof EventSource === "undefined";
  // Reset accumulated state when the source changes (a new run was loaded).
  const sourceRef = useRef(source);

  useEffect(() => {
    if (!source || typeof EventSource === "undefined") return;
    if (sourceRef.current !== source) {
      sourceRef.current = source;
      setRows([]);
      setFindings([]);
      setDropped(0);
    }

    const es = new EventSource(`/api/stream?source=${encodeURIComponent(source)}`);

    es.addEventListener("open", () => setConnected(true));
    // EventSource reconnects by itself (with Last-Event-ID, so the server
    // resumes after the last delivered line). While it is down we only say so.
    es.addEventListener("error", () => setConnected(false));

    es.addEventListener("log", (e) => {
      const event = JSON.parse((e as MessageEvent).data) as StreamLogEvent;
      setRows((r) => [...r, { kind: "log", event } as TailRow].slice(-TAIL_CAP));
    });

    es.addEventListener("finding", (e) => {
      const f = JSON.parse((e as MessageEvent).data) as Finding;
      setFindings((cur) => {
        // Same rule + same summary = the SAME finding re-emitted with grown
        // evidence: replace in place rather than duplicating the row.
        const i = cur.findIndex((x) => x.type === f.type && x.title === f.title);
        if (i === -1) return [...cur, f];
        const next = cur.slice();
        next[i] = f;
        return next;
      });
    });

    es.addEventListener("gap", (e) => {
      const gap = JSON.parse((e as MessageEvent).data) as { dropped: number };
      setDropped((d) => d + gap.dropped);
      setRows((r) =>
        [...r, { kind: "gap", dropped: gap.dropped } as TailRow].slice(-TAIL_CAP));
    });
    // `ping` is keepalive only — no listener on purpose.

    return () => {
      es.close();
      setConnected(false);
    };
  }, [source]);

  return { rows, findings, connected, dropped, unsupported };
}
