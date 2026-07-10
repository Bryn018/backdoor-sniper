"use client";

/**
 * StreamingProgress
 * -----------------
 * Real-time SSE-driven scan progress for large single-file scans.
 *
 * Opens an EventSource to GET /api/scan/stream?source=<url-encoded-source>
 * and displays a progress bar, a live finding counter, the latest 5 streamed
 * findings, and a rough ETA. Calls `onComplete(result)` when the server
 * emits the `complete` event, `onError(message)` on errors, and `onFallback()`
 * if the source is too large for the streaming endpoint (URL length limits).
 *
 * Visual: emerald accent (matches the project's emerald theme).
 */

import { useEffect, useRef, useState } from "react";
import { Loader2, Activity, AlertTriangle, CheckCircle2 } from "lucide-react";
import { SEVERITY_BADGE } from "@/lib/severity";
import type { ScanResult, Severity } from "@/lib/detector/types";

interface StreamingProgressProps {
  /** Python source code to stream-scan. */
  source: string;
  /**
   * Trigger value — when this changes, the stream is reopened. Use a
   * Date.now() or an incrementing counter to re-run the scan.
   */
  trigger?: number | string;
  /** Called with the full ScanResult on the `complete` event. */
  onComplete?: (result: ScanResult) => void;
  /** Called with an error message on the `error` event. */
  onError?: (message: string) => void;
  /**
   * Called when the source is too large for the streaming endpoint —
   * the caller should fall back to a regular POST /api/scan.
   */
  onFallback?: () => void;
}

/** URL length above which we fall back to standard scan. */
const TOO_LARGE_BYTES = 30_000;

type Status =
  | "idle"
  | "connecting"
  | "streaming"
  | "complete"
  | "error"
  | "fallback";

interface StreamFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  line: number;
  ts: number;
}

export function StreamingProgress({
  source,
  trigger,
  onComplete,
  onError,
  onFallback,
}: StreamingProgressProps) {
  const [status, setStatus] = useState<Status>("connecting");
  const [progress, setProgress] = useState(0);
  const [findingCount, setFindingCount] = useState(0);
  const [recentFindings, setRecentFindings] = useState<StreamFinding[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);

  const startRef = useRef<number>(0);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const doneRef = useRef<boolean>(false);

  // Keep latest callbacks in refs so we don't reopen the stream when
  // parent re-renders with new closure identities.
  const completeRef = useRef(onComplete);
  const errorRef = useRef(onError);
  const fallbackRef = useRef(onFallback);
  useEffect(() => {
    completeRef.current = onComplete;
    errorRef.current = onError;
    fallbackRef.current = onFallback;
  });

  useEffect(() => {
    // Cleanup any prior stream.
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    if (tickRef.current) {
      clearInterval(tickRef.current);
      tickRef.current = null;
    }
    doneRef.current = false;

    // Reset visible state for the new stream. These setStates are
    // intentional — we need to clear stale progress / findings from any
    // prior stream before opening a new EventSource.
    /* eslint-disable react-hooks/set-state-in-effect */
    setStatus("connecting");
    setProgress(0);
    setFindingCount(0);
    setRecentFindings([]);
    setErrorMsg(null);
    setElapsedMs(0);
    /* eslint-enable react-hooks/set-state-in-effect */

    // Fallback for too-large source — URL length limits make EventSource
    // unreliable past ~32 KB on most browsers/proxies.
    if (source.length > TOO_LARGE_BYTES) {
      setStatus("fallback");
      fallbackRef.current?.();
      return;
    }
    if (!source.trim()) {
      setStatus("error");
      setErrorMsg("No source provided.");
      errorRef.current?.("No source provided.");
      return;
    }

    startRef.current = Date.now();
    tickRef.current = setInterval(() => {
      setElapsedMs(Date.now() - startRef.current);
    }, 100);

    const url = `/api/scan/stream?source=${encodeURIComponent(source)}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      if (doneRef.current) return;
      setStatus("streaming");
    };

    es.onmessage = (ev) => {
      if (doneRef.current) return;
      let parsed: { event?: string; data?: Record<string, unknown> };
      try {
        parsed = JSON.parse(ev.data);
      } catch {
        return; // ignore malformed frames (e.g. heartbeat comments)
      }
      const evt = parsed.event;
      const data = parsed.data ?? {};

      if (evt === "progress") {
        const pct = typeof data.percent === "number" ? data.percent : 0;
        setProgress(Math.min(100, Math.max(0, pct)));
      } else if (evt === "finding") {
        setFindingCount((c) => c + 1);
        setRecentFindings((prev) => {
          const next: StreamFinding = {
            ruleId: String(data.ruleId ?? ""),
            title: String(data.title ?? ""),
            severity: (data.severity as Severity) ?? "info",
            line: typeof data.line === "number" ? data.line : 0,
            ts: Date.now(),
          };
          return [next, ...prev].slice(0, 5);
        });
      } else if (evt === "complete") {
        doneRef.current = true;
        setProgress(100);
        setStatus("complete");
        if (tickRef.current) {
          clearInterval(tickRef.current);
          tickRef.current = null;
        }
        completeRef.current?.(data as unknown as ScanResult);
        es.close();
      } else if (evt === "error") {
        doneRef.current = true;
        const msg =
          typeof data.message === "string" ? data.message : "Stream error";
        setStatus("error");
        setErrorMsg(msg);
        if (tickRef.current) {
          clearInterval(tickRef.current);
          tickRef.current = null;
        }
        errorRef.current?.(msg);
        es.close();
      }
    };

    es.onerror = () => {
      if (doneRef.current) return;
      // EventSource auto-reconnects by default — but a connection drop
      // mid-stream usually means the server closed without sending
      // `complete`. Surface it as an error.
      doneRef.current = true;
      setStatus("error");
      setErrorMsg("Stream connection lost before completion.");
      if (tickRef.current) {
        clearInterval(tickRef.current);
        tickRef.current = null;
      }
      errorRef.current?.("Stream connection lost before completion.");
      es.close();
    };

    return () => {
      doneRef.current = true;
      es.close();
      if (tickRef.current) {
        clearInterval(tickRef.current);
        tickRef.current = null;
      }
    };
  }, [source, trigger]);

  // Rough ETA: elapsed/percent * (100 - percent).
  const etaMs =
    progress > 0 && elapsedMs > 0
      ? Math.round((elapsedMs / progress) * (100 - progress))
      : null;

  if (status === "fallback") {
    return (
      <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300 flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
        <div>
          <p className="font-medium">Source too large for streaming</p>
          <p className="text-[10px] mt-0.5 opacity-90">
            Using standard scan instead — {source.length.toLocaleString()} chars
            exceeds the {TOO_LARGE_BYTES.toLocaleString()}-char streaming limit.
          </p>
        </div>
      </div>
    );
  }

  const statusLabel: Record<Status, string> = {
    idle: "Idle",
    connecting: "Connecting",
    streaming: "Streaming",
    complete: "Complete",
    error: "Error",
    fallback: "Fallback",
  };

  return (
    <div className="rounded-md border border-border bg-card p-3 space-y-3">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-medium">
          {status === "complete" ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
          ) : status === "error" ? (
            <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
          ) : (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-500" />
          )}
          <span className="capitalize">{statusLabel[status]}</span>
          <Activity className="h-3 w-3 text-muted-foreground/50" />
        </div>
        <div className="font-mono text-[10px] text-muted-foreground tabular-nums">
          {progress}%
          <span className="mx-1.5">·</span>
          {findingCount} finding{findingCount !== 1 ? "s" : ""}
          {elapsedMs > 0 && (
            <>
              <span className="mx-1.5">·</span>
              {(elapsedMs / 1000).toFixed(1)}s
            </>
          )}
          {etaMs !== null && etaMs > 0 && status !== "complete" && (
            <>
              <span className="mx-1.5">·</span>
              ~{(etaMs / 1000).toFixed(0)}s left
            </>
          )}
        </div>
      </div>

      {/* Progress bar (emerald accent) */}
      <div
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuenow={progress}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all duration-300 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Error message */}
      {errorMsg && (
        <p className="text-[11px] text-red-600 dark:text-red-400">{errorMsg}</p>
      )}

      {/* Live findings log */}
      {recentFindings.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Live findings (latest {recentFindings.length})
          </p>
          <div className="max-h-32 space-y-1 overflow-y-auto custom-scrollbar">
            {recentFindings.map((f, i) => {
              const sev = SEVERITY_BADGE[f.severity];
              return (
                <div
                  key={`${f.ruleId}-${f.line}-${f.ts}-${i}`}
                  className={`flex items-center gap-2 rounded px-2 py-1 text-[11px] ${sev.soft}`}
                >
                  <span
                    className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${sev.dot}`}
                  />
                  <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                    {f.ruleId}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-foreground/80">
                    {f.title}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                    L{f.line}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
