import { NextRequest, NextResponse } from "next/server";
import { scanPythonStreaming, type Finding } from "@/lib/detector";

export const runtime = "nodejs";

/** Maximum wall-clock time for a streaming scan. */
const TIMEOUT_MS = 60_000;
/** Heartbeat interval — SSE comment lines keep proxies from closing idle connections. */
const HEARTBEAT_INTERVAL_MS = 15_000;
/** Max source size accepted via query string (URL-encoded). */
const MAX_SOURCE_BYTES = 5 * 1024 * 1024; // 5 MB
/** Finding-event throttle: emit at most 1 finding event per this many ms. */
const FINDING_THROTTLE_MS = 100;
/** Hard cap on number of finding events streamed (to bound payload size). */
const MAX_FINDING_EVENTS = 500;

export async function GET(req: NextRequest) {
  const sourceParam = req.nextUrl.searchParams.get("source");
  if (!sourceParam) {
    return NextResponse.json(
      {
        error:
          "Missing 'source' query param. GET /api/scan/stream?source=<url-encoded-python>",
      },
      { status: 400 }
    );
  }

  let source: string;
  try {
    source = decodeURIComponent(sourceParam);
  } catch {
    return NextResponse.json(
      { error: "Invalid URL-encoded source." },
      { status: 400 }
    );
  }

  if (Buffer.byteLength(source, "utf8") > MAX_SOURCE_BYTES) {
    return NextResponse.json(
      {
        error: `Source is too large for the streaming endpoint (max ${MAX_SOURCE_BYTES} bytes via query string). Use POST /api/scan/project for larger files.`,
      },
      { status: 413 }
    );
  }

  const encoder = new TextEncoder();

  /** Format an SSE event: `data: <json>\n\n`. */
  const formatEvent = (event: string, data: unknown): Uint8Array => {
    const payload = JSON.stringify({ event, data });
    return encoder.encode(`data: ${payload}\n\n`);
  };

  /** SSE heartbeat comment — keeps the connection alive through proxies. */
  const heartbeat = encoder.encode(`: heartbeat\n\n`);

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let closed = false;
      let findingEventsSent = 0;
      let lastFindingEmit = 0;
      let timeoutHandle: NodeJS.Timeout | null = null;
      let heartbeatHandle: NodeJS.Timeout | null = null;

      const safeEnqueue = (chunk: Uint8Array) => {
        if (closed) return;
        try {
          controller.enqueue(chunk);
        } catch {
          closed = true;
        }
      };

      const cleanup = () => {
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
          timeoutHandle = null;
        }
        if (heartbeatHandle) {
          clearInterval(heartbeatHandle);
          heartbeatHandle = null;
        }
      };

      const closeStream = () => {
        if (closed) return;
        closed = true;
        cleanup();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };

      // 60s hard timeout.
      timeoutHandle = setTimeout(() => {
        safeEnqueue(
          formatEvent("error", { message: "timeout", timeoutMs: TIMEOUT_MS })
        );
        closeStream();
      }, TIMEOUT_MS);

      // 15s heartbeat.
      heartbeatHandle = setInterval(() => {
        safeEnqueue(heartbeat);
      }, HEARTBEAT_INTERVAL_MS);

      // Defer the (potentially long) synchronous scan to the next tick so the
      // response headers + the ReadableStream setup can be flushed first.
      setImmediate(() => {
        try {
          const result = scanPythonStreaming(source, {
            chunkSize: 1000,
            onProgress: (p) => {
              safeEnqueue(formatEvent("progress", p));
            },
            onFinding: (finding: Finding) => {
              // Throttle to at most 1 finding event per FINDING_THROTTLE_MS.
              // (Note: because scanPythonStreaming is synchronous, all finding
              // callbacks fire within the same event-loop tick — so this
              // throttle effectively limits to ~1 finding event per batch.
              // The hard cap below protects against pathological floods.)
              const now = Date.now();
              if (now - lastFindingEmit < FINDING_THROTTLE_MS) return;
              if (findingEventsSent >= MAX_FINDING_EVENTS) return;
              lastFindingEmit = now;
              findingEventsSent++;
              safeEnqueue(
                formatEvent("finding", {
                  ruleId: finding.ruleId,
                  title: finding.title,
                  severity: finding.severity,
                  category: finding.category,
                  line: finding.line,
                  snippet: finding.snippet,
                  confidence: finding.confidence,
                })
              );
            },
          });

          safeEnqueue(
            formatEvent("complete", {
              ...result,
              _findingEventsTruncated:
                result.findings.length > MAX_FINDING_EVENTS
                  ? result.findings.length
                  : undefined,
            })
          );
          closeStream();
        } catch (e) {
          safeEnqueue(
            formatEvent("error", {
              message: e instanceof Error ? e.message : String(e),
            })
          );
          closeStream();
        }
      });
    },
    cancel() {
      // Client disconnected — the controller is closed by the runtime.
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no", // disable proxy buffering (nginx)
      "Access-Control-Allow-Origin": "*",
    },
  });
}
