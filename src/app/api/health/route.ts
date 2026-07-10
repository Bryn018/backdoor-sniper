import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export const runtime = "nodejs";

/**
 * Health / readiness endpoint for load balancers & monitoring.
 * Checks DB connectivity and returns service metadata.
 */
export async function GET() {
  let dbOk = false;
  let dbLatencyMs: number | null = null;
  let dbError: string | null = null;
  try {
    const t0 = Date.now();
    await db.scanRecord.count();
    dbLatencyMs = Date.now() - t0;
    dbOk = true;
  } catch (e) {
    dbOk = false;
    dbError = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  }

  const healthy = dbOk;
  return NextResponse.json(
    {
      status: healthy ? "ok" : "degraded",
      uptime: process.uptime ? Math.round(process.uptime()) : null,
      db: { ok: dbOk, latencyMs: dbLatencyMs, error: dbError },
      timestamp: new Date().toISOString(),
      version: "2.0.0",
    },
    { status: healthy ? 200 : 503 },
  );
}
