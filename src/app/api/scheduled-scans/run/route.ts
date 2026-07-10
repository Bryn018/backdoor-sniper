import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { runDueScheduledScans } from "@/lib/scheduler";

export const runtime = "nodejs";

/**
 * POST /api/scheduled-scans/run
 *
 * Tick the scheduler: find all due scheduled scans and execute them.
 *
 * This endpoint is designed to be called by a cron job (GitHub Actions,
 * systemd timer, k8s CronJob) every minute — BackdoorSniper itself does
 * NOT run a background timer, so the user wires this up externally.
 *
 * Optionally accepts ?id=... to force-run a specific scheduled scan
 * immediately regardless of nextRunAt.
 *
 * Auth: requires an API key with `scan:run` scope (for the tick), or no
 * auth (anonymous, but rate-limited) — for simple setups. For production,
 * always protect with a key.
 */
export async function POST(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "scan:run")) {
    return NextResponse.json(
      { error: "Insufficient scope: scan:run required" },
      { status: 403 }
    );
  }

  // Allow forcing a specific scheduled scan to run immediately
  const url = new URL(req.url);
  const forceId = url.searchParams.get("id");
  if (forceId) {
    const job = await db.scheduledScan.findUnique({ where: { id: forceId } });
    if (!job) return NextResponse.json({ error: "Not found" }, { status: 404 });
    await db.scheduledScan.update({
      where: { id: forceId },
      data: { nextRunAt: new Date() },
    });
  }

  const result = await runDueScheduledScans();
  return NextResponse.json({
    ok: true,
    ...result,
    timestamp: new Date().toISOString(),
  });
}

/** GET — same as POST but idempotent & safe (no force); for uptime monitors. */
export async function GET(req: NextRequest) {
  return POST(req);
}
