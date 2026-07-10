import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";
import { computeNextRunAt, parseSchedule } from "@/lib/scheduler";

export const runtime = "nodejs";

/** DELETE /api/scheduled-scans/[id] — delete a scheduled scan. */
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "policy:manage")) {
    return NextResponse.json(
      { error: "Insufficient scope: policy:manage required" },
      { status: 403 }
    );
  }
  const { id } = await params;
  const existing = await db.scheduledScan.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Scheduled scan not found" }, { status: 404 });
  }
  await db.scheduledScan.delete({ where: { id } });
  await db.scheduledScanRun.deleteMany({ where: { scheduledScanId: id } });
  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id,
    actorName: authKey?.name,
    action: "scheduledscan.delete",
    target: id,
    metadata: { name: existing.name, schedule: existing.schedule },
  });
  return NextResponse.json({ ok: true });
}

/** PATCH /api/scheduled-scans/[id] — update / toggle a scheduled scan. */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "policy:manage")) {
    return NextResponse.json(
      { error: "Insufficient scope: policy:manage required" },
      { status: 403 }
    );
  }
  const { id } = await params;
  let body: {
    name?: string;
    schedule?: string;
    sourceType?: string;
    sourceData?: string;
    policyName?: string | null;
    notifyOnFail?: boolean;
    notifyOnCritical?: boolean;
    enabled?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const existing = await db.scheduledScan.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Scheduled scan not found" }, { status: 404 });
  }

  const data: Record<string, unknown> = {};
  if (typeof body.name === "string") data.name = body.name.trim();
  if (typeof body.schedule === "string") {
    const parsed = parseSchedule(body.schedule);
    if (!parsed.ok) return NextResponse.json({ error: parsed.error }, { status: 400 });
    data.schedule = body.schedule;
    data.nextRunAt = computeNextRunAt(parsed, body.enabled === false ? undefined : new Date());
  }
  if (typeof body.sourceType === "string" && ["paste", "url"].includes(body.sourceType))
    data.sourceType = body.sourceType;
  if (typeof body.sourceData === "string") data.sourceData = body.sourceData;
  if (body.policyName !== undefined) data.policyName = body.policyName || null;
  if (typeof body.notifyOnFail === "boolean") data.notifyOnFail = body.notifyOnFail;
  if (typeof body.notifyOnCritical === "boolean") data.notifyOnCritical = body.notifyOnCritical;
  if (typeof body.enabled === "boolean") {
    data.enabled = body.enabled;
    if (body.enabled && !existing.nextRunAt) {
      const parsed = parseSchedule(existing.schedule);
      if (parsed.ok) data.nextRunAt = computeNextRunAt(parsed);
    }
  }

  const updated = await db.scheduledScan.update({ where: { id }, data });
  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id,
    actorName: authKey?.name,
    action: "scheduledscan.update",
    target: id,
    metadata: { name: updated.name, changes: Object.keys(data) },
  });

  return NextResponse.json({
    ...updated,
    nextRunAt: updated.nextRunAt?.toISOString() ?? null,
    lastRunAt: updated.lastRunAt?.toISOString() ?? null,
  });
}
