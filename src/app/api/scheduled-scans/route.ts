import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";
import { computeNextRunAt, parseSchedule } from "@/lib/scheduler";

export const runtime = "nodejs";

/** GET /api/scheduled-scans — list all scheduled scans. */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "scan:read")) {
    return NextResponse.json(
      { error: "Insufficient scope: scan:read required" },
      { status: 403 }
    );
  }
  const scans = await db.scheduledScan.findMany({
    orderBy: { createdAt: "desc" },
    take: 100,
  });
  return NextResponse.json({
    rows: scans.map((s) => ({
      ...s,
      nextRunAt: s.nextRunAt?.toISOString() ?? null,
      lastRunAt: s.lastRunAt?.toISOString() ?? null,
    })),
    total: scans.length,
  });
}

/** POST /api/scheduled-scans — create a scheduled scan. */
export async function POST(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "policy:manage")) {
    return NextResponse.json(
      { error: "Insufficient scope: policy:manage required" },
      { status: 403 }
    );
  }
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

  const name = (body.name || "").trim();
  const schedule = (body.schedule || "").trim();
  const sourceType = (body.sourceType || "paste").trim();
  const sourceData = body.sourceData ?? "";

  if (!name) return NextResponse.json({ error: "name is required" }, { status: 400 });
  if (!schedule) return NextResponse.json({ error: "schedule is required" }, { status: 400 });

  const parsed = parseSchedule(schedule);
  if (!parsed.ok) {
    return NextResponse.json({ error: parsed.error }, { status: 400 });
  }
  if (!["paste", "url"].includes(sourceType)) {
    return NextResponse.json({ error: "sourceType must be paste or url" }, { status: 400 });
  }
  if (!sourceData) {
    return NextResponse.json({ error: "sourceData is required" }, { status: 400 });
  }

  const nextRunAt = computeNextRunAt(parsed);

  const created = await db.scheduledScan.create({
    data: {
      name,
      schedule,
      sourceType,
      sourceData,
      policyName: body.policyName ?? null,
      notifyOnFail: body.notifyOnFail !== false,
      notifyOnCritical: body.notifyOnCritical === true,
      enabled: body.enabled !== false,
      nextRunAt,
      createdBy: authKey?.name ?? "system",
    },
  });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id,
    actorName: authKey?.name,
    action: "scheduledscan.create",
    target: created.id,
    metadata: { name, schedule, sourceType, policyName: created.policyName },
  });

  return NextResponse.json(
    { ...created, nextRunAt: created.nextRunAt?.toISOString() ?? null, lastRunAt: null },
    { status: 201 }
  );
}
