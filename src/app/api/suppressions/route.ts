import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";

export const runtime = "nodejs";

/** GET /api/suppressions — list all baseline suppressions. */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "scan:read")) {
    return NextResponse.json({ error: "Insufficient scope: scan:read required" }, { status: 403 });
  }
  const rows = await db.suppression.findMany({
    orderBy: { createdAt: "desc" },
    take: 500,
  });
  return NextResponse.json({
    suppressions: rows.map((r) => ({
      id: r.id,
      ruleId: r.ruleId,
      sourceHash: r.sourceHash,
      fileName: r.fileName,
      line: r.line,
      reason: r.reason,
      createdBy: r.createdBy,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
    })),
  });
}

/** POST /api/suppressions — create a baseline suppression. */
export async function POST(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "policy:manage")) {
    return NextResponse.json(
      { error: "Insufficient scope: policy:manage required" },
      { status: 403 }
    );
  }

  let body: {
    ruleId?: string;
    sourceHash?: string | null;
    fileName?: string;
    line?: number | null;
    reason?: string;
    expiresAt?: string | null;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const ruleId = body.ruleId?.toString().trim().slice(0, 64);
  if (!ruleId) {
    return NextResponse.json({ error: "ruleId is required" }, { status: 400 });
  }
  const reason = body.reason?.toString().trim().slice(0, 500) || "No reason provided.";

  try {
    const created = await db.suppression.create({
      data: {
        ruleId,
        sourceHash: body.sourceHash ?? null,
        fileName: body.fileName?.toString().slice(0, 255) ?? null,
        line: typeof body.line === "number" ? body.line : null,
        reason,
        createdBy: authKey?.name ?? "anonymous",
        expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
      },
    });

    await recordAudit({
      actorType: authKey ? "api_key" : "web",
      actorId: authKey?.id ?? null,
      actorName: authKey?.name ?? "anonymous",
      action: "suppression.create",
      target: `${ruleId}:${body.sourceHash ?? "*"}:${body.line ?? "*"}`,
      metadata: { ruleId, sourceHash: body.sourceHash, line: body.line, reason },
    });

    return NextResponse.json(
      {
        id: created.id,
        ruleId: created.ruleId,
        sourceHash: created.sourceHash,
        fileName: created.fileName,
        line: created.line,
        reason: created.reason,
        createdAt: created.createdAt,
        expiresAt: created.expiresAt,
      },
      { status: 201 }
    );
  } catch (e) {
    // Unique constraint violation (duplicate suppression)
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("Unique constraint")) {
      return NextResponse.json(
        { error: "An equivalent suppression already exists for this rule/file/line." },
        { status: 409 }
      );
    }
    throw e;
  }
}

/** DELETE /api/suppressions?id=... — remove a suppression. */
export async function DELETE(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "policy:manage")) {
    return NextResponse.json(
      { error: "Insufficient scope: policy:manage required" },
      { status: 403 }
    );
  }
  const id = new URL(req.url).searchParams.get("id");
  if (!id) {
    return NextResponse.json({ error: "id query param required" }, { status: 400 });
  }
  const existing = await db.suppression.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Suppression not found" }, { status: 404 });
  }
  await db.suppression.delete({ where: { id } });
  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id ?? null,
    actorName: authKey?.name ?? "anonymous",
    action: "suppression.delete",
    target: id,
    metadata: { ruleId: existing.ruleId },
  });
  return NextResponse.json({ ok: true, deleted: id });
}
