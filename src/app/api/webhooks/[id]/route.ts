import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";

export const runtime = "nodejs";

/** DELETE /api/webhooks/[id] — delete a webhook endpoint. */
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "admin")) {
    return NextResponse.json(
      { error: "Insufficient scope: admin required" },
      { status: 403 }
    );
  }
  const { id } = await params;
  const existing = await db.webhookEndpoint.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Webhook not found" }, { status: 404 });
  }

  await db.webhookEndpoint.delete({ where: { id } });
  // Keep the delivery log for forensics but orphan it from the deleted endpoint
  await db.webhookDelivery.deleteMany({ where: { webhookId: id } });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id,
    actorName: authKey?.name,
    action: "webhook.delete",
    target: id,
    metadata: { name: existing.name, url: existing.url },
  });

  return NextResponse.json({ ok: true });
}

/** PATCH /api/webhooks/[id] — update an endpoint (toggle enabled, etc). */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "admin")) {
    return NextResponse.json(
      { error: "Insufficient scope: admin required" },
      { status: 403 }
    );
  }
  const { id } = await params;
  let body: {
    name?: string;
    url?: string;
    sinkType?: string;
    events?: string[];
    signingSecret?: string | null;
    enabled?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const existing = await db.webhookEndpoint.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Webhook not found" }, { status: 404 });
  }

  const data: Record<string, unknown> = {};
  if (typeof body.name === "string") data.name = body.name.trim();
  if (typeof body.url === "string" && /^https?:\/\//i.test(body.url)) data.url = body.url.trim();
  if (typeof body.sinkType === "string") data.sinkType = body.sinkType;
  if (Array.isArray(body.events)) data.events = JSON.stringify(body.events.filter((e) => typeof e === "string"));
  if (body.signingSecret !== undefined) data.signingSecret = body.signingSecret || null;
  if (typeof body.enabled === "boolean") data.enabled = body.enabled;

  const updated = await db.webhookEndpoint.update({ where: { id }, data });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id,
    actorName: authKey?.name,
    action: "webhook.update",
    target: id,
    metadata: { name: updated.name, changes: Object.keys(data) },
  });

  return NextResponse.json({
    ...updated,
    signingSecret: updated.signingSecret ? "••••" + updated.signingSecret.slice(-4) : null,
    events: updated.events ? safeParseArray(updated.events) : [],
  });
}

function safeParseArray(s: string | null): string[] {
  if (!s) return [];
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}
