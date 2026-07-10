import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";

export const runtime = "nodejs";

/** DELETE /api/api-keys/[id] — revoke (soft) then hard-delete. */
export async function DELETE(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "apikey:manage")) {
    return NextResponse.json({ error: "Insufficient scope: apikey:manage required" }, { status: 403 });
  }

  const existing = await db.apiKey.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "API key not found" }, { status: 404 });
  }

  await db.apiKey.delete({ where: { id } });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id ?? null,
    actorName: authKey?.name ?? "anonymous",
    action: "apikey.revoke",
    target: existing.prefix,
    metadata: { name: existing.name, keyId: id },
  });

  return NextResponse.json({ ok: true, revoked: existing.prefix });
}
