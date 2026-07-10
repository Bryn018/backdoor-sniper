import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  generateApiKey,
  validateApiKey,
  hasScope,
  VALID_SCOPES,
  type Scope,
} from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";

export const runtime = "nodejs";

/** GET /api/api-keys — list all API keys (hashes never returned). */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  // Listing keys requires apikey:manage or admin. If no key at all, we still
  // allow listing in this single-tenant demo but record an audit "denied".
  if (authKey && !hasScope(authKey, "apikey:manage")) {
    await recordAudit({
      actorType: "api_key",
      actorId: authKey.id,
      actorName: authKey.name,
      action: "auth.denied",
      outcome: "denied",
      metadata: { attempted: "apikey.list" },
    });
    return NextResponse.json({ error: "Insufficient scope: apikey:manage required" }, { status: 403 });
  }

  const rows = await db.apiKey.findMany({
    orderBy: { createdAt: "desc" },
    take: 200,
  });

  return NextResponse.json({
    keys: rows.map((r) => ({
      id: r.id,
      name: r.name,
      prefix: r.prefix,
      scopes: JSON.parse(r.scopes) as string[],
      createdBy: r.createdBy,
      createdAt: r.createdAt,
      lastUsedAt: r.lastUsedAt,
      revokedAt: r.revokedAt,
      expiresAt: r.expiresAt,
      useCount: r.useCount,
    })),
  });
}

/** POST /api/api-keys — create a new API key. Returns the full key ONCE. */
export async function POST(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "apikey:manage")) {
    return NextResponse.json({ error: "Insufficient scope: apikey:manage required" }, { status: 403 });
  }

  let body: { name?: string; scopes?: string[]; expiresInDays?: number };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const name = body.name?.toString().trim().slice(0, 64);
  if (!name) {
    return NextResponse.json({ error: "name is required (max 64 chars)" }, { status: 400 });
  }

  // Validate requested scopes.
  const requestedScopes = Array.isArray(body.scopes) ? body.scopes : ["scan:run", "scan:read"];
  const scopes = requestedScopes.filter((s): s is Scope =>
    (VALID_SCOPES as readonly string[]).includes(s as string)
  );
  if (scopes.length === 0) {
    return NextResponse.json(
      { error: `At least one valid scope required: ${VALID_SCOPES.join(", ")}` },
      { status: 400 }
    );
  }

  const { fullKey, keyHash, prefix } = generateApiKey();
  const expiresAt = body.expiresInDays
    ? new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000)
    : null;

  const created = await db.apiKey.create({
    data: {
      name,
      keyHash,
      prefix,
      scopes: JSON.stringify(scopes),
      createdBy: authKey?.name ?? "anonymous",
      expiresAt,
    },
  });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id ?? null,
    actorName: authKey?.name ?? "anonymous",
    action: "apikey.create",
    target: prefix,
    metadata: { name, scopes, keyId: created.id },
  });

  // The full key is returned ONCE here. It is never retrievable again.
  return NextResponse.json(
    {
      id: created.id,
      name: created.name,
      prefix: created.prefix,
      scopes,
      createdAt: created.createdAt,
      expiresAt,
      /** ⚠️ Store this securely. It will NOT be shown again. */
      fullKey,
    },
    { status: 201 }
  );
}
