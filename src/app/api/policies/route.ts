import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";
import { DEFAULT_POLICY_RULES, parsePolicyRules, type PolicyRules } from "@/lib/policy";

export const runtime = "nodejs";

/** GET /api/policies — list all scan policies. */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "scan:read")) {
    return NextResponse.json({ error: "Insufficient scope: scan:read required" }, { status: 403 });
  }
  const rows = await db.scanPolicy.findMany({ orderBy: { createdAt: "desc" } });
  return NextResponse.json({
    policies: rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      rules: parsePolicyRules(r.rules),
      isDefault: r.isDefault,
      createdBy: r.createdBy,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    })),
    defaults: DEFAULT_POLICY_RULES,
  });
}

/** POST /api/policies — create a new scan policy. */
export async function POST(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "policy:manage")) {
    return NextResponse.json({ error: "Insufficient scope: policy:manage required" }, { status: 403 });
  }

  let body: {
    name?: string;
    description?: string;
    rules?: PolicyRules;
    isDefault?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const name = body.name?.toString().trim().slice(0, 64);
  if (!name) {
    return NextResponse.json({ error: "name is required (max 64 chars)" }, { status: 400 });
  }

  const existing = await db.scanPolicy.findUnique({ where: { name } });
  if (existing) {
    return NextResponse.json({ error: `Policy "${name}" already exists` }, { status: 409 });
  }

  // If this policy is set as default, unset any existing default first.
  if (body.isDefault) {
    await db.scanPolicy.updateMany({
      where: { isDefault: true },
      data: { isDefault: false },
    });
  }

  const rules: PolicyRules = body.rules ?? DEFAULT_POLICY_RULES;
  const created = await db.scanPolicy.create({
    data: {
      name,
      description: body.description?.toString().slice(0, 500) ?? null,
      rules: JSON.stringify(rules),
      isDefault: body.isDefault ?? false,
      createdBy: authKey?.name ?? "anonymous",
    },
  });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id ?? null,
    actorName: authKey?.name ?? "anonymous",
    action: "policy.create",
    target: name,
    metadata: { rules, isDefault: body.isDefault ?? false },
  });

  return NextResponse.json(
    {
      id: created.id,
      name: created.name,
      description: created.description,
      rules: parsePolicyRules(created.rules),
      isDefault: created.isDefault,
    },
    { status: 201 }
  );
}
