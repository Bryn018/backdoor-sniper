import { NextRequest, NextResponse } from "next/server";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { queryAudit } from "@/lib/audit";

export const runtime = "nodejs";

/** GET /api/audit — query the audit log with filters. */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  // Audit log requires scan:read scope if a key is presented.
  if (authKey && !hasScope(authKey, "scan:read")) {
    return NextResponse.json({ error: "Insufficient scope: scan:read required" }, { status: 403 });
  }

  const url = new URL(req.url);
  const action = url.searchParams.get("action") ?? undefined;
  const actorId = url.searchParams.get("actorId") ?? undefined;
  const outcome = url.searchParams.get("outcome") ?? undefined;
  const limit = url.searchParams.get("limit")
    ? Math.min(Number(url.searchParams.get("limit")), 500)
    : 100;
  const offset = url.searchParams.get("offset")
    ? Number(url.searchParams.get("offset"))
    : 0;

  const result = await queryAudit({ action, actorId, outcome, limit, offset });
  return NextResponse.json(result);
}
