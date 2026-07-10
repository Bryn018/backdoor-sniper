import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";
import { recordAudit } from "@/lib/audit";
import { dispatchAuditEvent } from "@/lib/webhook";

export const runtime = "nodejs";

const VALID_SINKS = new Set([
  "generic",
  "slack",
  "teams",
  "discord",
  "splunk",
  "datadog",
  "elasticsearch",
  "pagerduty",
]);

/** GET /api/webhooks — list all webhook endpoints. */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "admin")) {
    return NextResponse.json(
      { error: "Insufficient scope: admin required" },
      { status: 403 }
    );
  }
  const endpoints = await db.webhookEndpoint.findMany({
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  return NextResponse.json({
    rows: endpoints.map((e) => ({
      ...e,
      signingSecret: e.signingSecret ? "••••" + e.signingSecret.slice(-4) : null,
      events: safeParseArray(e.events),
    })),
    total: endpoints.length,
  });
}

/** POST /api/webhooks — create a new webhook endpoint. */
export async function POST(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "admin")) {
    return NextResponse.json(
      { error: "Insufficient scope: admin required" },
      { status: 403 }
    );
  }
  let body: {
    name?: string;
    url?: string;
    sinkType?: string;
    events?: string[];
    signingSecret?: string;
    enabled?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const name = (body.name || "").trim();
  const url = (body.url || "").trim();
  const sinkType = (body.sinkType || "generic").trim();

  if (!name) return NextResponse.json({ error: "name is required" }, { status: 400 });
  if (!url) return NextResponse.json({ error: "url is required" }, { status: 400 });
  if (!/^https?:\/\//i.test(url))
    return NextResponse.json({ error: "url must start with http:// or https://" }, { status: 400 });
  if (!VALID_SINKS.has(sinkType))
    return NextResponse.json({ error: `invalid sinkType: ${sinkType}` }, { status: 400 });

  const events = Array.isArray(body.events) ? body.events.filter((e) => typeof e === "string") : [];

  const created = await db.webhookEndpoint.create({
    data: {
      name,
      url,
      sinkType,
      events: JSON.stringify(events),
      signingSecret: body.signingSecret || null,
      enabled: body.enabled !== false,
      createdBy: authKey?.name ?? "system",
    },
  });

  await recordAudit({
    actorType: authKey ? "api_key" : "web",
    actorId: authKey?.id,
    actorName: authKey?.name,
    action: "webhook.create",
    target: created.id,
    metadata: { name, url, sinkType, eventsCount: events.length },
  });

  // Send a synthetic test event so the user can verify their config immediately.
  const testLog = {
    id: "test-" + created.id,
    createdAt: new Date(),
    actorType: "system" as const,
    actorId: null,
    actorName: "BackdoorSniper Test",
    actorIp: null,
    action: "webhook.test",
    target: created.id,
    outcome: "success" as const,
    verdict: null,
    riskScore: null,
    policyPassed: null,
    metadata: JSON.stringify({ test: true, message: "Synthetic test event from BackdoorSniper" }),
  };
  const testResult = await dispatchAuditEvent(testLog as never);

  return NextResponse.json(
    {
      ...created,
      signingSecret: created.signingSecret ? "••••" + created.signingSecret.slice(-4) : null,
      events: safeParseArray(created.events),
      testDelivery: testResult,
    },
    { status: 201 }
  );
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
