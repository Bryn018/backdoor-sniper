import { createHmac } from "node:crypto";
import { db } from "@/lib/db";
// Local AuditLog shape (replaces the removed `@prisma/client` type).
// Mirrors prisma/schema.prisma `AuditLog` model.
export interface AuditLog {
  id: string;
  createdAt: Date;
  actorType: "api_key" | "web" | "system" | "cron" | string;
  actorId?: string | null;
  actorName?: string | null;
  actorIp?: string | null;
  action: string;
  target?: string | null;
  outcome: string;
  verdict?: string | null;
  riskScore?: number | null;
  policyPassed?: boolean | null;
  metadata?: string | null;
}

/**
 * Outbound webhook / SIEM sink dispatcher.
 *
 * When a security-relevant audit event is recorded, this module is invoked to
 * fan-out the event to all enabled webhook endpoints. It supports several
 * sink-specific payload transformations (Slack, Microsoft Teams, Discord,
 * Splunk HEC, Datadog, Elasticsearch, PagerDuty, generic JSON POST).
 *
 * Each delivery is logged in `WebhookDelivery` for forensic / retry purposes.
 * Delivery is fire-and-forget — failures never raise to the caller. The audit
 * trail itself is the source of truth; webhooks are a delivery optimisation.
 */

export type SinkType =
  | "generic"
  | "slack"
  | "teams"
  | "discord"
  | "splunk"
  | "datadog"
  | "elasticsearch"
  | "pagerduty";

export interface WebhookPayload {
  /** ISO timestamp the event was generated */
  timestamp: string;
  /** Event action, e.g. "scan.run", "apikey.create" */
  eventType: string;
  /** Outcome: success | failure | denied */
  outcome: string;
  /** Who/what initiated the event */
  actor: {
    type: string;
    id?: string | null;
    name?: string | null;
    ip?: string | null;
  };
  /** What the event targeted (file hash, key prefix, etc.) */
  target?: string | null;
  /** For scan events: verdict + risk + policy pass */
  scan?: {
    verdict?: string | null;
    riskScore?: number | null;
    policyPassed?: boolean | null;
    findingCount?: number;
  };
  /** Free-form extra context */
  metadata?: Record<string, unknown>;
  /** BackdoorSniper signature */
  source: "backdoorsniper";
  version: "2.1.0";
}

/**
 * Transform a generic payload into a sink-specific body.
 * Each sink has a different expected JSON shape.
 */
function transformPayload(
  sink: SinkType,
  payload: WebhookPayload
): Record<string, unknown> {
  const ts = payload.timestamp;
  const actor = payload.actor.name || payload.actor.id || payload.actor.type;
  const verdict = payload.scan?.verdict;
  const risk = payload.scan?.riskScore;
  const policy = payload.scan?.policyPassed;

  switch (sink) {
    case "slack": {
      const color =
        payload.outcome === "denied"
          ? "#dc2626"
          : verdict === "dangerous"
            ? "#7f1d1d"
            : verdict === "malicious"
              ? "#b91c1c"
              : verdict === "suspicious"
                ? "#f59e0b"
                : "#10b981";
      const fields: { title: string; value: string; short?: boolean }[] = [
        { title: "Event", value: payload.eventType, short: true },
        { title: "Outcome", value: payload.outcome, short: true },
        { title: "Actor", value: actor, short: true },
      ];
      if (verdict) fields.push({ title: "Verdict", value: verdict, short: true });
      if (typeof risk === "number") fields.push({ title: "Risk", value: `${risk}/100`, short: true });
      if (typeof policy === "boolean") fields.push({ title: "Policy", value: policy ? "PASS" : "FAIL", short: true });
      return {
        username: "BackdoorSniper",
        icon_emoji: ":snake:",
        attachments: [
          {
            fallback: `${payload.eventType} — ${payload.outcome} — ${verdict ?? ""} ${risk ?? ""}`.trim(),
            color,
            ts: Math.floor(new Date(ts).getTime() / 1000),
            title: `:rotating_light: BackdoorSniper — ${payload.eventType}`,
            fields,
            footer: "BackdoorSniper v2.1",
          },
        ],
      };
    }

    case "teams": {
      const theme =
        payload.outcome === "denied" || verdict === "dangerous" ? "FF0000" : verdict === "suspicious" ? "FFA500" : "00FF00";
      const facts = [
        { name: "Event", value: payload.eventType },
        { name: "Outcome", value: payload.outcome },
        { name: "Actor", value: actor },
      ];
      if (verdict) facts.push({ name: "Verdict", value: verdict });
      if (typeof risk === "number") facts.push({ name: "Risk", value: `${risk}/100` });
      if (typeof policy === "boolean") facts.push({ name: "Policy", value: policy ? "PASS" : "FAIL" });
      return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        themeColor: theme,
        summary: `BackdoorSniper ${payload.eventType}`,
        title: `BackdoorSniper — ${payload.eventType}`,
        sections: [
          {
            activityTitle: "BackdoorSniper Security Event",
            activitySubtitle: ts,
            facts,
          },
        ],
      };
    }

    case "discord": {
      const color =
        payload.outcome === "denied"
          ? 0xdc2626
          : verdict === "dangerous"
            ? 0x7f1d1d
            : verdict === "suspicious"
              ? 0xf59e0b
              : 0x10b981;
      const fields = [
        { name: "Event", value: payload.eventType, inline: true },
        { name: "Outcome", value: payload.outcome, inline: true },
        { name: "Actor", value: actor, inline: true },
      ];
      if (verdict) fields.push({ name: "Verdict", value: verdict, inline: true });
      if (typeof risk === "number") fields.push({ name: "Risk", value: `${risk}/100`, inline: true });
      if (typeof policy === "boolean") fields.push({ name: "Policy", value: policy ? "PASS" : "FAIL", inline: true });
      return {
        username: "BackdoorSniper",
        embeds: [
          {
            title: `BackdoorSniper — ${payload.eventType}`,
            color,
            timestamp: ts,
            fields,
            footer: { text: "BackdoorSniper v2.1" },
          },
        ],
      };
    }

    case "splunk": {
      // Splunk HTTP Event Collector (HEC) format
      return {
        time: Math.floor(new Date(ts).getTime() / 1000),
        host: "backdoorsniper",
        source: "backdoorsniper:audit",
        sourcetype: "_json",
        event: payload,
      };
    }

    case "datadog": {
      // Datadog Events API
      const alertType =
        payload.outcome === "denied"
          ? "error"
          : verdict === "dangerous" || verdict === "malicious"
            ? "error"
            : verdict === "suspicious"
              ? "warning"
              : "success";
      const priority = verdict === "dangerous" ? "P1" : verdict === "malicious" ? "P2" : "P3";
      return {
        title: `BackdoorSniper ${payload.eventType} — ${verdict ?? payload.outcome}`,
        text: `Actor: ${actor}\nOutcome: ${payload.outcome}${verdict ? `\nVerdict: ${verdict}` : ""}${typeof risk === "number" ? `\nRisk: ${risk}/100` : ""}${typeof policy === "boolean" ? `\nPolicy: ${policy ? "PASS" : "FAIL"}` : ""}`,
        alert_type: alertType,
        priority,
        tags: [
          "source:backdoorsniper",
          `event:${payload.eventType}`,
          `outcome:${payload.outcome}`,
          `verdict:${verdict ?? "n/a"}`,
        ],
        date_happened: Math.floor(new Date(ts).getTime() / 1000),
        source_type_name: "backdoorsniper",
      };
    }

    case "elasticsearch": {
      // ES document
      return {
        "@timestamp": ts,
        ...payload,
      };
    }

    case "pagerduty": {
      // PagerDuty Events API v2 — only trigger for severe events
      const severity =
        verdict === "dangerous"
          ? "critical"
          : verdict === "malicious"
            ? "error"
            : payload.outcome === "denied"
              ? "warning"
              : "info";
      return {
        routing_key: "", // Caller should set, or use the URL itself
        event_action: "trigger",
        payload: {
          summary: `BackdoorSniper ${payload.eventType} — ${verdict ?? payload.outcome}`,
          severity,
          source: "backdoorsniper",
          custom_details: {
            actor,
            outcome: payload.outcome,
            verdict: verdict ?? "n/a",
            risk: typeof risk === "number" ? `${risk}/100` : "n/a",
            policy: typeof policy === "boolean" ? (policy ? "PASS" : "FAIL") : "n/a",
          },
        },
        timestamps: { event_timestamp: ts },
      };
    }

    case "generic":
    default:
      return payload;
  }
}

/**
 * Compute the HMAC-SHA256 signature of the body using the endpoint's signing
 * secret. Sent as the `X-BackdoorSniper-Signature` header (hex).
 */
function signBody(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Send a single payload to a single webhook endpoint. Records the delivery in
 * the WebhookDelivery table. Never throws — failures are recorded as
 * `failureCount` increments on the endpoint.
 */
async function deliver(
  endpointId: string,
  url: string,
  sinkType: SinkType,
  signingSecret: string | null,
  payload: WebhookPayload
): Promise<{ ok: boolean; status?: number; error?: string; durationMs: number }> {
  const start = Date.now();
  const body = JSON.stringify(transformPayload(sinkType, payload));
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "BackdoorSniper-Webhook/2.1",
    "X-BackdoorSniper-Event": payload.eventType,
  };
  if (signingSecret) {
    headers["X-BackdoorSniper-Signature"] = signBody(body, signingSecret);
    headers["X-BackdoorSniper-Signature-Alg"] = "hmac-sha256";
  }

  let status: number | undefined;
  let responseText = "";
  let errorMessage: string | undefined;
  let ok = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    const res = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);
    status = res.status;
    ok = res.ok;
    responseText = (await res.text()).slice(0, 2000);
    if (!ok) errorMessage = `HTTP ${status}`;
  } catch (e) {
    errorMessage = e instanceof Error ? e.message : String(e);
    ok = false;
  }

  const durationMs = Date.now() - start;

  // Persist the delivery record (best-effort)
  try {
    await db.webhookDelivery.create({
      data: {
        webhookId: endpointId,
        eventType: payload.eventType,
        payload: body.slice(0, 65000),
        statusCode: status,
        response: responseText || null,
        errorMessage: errorMessage || null,
        durationMs,
      },
    });
    await db.webhookEndpoint.update({
      where: { id: endpointId },
      data: {
        lastStatus: ok ? "success" : "failure",
        lastDeliveryAt: new Date(),
        lastError: errorMessage || null,
        successCount: { increment: ok ? 1 : 0 },
        failureCount: { increment: ok ? 0 : 1 },
      },
    });
  } catch {
    // DB failures during webhook delivery are non-fatal
  }

  return { ok, status, error: errorMessage, durationMs };
}

/**
 * Fan out a single audit event to all matching, enabled webhook endpoints.
 * Called by the audit log writer after a record is persisted.
 *
 * Returns the number of endpoints delivered to (success or failure).
 */
export async function dispatchAuditEvent(
  log: AuditLog
): Promise<{ delivered: number; succeeded: number; failed: number }> {
  try {
    const endpoints = await db.webhookEndpoint.findMany({
      where: { enabled: true },
    });
    if (endpoints.length === 0) return { delivered: 0, succeeded: 0, failed: 0 };

    const payload: WebhookPayload = {
      timestamp: log.createdAt.toISOString(),
      eventType: log.action,
      outcome: log.outcome,
      actor: {
        type: log.actorType,
        id: log.actorId,
        name: log.actorName,
        ip: log.actorIp,
      },
      target: log.target,
      scan:
        log.verdict || log.riskScore !== null || log.policyPassed !== null
          ? {
              verdict: log.verdict,
              riskScore: log.riskScore,
              policyPassed: log.policyPassed,
            }
          : undefined,
      metadata: log.metadata ? safeParse(log.metadata) : undefined,
      source: "backdoorsniper",
      version: "2.1.0",
    };

    let delivered = 0;
    let succeeded = 0;
    let failed = 0;

    // Filter endpoints by subscribed events (empty = all events)
    const matching = endpoints.filter((ep) => {
      if (!ep.events || ep.events === "[]") return true;
      try {
        const events = JSON.parse(ep.events) as string[];
        return events.length === 0 || events.includes(log.action);
      } catch {
        return true;
      }
    });

    // Fire in parallel — don't block the caller
    await Promise.all(
      matching.map(async (ep) => {
        const result = await deliver(
          ep.id,
          ep.url,
          ep.sinkType as SinkType,
          ep.signingSecret,
          payload
        );
        delivered++;
        if (result.ok) succeeded++;
        else failed++;
      })
    );

    return { delivered, succeeded, failed };
  } catch {
    // Webhook dispatch failures must NEVER break the request that triggered the audit event
    return { delivered: 0, succeeded: 0, failed: 0 };
  }
}

function safeParse(s: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(s) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}
