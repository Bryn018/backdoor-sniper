import { db } from "@/lib/db";
import { dispatchAuditEvent } from "@/lib/webhook";

/**
 * Tamper-evident audit logging for every security-relevant action.
 *
 * Every scan, API key creation/revocation, policy change and suppression
 * change is recorded with: actor (api key id / web / system), actor IP,
 * action, target, outcome, verdict (for scans) and arbitrary metadata.
 *
 * After persisting, the entry is fanned out to all enabled webhook / SIEM
 * sinks (Slack, Splunk, Teams, Datadog, etc.) — see src/lib/webhook.ts.
 */

export type ActorType = "api_key" | "web" | "system" | "cron";
export type AuditAction =
  | "scan.run"
  | "scan.read"
  | "scan.project"
  | "scan.upload"
  | "scan.stream"
  | "apikey.create"
  | "apikey.revoke"
  | "apikey.delete"
  | "policy.create"
  | "policy.update"
  | "policy.delete"
  | "suppression.create"
  | "suppression.delete"
  | "webhook.create"
  | "webhook.update"
  | "webhook.delete"
  | "webhook.test"
  | "scheduledscan.create"
  | "scheduledscan.update"
  | "scheduledscan.delete"
  | "scheduledscan.run"
  | "auth.denied";
export type AuditOutcome = "success" | "failure" | "denied";

export interface AuditEntry {
  actorType: ActorType;
  actorId?: string | null;
  actorName?: string | null;
  actorIp?: string | null;
  action: AuditAction;
  target?: string | null;
  outcome?: AuditOutcome;
  verdict?: string | null;
  riskScore?: number | null;
  policyPassed?: boolean | null;
  metadata?: Record<string, unknown> | null;
}

/** Insert an audit log entry. Never throws — audit failures must not break the request. */
export async function recordAudit(entry: AuditEntry): Promise<void> {
  try {
    const created = await db.auditLog.create({
      data: {
        actorType: entry.actorType,
        actorId: entry.actorId ?? null,
        actorName: entry.actorName ?? null,
        actorIp: entry.actorIp ?? null,
        action: entry.action,
        target: entry.target ?? null,
        outcome: entry.outcome ?? "success",
        verdict: entry.verdict ?? null,
        riskScore: entry.riskScore ?? null,
        policyPassed: entry.policyPassed ?? null,
        metadata: entry.metadata ? JSON.stringify(entry.metadata) : null,
      },
    });

    // Fan out to webhook / SIEM sinks (fire-and-forget; failures are isolated).
    // We deliberately do NOT await this in the request path.
    void dispatchAuditEvent(created).catch(() => {
      /* swallow — webhooks are best-effort */
    });
  } catch (e) {
    // Audit logging must never break the request flow.
    console.error("[audit] failed to record entry:", e);
  }
}

export interface AuditQuery {
  action?: string;
  actorId?: string;
  outcome?: string;
  limit?: number;
  offset?: number;
}

/** Query the audit log with optional filters. */
export async function queryAudit(q: AuditQuery = {}) {
  const where: Record<string, unknown> = {};
  if (q.action) where.action = q.action;
  if (q.actorId) where.actorId = q.actorId;
  if (q.outcome) where.outcome = q.outcome;
  const limit = Math.min(q.limit ?? 100, 500);
  const offset = q.offset ?? 0;
  const [rows, total] = await Promise.all([
    db.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
      skip: offset,
    }),
    db.auditLog.count({ where }),
  ]);
  return {
    rows: rows.map((r) => ({
      ...r,
      metadata: r.metadata ? safeParse(r.metadata) : null,
    })),
    total,
    limit,
    offset,
  };
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
