import { db } from "@/lib/db";
import { scanPython } from "@/lib/detector/scanner";
import { evaluatePolicy } from "@/lib/policy";
import { dispatchAuditEvent } from "@/lib/webhook";
import type { Finding } from "@/lib/detector/types";

/**
 * Scheduled-scan runner. Fetches source (paste / url), runs the detector,
 * persists a ScanRecord, evaluates the configured policy (if any), and
 * fires webhooks when configured (notifyOnFail / notifyOnCritical).
 */

export interface ScanSourceResult {
  scanRecordId: string;
  riskScore: number;
  verdict: string;
  findingCount: number;
  policyPassed: boolean | null;
  policyViolations: string[];
}

export async function scanSource(
  sourceType: string,
  sourceData: string,
  policyName: string | undefined | null,
  scheduledScanId: string
): Promise<ScanSourceResult> {
  let source: string;

  if (sourceType === "paste") {
    source = sourceData;
  } else if (sourceType === "url") {
    // Fetch the URL with a strict timeout & size limit
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const res = await fetch(sourceData, {
        signal: controller.signal,
        headers: { "User-Agent": "BackdoorSniper-ScheduledScan/2.1" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${sourceData}`);
      const text = await res.text();
      // Cap at 2 MB to avoid DoS
      if (text.length > 2 * 1024 * 1024) throw new Error("Source exceeds 2 MB limit");
      source = text;
    } finally {
      clearTimeout(timeout);
    }
  } else {
    throw new Error(`Unknown sourceType: ${sourceType}`);
  }

  // Run the detector
  const result = scanPython(source);

  // Evaluate policy if specified
  let policyPassed: boolean | null = null;
  let policyViolations: string[] = [];
  if (policyName) {
    const policy = await db.scanPolicy.findUnique({ where: { name: policyName } });
    if (policy) {
      let rules: { maxRiskScore?: number; blockedSeverities?: string[]; blockedRuleIds?: string[]; maxFindings?: number; blockOnVerdict?: string[] };
      try {
        rules = JSON.parse(policy.rules);
      } catch {
        rules = {};
      }
      const evaluation = evaluatePolicy(policyName, rules, result.findings, result.riskScore, result.verdict);
      policyPassed = evaluation.passed;
      policyViolations = evaluation.violations.map((v) => `${v.kind}: ${v.message}`);
    }
  }

  // Persist ScanRecord with scanMode=cron
  const scanRecord = await db.scanRecord.create({
    data: {
      sourceHash: result.sourceHash,
      fileName: sourceType === "url" ? sourceData : `scheduled:${scheduledScanId}`,
      riskScore: result.riskScore,
      verdict: result.verdict,
      totalLines: result.stats.totalLines,
      findings: JSON.stringify(result.findings),
      sourcePreview: source.slice(0, 500),
      policyName: policyName ?? null,
      policyPassed,
      policyViolations: policyViolations.length > 0 ? JSON.stringify(policyViolations) : null,
      scanMode: "cron",
    },
  });

  // Record audit entry
  const auditLog = {
    id: scanRecord.id,
    createdAt: new Date(),
    actorType: "cron" as const,
    actorId: scheduledScanId,
    actorName: `scheduled:${scheduledScanId}`,
    actorIp: null,
    action: "scheduledscan.run" as const,
    target: result.sourceHash,
    outcome: "success" as const,
    verdict: result.verdict,
    riskScore: result.riskScore,
    policyPassed,
    metadata: JSON.stringify({
      scheduledScanId,
      findingCount: result.findings.length,
      fileName: scanRecord.fileName,
      policyName: policyName ?? null,
    }),
  };

  await db.auditLog.create({ data: {
    actorType: "cron",
    actorId: scheduledScanId,
    actorName: `scheduled:${scheduledScanId}`,
    action: "scheduledscan.run",
    target: result.sourceHash,
    outcome: "success",
    verdict: result.verdict,
    riskScore: result.riskScore,
    policyPassed,
    metadata: auditLog.metadata,
  }});

  // Fire webhooks for this scheduled scan event (always — let the sink decide)
  void dispatchAuditEvent(auditLog as never).catch(() => {});

  // Determine whether we should also fire the alert-style webhook
  const hasCritical = result.findings.some((f: Finding) => f.severity === "critical");
  const job = await db.scheduledScan.findUnique({ where: { id: scheduledScanId } });
  const shouldAlert =
    job && (
      (job.notifyOnFail && policyPassed === false) ||
      (job.notifyOnCritical && hasCritical)
    );

  if (shouldAlert) {
    // Build a synthetic high-priority audit event that sinks (Slack/PagerDuty)
    // will render as an alert.
    const alertLog = {
      id: "alert-" + scanRecord.id,
      createdAt: new Date(),
      actorType: "cron" as const,
      actorId: scheduledScanId,
      actorName: `ALERT:${scheduledScanId}`,
      actorIp: null,
      action: "scheduledscan.run" as const,
      target: result.sourceHash,
      outcome: "failure" as const, // alert = elevated severity
      verdict: result.verdict,
      riskScore: result.riskScore,
      policyPassed,
      metadata: JSON.stringify({
        alert: true,
        reason: policyPassed === false ? "policy_failed" : "critical_findings",
        scheduledScanId,
        scheduledScanName: job?.name,
        findingCount: result.findings.length,
        criticalCount: result.findings.filter((f: Finding) => f.severity === "critical").length,
      }),
    };
    void dispatchAuditEvent(alertLog as never).catch(() => {});
  }

  return {
    scanRecordId: scanRecord.id,
    riskScore: result.riskScore,
    verdict: result.verdict,
    findingCount: result.findings.length,
    policyPassed,
    policyViolations,
  };
}
