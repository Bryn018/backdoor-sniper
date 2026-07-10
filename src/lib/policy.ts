import type { Finding, Severity } from "@/lib/detector/types";

/**
 * Scan policy engine — defines pass/fail gates for CI/CD integration.
 *
 * A policy is a JSON document with optional rules:
 *   {
 *     "maxRiskScore": 50,            // fail if risk score exceeds
 *     "blockedSeverities": ["critical", "high"],  // fail if any unsuppressed finding of these severities
 *     "blockedRuleIds": ["PY-EXEC-001"],          // fail if any of these specific rules fire
 *     "maxFindings": 0,              // fail if unsuppressed finding count exceeds
 *     "blockOnVerdict": ["dangerous", "malicious"] // fail if verdict is one of these
 *   }
 *
 * The default policy blocks on any critical finding or a "dangerous" verdict.
 */

export interface PolicyRules {
  maxRiskScore?: number;
  blockedSeverities?: Severity[];
  blockedRuleIds?: string[];
  maxFindings?: number;
  blockOnVerdict?: string[];
}

export interface PolicyEvaluation {
  policyName: string;
  passed: boolean;
  violations: PolicyViolation[];
  /** The findings (unsuppressed) that caused a violation, for the CI report. */
  blockingFindings: Finding[];
  evaluatedAt: string;
}

export interface PolicyViolation {
  kind:
    | "risk-score"
    | "severity"
    | "rule-id"
    | "finding-count"
    | "verdict";
  message: string;
  detail?: unknown;
}

export const DEFAULT_POLICY_RULES: PolicyRules = {
  blockedSeverities: ["critical"],
  blockOnVerdict: ["dangerous"],
};

/** Parse a policy's JSON rules string into a typed object. */
export function parsePolicyRules(raw: string): PolicyRules {
  try {
    const obj = JSON.parse(raw) as Partial<PolicyRules>;
    return {
      maxRiskScore: typeof obj.maxRiskScore === "number" ? obj.maxRiskScore : undefined,
      blockedSeverities: Array.isArray(obj.blockedSeverities)
        ? (obj.blockedSeverities as Severity[])
        : undefined,
      blockedRuleIds: Array.isArray(obj.blockedRuleIds)
        ? (obj.blockedRuleIds as string[])
        : undefined,
      maxFindings: typeof obj.maxFindings === "number" ? obj.maxFindings : undefined,
      blockOnVerdict: Array.isArray(obj.blockOnVerdict)
        ? (obj.blockOnVerdict as string[])
        : undefined,
    };
  } catch {
    return DEFAULT_POLICY_RULES;
  }
}

/**
 * Evaluate a scan's findings against a policy.
 * Suppressed findings are NOT counted (they are accepted-risk baselines).
 */
export function evaluatePolicy(
  policyName: string,
  rules: PolicyRules,
  findings: Finding[],
  riskScore: number,
  verdict: string
): PolicyEvaluation {
  const active = findings.filter((f) => !f.suppressed);
  const violations: PolicyViolation[] = [];
  const blockingFindings: Finding[] = [];

  if (typeof rules.maxRiskScore === "number" && riskScore > rules.maxRiskScore) {
    violations.push({
      kind: "risk-score",
      message: `Risk score ${riskScore} exceeds maximum ${rules.maxRiskScore}`,
      detail: { score: riskScore, max: rules.maxRiskScore },
    });
  }

  if (rules.blockedSeverities?.length) {
    const blocked = active.filter((f) => rules.blockedSeverities!.includes(f.severity));
    if (blocked.length > 0) {
      violations.push({
        kind: "severity",
        message: `${blocked.length} finding(s) at blocked severity level(s): ${rules.blockedSeverities.join(", ")}`,
        detail: { count: blocked.length, severities: rules.blockedSeverities },
      });
      blockingFindings.push(...blocked);
    }
  }

  if (rules.blockedRuleIds?.length) {
    const blocked = active.filter((f) => rules.blockedRuleIds!.includes(f.ruleId));
    if (blocked.length > 0) {
      violations.push({
        kind: "rule-id",
        message: `${blocked.length} finding(s) from blocked rule(s): ${rules.blockedRuleIds.join(", ")}`,
        detail: { count: blocked.length, ruleIds: rules.blockedRuleIds },
      });
      blockingFindings.push(...blocked);
    }
  }

  if (typeof rules.maxFindings === "number" && active.length > rules.maxFindings) {
    violations.push({
      kind: "finding-count",
      message: `${active.length} active finding(s) exceed maximum ${rules.maxFindings}`,
      detail: { count: active.length, max: rules.maxFindings },
    });
  }

  if (rules.blockOnVerdict?.length && rules.blockOnVerdict.includes(verdict)) {
    violations.push({
      kind: "verdict",
      message: `Verdict "${verdict}" is in the blocked list: ${rules.blockOnVerdict.join(", ")}`,
      detail: { verdict, blocked: rules.blockOnVerdict },
    });
  }

  return {
    policyName,
    passed: violations.length === 0,
    violations,
    blockingFindings,
    evaluatedAt: new Date().toISOString(),
  };
}

/**
 * Produce an exit-code-friendly CI/CD summary string.
 * Suitable for printing in a GitHub Actions / Jenkins log.
 */
export function formatCISummary(eval_: PolicyEvaluation, riskScore: number, verdict: string): string {
  const lines: string[] = [];
  lines.push(`╔══════════════════════════════════════════════════════════╗`);
  lines.push(`║  BackdoorSniper — Scan Policy: ${eval_.policyName.padEnd(28)} ║`);
  lines.push(`╠══════════════════════════════════════════════════════════╣`);
  lines.push(`║  Result:   ${eval_.passed ? "PASS ✓" : "FAIL ✗"}${eval_.passed ? "                                  " : "                                  "}║`);
  lines.push(`║  Risk:     ${String(riskScore).padEnd(3)}/100   Verdict: ${verdict.padEnd(11)}     ║`);
  lines.push(`║  Blocking findings: ${String(eval_.blockingFindings.length).padEnd(37)}║`);
  lines.push(`╚══════════════════════════════════════════════════════════╝`);
  if (eval_.violations.length > 0) {
    lines.push("");
    lines.push("Policy violations:");
    for (const v of eval_.violations) {
      lines.push(`  • [${v.kind}] ${v.message}`);
    }
  }
  if (eval_.blockingFindings.length > 0) {
    lines.push("");
    lines.push("Blocking findings:");
    for (const f of eval_.blockingFindings.slice(0, 20)) {
      lines.push(`  • ${f.ruleId} [${f.severity.toUpperCase()}] line ${f.line}: ${f.title}`);
    }
    if (eval_.blockingFindings.length > 20) {
      lines.push(`  ... and ${eval_.blockingFindings.length - 20} more`);
    }
  }
  return lines.join("\n");
}
