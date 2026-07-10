import { NextRequest, NextResponse } from "next/server";
import { createHash } from "node:crypto";
import {
  scanPython,
  buildCustomRule,
  type CustomRuleSpec,
  type DetectionRule,
  type SuppressionMatch,
} from "@/lib/detector";
import { db } from "@/lib/db";
import { validateApiKey } from "@/lib/auth/api-key";
import { enforceRateLimit, actorKeyFromRequest } from "@/lib/auth/rate-limit";
import { recordAudit } from "@/lib/audit";
import {
  evaluatePolicy,
  parsePolicyRules,
  DEFAULT_POLICY_RULES,
  formatCISummary,
  type PolicyEvaluation,
} from "@/lib/policy";

export const runtime = "nodejs";

const MAX_SOURCE_BYTES = 500_000; // 500 KB cap
const MAX_CUSTOM_RULES = 50;

function getClientIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}

/** Load active suppressions from the database (enterprise baseline). */
async function loadSuppressions(sourceHash: string): Promise<SuppressionMatch[]> {
  try {
    // Global suppressions (sourceHash null) + per-file suppressions, unexpired only.
    const rows = await db.suppression.findMany({
      where: {
        OR: [{ sourceHash: null }, { sourceHash }],
        expiresAt: null,
      },
    });
    const seen = new Set<string>();
    const out: SuppressionMatch[] = [];
    for (const r of rows) {
      const key = `${r.ruleId}:${r.sourceHash ?? ""}:${r.line ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ ruleId: r.ruleId, sourceHash: r.sourceHash, line: r.line });
    }
    return out;
  } catch {
    return [];
  }
}

export async function POST(req: NextRequest) {
  const actorIp = getClientIp(req);
  const authHeader = req.headers.get("authorization");
  const apiKey = await validateApiKey(authHeader);

  // Rate limit: anonymous web UI gets a smaller bucket, API keys get the full one.
  const rateLimitRes = enforceRateLimit(req, actorKeyFromRequest(req, apiKey?.id), !apiKey);
  if (rateLimitRes) return rateLimitRes;

  let body: {
    code?: string;
    fileName?: string;
    save?: boolean;
    disabledRuleIds?: string[];
    customRules?: CustomRuleSpec[];
    policyName?: string;
    scanMode?: string;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const code = (body.code ?? "").toString();
  const fileName = body.fileName?.toString().slice(0, 255) || null;
  const save = body.save !== false; // default true
  const disabledRuleIds = body.disabledRuleIds
    ? new Set<string>(body.disabledRuleIds)
    : undefined;
  const scanMode: "ci" | "batch" | "cron" | "manual" =
    body.scanMode === "ci" ? "ci"
    : body.scanMode === "batch" ? "batch"
    : body.scanMode === "cron" ? "cron"
    : "manual";

  if (!code.trim()) {
    return NextResponse.json(
      { error: "No code provided. Paste some Python source to scan." },
      { status: 400 }
    );
  }
  if (Buffer.byteLength(code, "utf8") > MAX_SOURCE_BYTES) {
    return NextResponse.json(
      { error: `Source too large. Limit is ${MAX_SOURCE_BYTES} bytes.` },
      { status: 413 }
    );
  }

  // Compile any user-supplied custom rules.
  const customRuleErrors: { id: string; error: string }[] = [];
  const compiledCustomRules: DetectionRule[] = [];
  if (Array.isArray(body.customRules) && body.customRules.length > 0) {
    const limited = body.customRules.slice(0, MAX_CUSTOM_RULES);
    for (const spec of limited) {
      const { rule, error } = buildCustomRule(spec);
      if (error) {
        customRuleErrors.push({ id: spec.id ?? "(no id)", error });
      } else if (rule) {
        compiledCustomRules.push(rule);
      }
    }
  }

  // Load suppressions from DB (enterprise baseline).
  const sourceHash = createHash("sha256").update(code).digest("hex").slice(0, 16);
  const suppressions = await loadSuppressions(sourceHash);

  const result = scanPython(code, disabledRuleIds, compiledCustomRules, suppressions);

  // --- Policy evaluation (enterprise CI/CD gating) ---
  let policy: ScanPolicyResponse | null = null;
  let policyEval: PolicyEvaluation | null = null;
  try {
    const policyRow = body.policyName
      ? await db.scanPolicy.findUnique({ where: { name: body.policyName } })
      : await db.scanPolicy.findFirst({ where: { isDefault: true } });
    const rules = policyRow
      ? parsePolicyRules(policyRow.rules)
      : DEFAULT_POLICY_RULES;
    const policyName = policyRow?.name ?? "default";
    policyEval = evaluatePolicy(
      policyName,
      rules,
      result.findings,
      result.riskScore,
      result.verdict
    );
    policy = {
      name: policyName,
      passed: policyEval.passed,
      violations: policyEval.violations,
      blockingFindingIds: policyEval.blockingFindings.map(
        (f) => `${f.ruleId}:${f.line}`
      ),
      ciSummary: formatCISummary(policyEval, result.riskScore, result.verdict),
    };
  } catch (e) {
    console.error("[scan] policy evaluation failed:", e);
  }

  // --- Persist scan record ---
  let savedId: string | null = null;
  if (save) {
    try {
      const record = await db.scanRecord.create({
        data: {
          sourceHash: result.sourceHash,
          fileName,
          riskScore: result.riskScore,
          verdict: result.verdict,
          totalLines: result.stats.totalLines,
          findings: JSON.stringify(result.findings),
          sourcePreview: code.slice(0, 500),
          apiKeyId: apiKey?.id ?? null,
          actorIp,
          policyName: policy?.name ?? null,
          policyPassed: policy?.passed ?? null,
          policyViolations: policyEval
            ? JSON.stringify(policyEval.violations)
            : null,
          scanMode,
        },
      });
      savedId = record.id;
    } catch (e) {
      console.error("Failed to persist scan record:", e);
    }
  }

  // --- Audit log ---
  await recordAudit({
    actorType: apiKey ? "api_key" : scanMode === "cron" ? "cron" : "web",
    actorId: apiKey?.id ?? null,
    actorName: apiKey?.name ?? null,
    actorIp,
    action: "scan.run",
    target: result.sourceHash,
    outcome: "success",
    verdict: result.verdict,
    riskScore: result.riskScore,
    policyPassed: policy?.passed ?? null,
    metadata: {
      fileName,
      findingsCount: result.stats.totalFindings,
      scanMode,
      policyName: policy?.name ?? null,
    },
  });

  const responseStatus =
    scanMode === "ci" && policy && !policy.passed ? 418 : 200;

  return NextResponse.json(
    {
      ...result,
      savedId,
      policy,
      customRuleErrors: customRuleErrors.length > 0 ? customRuleErrors : undefined,
      authenticatedAs: apiKey ? { name: apiKey.name, prefix: apiKey.prefix } : null,
    },
    { status: responseStatus }
  );
}

interface ScanPolicyResponse {
  name: string;
  passed: boolean;
  violations: { kind: string; message: string; detail?: unknown }[];
  blockingFindingIds: string[];
  ciSummary: string;
}

export async function GET() {
  return NextResponse.json({
    name: "BackdoorSniper — Python Backdoor Detector",
    version: 2,
    enterprise: true,
    endpoints: {
      scan: "POST /api/scan  { code, fileName?, save?, disabledRuleIds?, customRules?, policyName?, scanMode? }",
      history: "GET /api/history",
      health: "GET /api/health",
      apiKeys: "GET/POST /api/api-keys  (requires apikey:manage scope)",
      audit: "GET /api/audit  (requires scan:read scope)",
      policies: "GET/POST /api/policies",
      suppressions: "GET/POST /api/suppressions",
    },
    auth: "Bearer bdp_live_...  (Authorization header)",
  });
}
