import { createHash } from "node:crypto";
import type {
  Category,
  DetectionRule,
  Finding,
  RawMatch,
  ScanContext,
  ScanResult,
  ScanStats,
  Severity,
} from "./types";
import { RULES } from "./rules";
import { RULES_ENTERPRISE } from "./rules-enterprise";
import { RULES_SUPPLY_CHAIN } from "./rules-supply-chain";
import { RULES_AST } from "./rules-ast";
import { COMPLIANCE_MAP } from "./compliance";

/** Combined rule set: built-in + enterprise hardening + supply-chain + AST-aware rules. */
export const ALL_RULES: DetectionRule[] = [
  ...RULES,
  ...RULES_ENTERPRISE,
  ...RULES_SUPPLY_CHAIN,
  ...RULES_AST,
];

/** Exported for reuse by the streaming + project scanners. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 14,
  medium: 7,
  low: 3,
  info: 1,
};

/** Exported for reuse by the streaming + project scanners. */
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Exported for reuse by the streaming + project scanners. */
export const ALL_CATEGORIES: Category[] = [
  "code-execution",
  "command-execution",
  "network",
  "reverse-shell",
  "obfuscation",
  "deserialization",
  "dangerous-import",
  "persistence",
  "credential-theft",
  "privilege-escalation",
  "exfiltration",
  "anti-analysis",
  "filesystem",
  "hardcoded-secret",
  "suspicious-pattern",
  "supply-chain",
];

/** Parse `import X` and `from X import Y` statements (best-effort, line based). */
export function extractImports(source: string, lines: string[]): {
  imports: Set<string>;
  fromImports: Set<string>;
} {
  const imports = new Set<string>();
  const fromImports = new Set<string>();
  for (const raw of lines) {
    const line = stripLineComment(raw).trim();
    // import a, b.c as d
    const m1 = /^import\s+(.+)$/.exec(line);
    if (m1) {
      for (const part of m1[1].split(",")) {
        const name = part.split(/\s+as\s+/)[0].trim().split(".")[0];
        if (name) imports.add(name);
      }
      continue;
    }
    // from a.b import c, d
    const m2 = /^from\s+([\w.]+)\s+import\s+(.+)$/.exec(line);
    if (m2) {
      const mod = m2[1].split(".")[0];
      if (mod) imports.add(mod);
      for (const part of m2[2].split(",")) {
        const name = part.split(/\s+as\s+/)[0].trim();
        if (name && name !== "(" && name !== ")") fromImports.add(name);
      }
    }
  }
  return { imports, fromImports };
}

export function stripLineComment(line: string): string {
  let inS = false;
  let inD = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === "#" && !inS && !inD) return line.slice(0, i);
  }
  return line;
}

/** Heuristic obfuscation signal counter (0..N). */
export function computeObfuscationSignals(lines: string[]): number {
  let signals = 0;
  let longLines = 0;
  let chrCount = 0;
  let base64Count = 0;
  for (const l of lines) {
    if (l.length > 500) longLines++;
    if (/chr\s*\(\s*\d+\s*\)/.test(l)) chrCount++;
    if (/['"][A-Za-z0-9+/=]{80,}['"]/.test(l)) base64Count++;
  }
  if (longLines >= 1) signals += Math.min(longLines, 3);
  if (chrCount >= 3) signals += 2;
  if (base64Count >= 2) signals += 2;
  return signals;
}

export function buildFinding(rule: DetectionRule, raw: RawMatch): Finding {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    line: raw.line,
    snippet: raw.snippet,
    description: rule.description,
    remediation: rule.remediation,
    references: rule.references,
    confidence: raw.confidence ?? 0.85,
    compliance: COMPLIANCE_MAP[rule.id],
  };
}

/** De-duplicate findings: same rule+line keeps the highest-confidence one. */
export function dedupe(findings: Finding[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.ruleId}:${f.line}`;
    const prev = map.get(key);
    if (!prev || f.confidence > prev.confidence) map.set(key, f);
  }
  return Array.from(map.values()).sort((a, b) => {
    // severity first, then line number
    const sa = SEVERITY_ORDER.indexOf(a.severity);
    const sb = SEVERITY_ORDER.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    return a.line - b.line;
  });
}

export function computeStats(findings: Finding[], totalLines: number): ScanStats {
  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  } as Record<Severity, number>;
  const byCategory = {} as Record<Category, number>;
  for (const c of ALL_CATEGORIES) byCategory[c] = 0;
  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }
  return {
    totalLines,
    totalFindings: findings.length,
    bySeverity,
    byCategory,
  };
}

export function computeRiskScore(findings: Finding[], obfSignals: number): number {
  let score = 0;
  for (const f of findings) {
    score += SEVERITY_WEIGHT[f.severity] * Math.max(0.4, f.confidence);
  }
  score += obfSignals * 3;
  // critical findings boost: any single critical reverse-shell / code-exec = floor of 75
  const hasCriticalExec = findings.some(
    (f) =>
      f.severity === "critical" &&
      (f.category === "code-execution" ||
        f.category === "reverse-shell" ||
        f.category === "deserialization")
  );
  if (hasCriticalExec) score = Math.max(score, 78);
  return Math.min(100, Math.round(score));
}

export function verdictFromScore(score: number, findings: Finding[]): ScanResult["verdict"] {
  if (score >= 70) return "dangerous";
  const hasCritical = findings.some((f) => f.severity === "critical");
  if (hasCritical || score >= 40) return "malicious";
  if (findings.length > 0) return "suspicious";
  return "clean";
}

/** Main entry point: scan a Python source string and return a structured result. */
export function scanPython(
  source: string,
  disabledRuleIds?: Set<string>,
  customRules?: DetectionRule[],
  suppressions?: SuppressionMatch[]
): ScanResult {
  const start = Date.now();
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const { imports, fromImports } = extractImports(source, lines);
  const obfuscationSignals = computeObfuscationSignals(lines);

  const ctx: ScanContext = {
    source,
    lines,
    imports,
    fromImports,
    obfuscationSignals,
  };

  const disabled = disabledRuleIds ?? new Set<string>();
  // Combine built-in + enterprise rules with custom user-defined rules
  const allRules: DetectionRule[] = [...ALL_RULES, ...(customRules ?? [])];
  const rawFindings: Finding[] = [];
  for (const rule of allRules) {
    if (disabled.has(rule.id)) continue;
    const matches = safeMatch(rule, ctx);
    for (const m of matches) rawFindings.push(buildFinding(rule, m));
  }

  let findings = dedupe(rawFindings);

  // Apply suppressions (enterprise baseline / false-positive management)
  if (suppressions && suppressions.length > 0) {
    const sourceHash = hashSource(source);
    findings = findings.map((f) => {
      const isSuppressed = suppressions.some(
        (s) =>
          s.ruleId === f.ruleId &&
          (s.sourceHash == null || s.sourceHash === sourceHash) &&
          (s.line == null || s.line === f.line)
      );
      return isSuppressed ? { ...f, suppressed: true } : f;
    });
  }

  const stats = computeStats(findings, lines.length);
  const riskScore = computeRiskScore(findings, obfuscationSignals);
  const verdict = verdictFromScore(riskScore, findings);

  return {
    findings,
    stats,
    riskScore,
    verdict,
    durationMs: Date.now() - start,
    sourceHash: hashSource(source),
    scannedAt: new Date().toISOString(),
  };
}

/** A suppression spec used to mark findings as false positives. */
export interface SuppressionMatch {
  ruleId: string;
  sourceHash?: string | null;
  line?: number | null;
}

/**
 * Build a custom DetectionRule from a user-supplied spec (regex-based).
 * The rule matches line-by-line: any line whose trimmed content matches the
 * pattern produces a finding. Pattern must be a valid JavaScript regex source
 * (flags ignored; we always use a case-insensitive global match per line).
 */
export function buildCustomRule(spec: CustomRuleSpec): {
  rule?: DetectionRule;
  error?: string;
} {
  if (!spec.id || !/^[\w-]+$/.test(spec.id)) {
    return { error: "Rule id is required and must be alphanumeric/underscore/hyphen." };
  }
  if (!spec.title?.trim()) {
    return { error: "Title is required." };
  }
  if (!spec.pattern?.trim()) {
    return { error: "Regex pattern is required." };
  }
  let regex: RegExp;
  try {
    regex = new RegExp(spec.pattern, "i");
  } catch (e) {
    return {
      error: `Invalid regex: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
  const validSeverities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const severity = validSeverities.includes(spec.severity as Severity)
    ? (spec.severity as Severity)
    : "medium";
  const validCategories = ALL_CATEGORIES;
  const category = validCategories.includes(spec.category as Category)
    ? (spec.category as Category)
    : "suspicious-pattern";

  const rule: DetectionRule = {
    id: spec.id,
    title: spec.title.trim(),
    severity,
    category,
    description: spec.description?.trim() || "User-defined detection rule.",
    remediation: spec.remediation?.trim() || "Review the matched line and remove or replace if unsafe.",
    references: spec.references
      ? spec.references.split(/[\s,]+/).filter(Boolean)
      : undefined,
    match: (ctx: ScanContext): RawMatch[] => {
      const out: RawMatch[] = [];
      for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        // Match against the full line (with leading whitespace trimmed)
        const target = line.trim();
        if (!target) continue;
        // Reset lastIndex because we reuse the regex per line
        regex.lastIndex = 0;
        if (regex.test(target)) {
          out.push({
            line: i + 1,
            snippet: line.length > 200 ? line.slice(0, 200) + "…" : line,
            confidence: 0.7, // custom rules get a moderate default confidence
          });
        }
      }
      return out;
    },
  };
  return { rule };
}

export interface CustomRuleSpec {
  id: string;
  title: string;
  severity: string;
  category: string;
  pattern: string;
  description?: string;
  remediation?: string;
  references?: string;
}

/** Run a rule's match() with try/catch — never throws. */
export function safeMatch(rule: DetectionRule, ctx: ScanContext): RawMatch[] {
  try {
    return rule.match(ctx) ?? [];
  } catch {
    return [];
  }
}

/** Exported for reuse by the streaming + project scanners. */
export function hashSource(source: string): string {
  return createHash("sha256").update(source).digest("hex").slice(0, 16);
}
