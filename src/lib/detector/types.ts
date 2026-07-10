// Core types for the Python backdoor detection engine

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "code-execution"
  | "command-execution"
  | "network"
  | "reverse-shell"
  | "obfuscation"
  | "deserialization"
  | "dangerous-import"
  | "persistence"
  | "credential-theft"
  | "privilege-escalation"
  | "exfiltration"
  | "anti-analysis"
  | "filesystem"
  | "hardcoded-secret"
  | "suspicious-pattern"
  | "supply-chain";

/** Compliance framework tags mapped to a finding. */
export interface ComplianceTags {
  /** PCI-DSS requirements, e.g. ["6.5.1", "6.5.7"] */
  pciDss?: string[];
  /** OWASP Top 10 2021, e.g. ["A03:2021 - Injection"] */
  owasp?: string[];
  /** NIST 800-53 control IDs, e.g. ["SI-10", "SC-18"] */
  nist?: string[];
  /** ISO 27001 control IDs, e.g. ["A.14.2.5"] */
  iso27001?: string[];
}

export interface Finding {
  /** Stable rule id, e.g. "PY-EVAL-001" */
  ruleId: string;
  /** Human readable title */
  title: string;
  severity: Severity;
  category: Category;
  /** 1-based line number where the issue was detected */
  line: number;
  /** The exact source line that triggered the rule */
  snippet: string;
  /** Detailed explanation of why this is dangerous */
  description: string;
  /** Concrete advice on how to fix / what to replace it with */
  remediation: string;
  /** Confidence 0..1 of the detection */
  confidence: number;
  /** OWASP / CWE reference if applicable */
  references?: string[];
  /** Compliance framework mapping (enterprise) */
  compliance?: ComplianceTags;
  /** True if this finding was suppressed by a baseline rule (enterprise) */
  suppressed?: boolean;
}

export interface ScanStats {
  totalLines: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<Category, number>;
}

export interface ScanResult {
  findings: Finding[];
  stats: ScanStats;
  /** 0..100 risk score, higher = more dangerous */
  riskScore: number;
  /** Overall verdict label */
  verdict: "clean" | "suspicious" | "malicious" | "dangerous";
  /** Scan duration in milliseconds */
  durationMs: number;
  /** Hash of the scanned source (for history) */
  sourceHash: string;
  scannedAt: string;
}

export interface DetectionRule {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  description: string;
  remediation: string;
  references?: string[];
  /**
   * Run against the full source + pre-computed line array.
   * Return one Finding per match (line is auto-filled by the scanner).
   */
  match: (ctx: ScanContext) => RawMatch[];
}

export interface RawMatch {
  line: number;
  snippet: string;
  confidence?: number;
  extra?: string;
}

export interface ScanContext {
  /** Raw source code */
  source: string;
  /** Source split into lines (no trailing newline) */
  lines: string[];
  /** Set of imported module names detected (e.g. "os", "socket") */
  imports: Set<string>;
  /** Set of imported names (e.g. "system" from `from os import system`) */
  fromImports: Set<string>;
  /** True if the source looks minified / heavily obfuscated */
  obfuscationSignals: number;
}
