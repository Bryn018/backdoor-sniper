import type { ComplianceTags } from "./types";
import { RULES } from "./rules";
import { RULES_ENTERPRISE } from "./rules-enterprise";
import { RULES_SUPPLY_CHAIN } from "./rules-supply-chain";
import { RULES_AST } from "./rules-ast";

/**
 * Enterprise compliance framework mapping.
 *
 * Maps each detection rule id to the relevant controls across:
 *  - PCI-DSS 4.0 (payment card industry)
 *  - OWASP Top 10 2021 (web application security)
 *  - NIST SP 800-53 Rev. 5 (federal information systems)
 *  - ISO/IEC 27001:2022 (information security management)
 *
 * Entries are derived from the rule category by default, with explicit
 * overrides for the most security-critical rules.
 */

// Category-level defaults — applied to any rule not explicitly overridden.
const CATEGORY_DEFAULTS: Record<string, ComplianceTags> = {
  "code-execution": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "command-execution": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  network: {
    pciDss: ["1.2.1", "1.4.1"],
    owasp: ["A05:2021 - Security Misconfiguration"],
    nist: ["SC-7", "SC-8", "AC-4"],
    iso27001: ["A.13.1.1", "A.13.1.3"],
  },
  "reverse-shell": {
    pciDss: ["6.5.1", "10.2.4"],
    owasp: ["A03:2021 - Injection", "A09:2021 - Security Logging"],
    nist: ["SC-7", "SI-4", "AC-4"],
    iso27001: ["A.13.1.1", "A.12.4.1"],
  },
  obfuscation: {
    pciDss: ["6.2.4", "6.3.2"],
    owasp: ["A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-3", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.7"],
  },
  deserialization: {
    pciDss: ["6.5.1"],
    owasp: ["A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-7", "SC-18", "SI-3"],
    iso27001: ["A.8.12", "A.14.2.5"],
  },
  "dangerous-import": {
    pciDss: ["6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-7", "SC-18"],
    iso27001: ["A.14.2.5"],
  },
  persistence: {
    pciDss: ["6.5.1", "10.2.7"],
    owasp: ["A05:2021 - Security Misconfiguration"],
    nist: ["AC-2", "SI-4", "CM-7"],
    iso27001: ["A.9.4.4", "A.12.4.1"],
  },
  "credential-theft": {
    pciDss: ["3.3.1", "8.2.1", "8.3.1"],
    owasp: ["A02:2021 - Cryptographic Failures", "A07:2021 - Identification & Auth Failures"],
    nist: ["IA-5", "IA-2", "SC-12"],
    iso27001: ["A.5.17", "A.8.5", "A.9.4.2"],
  },
  "privilege-escalation": {
    pciDss: ["7.2.1", "7.2.2"],
    owasp: ["A01:2021 - Broken Access Control"],
    nist: ["AC-2", "AC-3", "AC-6"],
    iso27001: ["A.9.4.4", "A.9.4.1"],
  },
  exfiltration: {
    pciDss: ["3.4.1", "12.3.3"],
    owasp: ["A02:2021 - Cryptographic Failures"],
    nist: ["AC-4", "SC-8", "SI-4"],
    iso27001: ["A.13.1.1", "A.8.12"],
  },
  "anti-analysis": {
    pciDss: ["6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-3", "SI-7", "SC-18"],
    iso27001: ["A.8.7", "A.14.2.5"],
  },
  filesystem: {
    pciDss: ["6.5.1", "7.2.1"],
    owasp: ["A01:2021 - Broken Access Control"],
    nist: ["AC-3", "AC-6", "SI-3"],
    iso27001: ["A.8.7", "A.9.4.1"],
  },
  "hardcoded-secret": {
    pciDss: ["3.3.1", "8.3.1", "8.6.2"],
    owasp: ["A02:2021 - Cryptographic Failures", "A07:2021 - Identification & Auth Failures"],
    nist: ["IA-5", "SC-12", "SC-13"],
    iso27001: ["A.5.17", "A.8.5"],
  },
  "suspicious-pattern": {
    pciDss: ["6.2.4", "6.3.2"],
    owasp: ["A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-7", "SC-18"],
    iso27001: ["A.14.2.5"],
  },
  "supply-chain": {
    pciDss: ["6.3.2", "6.2.4", "12.6.2"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A06:2021 - Vulnerable Components"],
    nist: ["SR-3", "SR-5", "SR-11", "SI-7"],
    iso27001: ["A.5.21", "A.5.22", "A.8.30", "A.14.2.5"],
  },
};

// Explicit overrides for specific high-impact rules.
const RULE_OVERRIDES: Record<string, ComplianceTags> = {
  "PY-EXEC-001": {
    pciDss: ["6.5.1", "6.2.4", "6.3.3"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-3", "AC-4"],
    iso27001: ["A.14.2.5", "A.8.28", "A.12.4.1"],
  },
  "PY-EXEC-002": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-CRED-001": {
    pciDss: ["3.3.1", "8.2.1", "8.3.1", "8.6.2"],
    owasp: ["A02:2021 - Cryptographic Failures", "A07:2021 - Identification & Auth Failures"],
    nist: ["IA-5", "IA-2", "SC-12", "SC-13"],
    iso27001: ["A.5.17", "A.8.5", "A.9.4.2"],
  },
  "PY-DESER-001": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SC-18", "SI-3", "SI-10"],
    iso27001: ["A.8.12", "A.14.2.5", "A.8.7"],
  },
  // -----------------------------------------------------------------------
  // AST-aware rule overrides — indirect execution and data-flow to sinks.
  // Code-execution AST rules map to PCI 6.5.1, OWASP A03:2021, NIST SI-10,
  // ISO A.14.2.5 as specified.
  // -----------------------------------------------------------------------
  "PY-AST-001": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-002": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-003": {
    pciDss: ["6.2.4", "6.3.2"],
    owasp: ["A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-3", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.7"],
  },
  "PY-AST-004": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-005": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-006": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-007": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-008": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-009": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.7"],
  },
  "PY-AST-010": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-011": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-012": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28", "A.8.7"],
  },
  "PY-AST-013": {
    pciDss: ["6.5.1", "6.2.4", "10.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18", "SI-4"],
    iso27001: ["A.14.2.5", "A.8.28", "A.12.4.1"],
  },
  "PY-AST-014": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-015": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-016": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28", "A.8.12"],
  },
  "PY-AST-017": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  // PY-AST-018..028: decorator / metaclass / lambda / functional / conditional payload triggers
  "PY-AST-018": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-019": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-020": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-021": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-022": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-023": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-024": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-025": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-026": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-027": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-028": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection"],
    nist: ["SI-10", "SC-18", "SI-4"],
    iso27001: ["A.14.2.5", "A.8.28", "A.12.4.1"],
  },
  "PY-AST-032": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-029": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18", "SI-3"],
    iso27001: ["A.14.2.5", "A.8.28", "A.8.7"],
  },
  "PY-AST-030": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A08:2021 - Software & Data Integrity Failures", "A03:2021 - Injection"],
    nist: ["SI-7", "SI-10", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-031": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
  "PY-AST-033": {
    pciDss: ["6.5.1", "6.2.4"],
    owasp: ["A03:2021 - Injection", "A08:2021 - Software & Data Integrity Failures"],
    nist: ["SI-10", "SI-7", "SC-18"],
    iso27001: ["A.14.2.5", "A.8.28"],
  },
};

/**
 * Build the full compliance map by merging category defaults with rule overrides.
 * Exported so the scanner can attach compliance tags to each finding.
 */
export function buildComplianceMap(
  ruleMetas: { id: string; category: string }[]
): Record<string, ComplianceTags> {
  const map: Record<string, ComplianceTags> = {};
  for (const r of ruleMetas) {
    const base = CATEGORY_DEFAULTS[r.category];
    const override = RULE_OVERRIDES[r.id];
    map[r.id] = override ?? base ?? {};
  }
  return map;
}

/**
 * The compiled compliance map for all built-in + enterprise rules.
 * Built once at module load from the actual rule definitions.
 */
export const COMPLIANCE_MAP: Record<string, ComplianceTags> = buildComplianceMap(
  [...RULES, ...RULES_ENTERPRISE, ...RULES_SUPPLY_CHAIN, ...RULES_AST].map((r) => ({ id: r.id, category: r.category }))
);

/**
 * Lookup a compliance tag for a rule id at runtime. Falls back to an empty
 * object if the rule id is unknown (e.g. custom rules).
 */
export function lookupCompliance(ruleId: string): ComplianceTags | undefined {
  return COMPLIANCE_MAP[ruleId];
}

// Re-export the category defaults for use by the enterprise UI / reporting.
export { CATEGORY_DEFAULTS, RULE_OVERRIDES };
