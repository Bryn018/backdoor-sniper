/**
 * Detection Profiles — curated bundles of rule IDs to enable/disable for
 * specific auditing contexts. Switching a profile sets the disabled set to
 * match the profile's `disabledRuleIds` list.
 *
 * Built-in rule IDs follow the PY-<CAT>-NNN convention (see rules.ts).
 * Any ID not in the rule set is silently ignored by the scanner, so a
 * profile is always safe to apply.
 */

export interface DetectionProfile {
  id: string;
  name: string;
  description: string;
  /** Rule IDs to DISABLE when this profile is active. All others stay enabled. */
  disabledRuleIds: string[];
  /** Accent color used in the UI badge. */
  accent: "emerald" | "amber" | "orange" | "red" | "slate" | "purple";
  /** Lucide icon name (mapped on the frontend). */
  icon: string;
}

export const DETECTION_PROFILES: DetectionProfile[] = [
  {
    id: "all",
    name: "Full Arsenal",
    description:
      "All 79 rules enabled. Maximum coverage for unknown / untrusted code.",
    disabledRuleIds: [],
    accent: "emerald",
    icon: "ShieldCheck",
  },
  {
    id: "web-framework",
    name: "Web Framework Audit",
    description:
      "Focused on Flask/Django/FastAPI code review. Disables low-signal native-shell & keylogger-style rules so findings stay actionable in a web context.",
    disabledRuleIds: [
      "PY-PERS-002", // registry run key persistence
      "PY-PERS-003", // systemd service
      "PY-ANTI-003", // VM/sandbox detection
      "PY-ANTI-001", // sleep-based VM evasion
      "PY-ANTI-002", // process enumeration
    ],
    accent: "amber",
    icon: "Globe",
  },
  {
    id: "script-audit",
    name: "Script Audit (Lite)",
    description:
      "Lightweight rule set for one-off scripts & CLI tools. Focuses on code execution, command injection, and credential theft; skips low-severity pattern noise.",
    disabledRuleIds: [
      "PY-SUS-001",
      "PY-SUS-002",
      "PY-SUS-003",
      "PY-SUS-004",
      "PY-IMP-002",
      "PY-IMP-003",
      "PY-FS-003",
      "PY-FS-004",
      "PY-ANTI-001",
      "PY-ANTI-002",
    ],
    accent: "emerald",
    icon: "FileCode2",
  },
  {
    id: "supply-chain",
    name: "Supply Chain Review",
    description:
      "Optimised for reviewing third-party packages before install. Emphasises obfuscation, dynamic loading, network exfil, and dependency confusion rules; relaxes noisy developer primitives.",
    disabledRuleIds: [
      "PY-EXEC-001", // eval() — extremely common in legit libs
      "PY-EXEC-002", // exec()
      "PY-EXEC-003", // compile()
      "PY-CMD-001", // os.system — commonly used
      "PY-NET-003", // generic socket connect
      "PY-FS-001", // open() write
    ],
    accent: "purple",
    icon: "PackageSearch",
  },
  {
    id: "critical-only",
    name: "Critical Only",
    description:
      "Only fires on critical-severity findings: confirmed reverse shells, RCE primitives, shellcode runners. Use for fast triage of large codebases.",
    disabledRuleIds: [
      // Disable every high/medium/low/info rule; keep only critical ones.
      "PY-NET-002",
      "PY-CMD-002",
      "PY-CMD-003",
      "PY-CMD-004",
      "PY-CMD-005",
      "PY-OBF-001",
      "PY-OBF-002",
      "PY-OBF-003",
      "PY-OBF-004",
      "PY-DESER-002",
      "PY-IMP-001",
      "PY-IMP-002",
      "PY-IMP-003",
      "PY-PERS-001",
      "PY-PERS-002",
      "PY-PERS-003",
      "PY-PERS-004",
      "PY-CRED-002",
      "PY-CRED-003",
      "PY-PRIV-002",
      "PY-EXF-001",
      "PY-EXF-002",
      "PY-EXF-003",
      "PY-ANTI-001",
      "PY-ANTI-002",
      "PY-ANTI-003",
      "PY-FS-001",
      "PY-FS-002",
      "PY-FS-003",
      "PY-FS-004",
      "PY-FS-005",
      "PY-SEC-001",
      "PY-SEC-002",
      "PY-SEC-003",
      "PY-SEC-004",
      "PY-SUS-001",
      "PY-SUS-002",
      "PY-SUS-003",
      "PY-SUS-004",
      "PY-SUS-005",
      "PY-SUS-006",
      "PY-SUS-007",
      "PY-SUS-008",
      "PY-SUS-009",
      "PY-SUS-010",
      "PY-SUS-011",
      "PY-SUS-012",
      "PY-SUS-013",
      "PY-SUS-014",
      "PY-SUS-015",
      "PY-SUS-016",
      "PY-SUS-017",
      "PY-SUS-018",
      "PY-SUS-019",
      "PY-SUS-020",
      "PY-SUS-021",
      "PY-SUS-022",
      "PY-SUS-023",
      "PY-SUS-024",
    ],
    accent: "red",
    icon: "Flame",
  },
  {
    id: "cicd",
    name: "CI/CD Gate",
    description:
      "Strict policy for build pipelines: surfaces high/critical findings with minimal noise. Disables info/low severity rules to keep signal-to-noise high.",
    disabledRuleIds: [
      "PY-SUS-001",
      "PY-SUS-002",
      "PY-IMP-003",
      "PY-FS-003",
      "PY-FS-004",
      "PY-ANTI-001",
      "PY-ANTI-002",
      "PY-OBF-004",
    ],
    accent: "orange",
    icon: "GitBranch",
  },
];

/** Lookup a profile by id (defaults to "all"). */
export function getProfile(id: string | null | undefined): DetectionProfile {
  if (!id) return DETECTION_PROFILES[0];
  return DETECTION_PROFILES.find((p) => p.id === id) ?? DETECTION_PROFILES[0];
}
