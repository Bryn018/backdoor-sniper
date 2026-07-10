import type { Category, Severity } from "@/lib/detector/types";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Tailwind classes (no indigo/blue per design rules). */
export const SEVERITY_BADGE: Record<
  Severity,
  {
    badge: string;
    dot: string;
    text: string;
    bar: string;
    soft: string;
    leftBorder: string;
  }
> = {
  critical: {
    badge:
      "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30",
    dot: "bg-red-500",
    text: "text-red-600 dark:text-red-400",
    bar: "bg-red-500",
    soft: "bg-red-500/10",
    leftBorder: "finding-border-critical",
  },
  high: {
    badge:
      "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30",
    dot: "bg-orange-500",
    text: "text-orange-600 dark:text-orange-400",
    bar: "bg-orange-500",
    soft: "bg-orange-500/10",
    leftBorder: "finding-border-high",
  },
  medium: {
    badge:
      "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30",
    dot: "bg-amber-500",
    text: "text-amber-600 dark:text-amber-400",
    bar: "bg-amber-500",
    soft: "bg-amber-500/10",
    leftBorder: "finding-border-medium",
  },
  low: {
    badge:
      "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
    dot: "bg-emerald-500",
    text: "text-emerald-600 dark:text-emerald-400",
    bar: "bg-emerald-500",
    soft: "bg-emerald-500/10",
    leftBorder: "finding-border-low",
  },
  info: {
    badge:
      "bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30",
    dot: "bg-slate-500",
    text: "text-slate-600 dark:text-slate-300",
    bar: "bg-slate-500",
    soft: "bg-slate-500/10",
    leftBorder: "finding-border-info",
  },
};

export const CATEGORY_LABEL: Record<Category, string> = {
  "code-execution": "Code Execution",
  "command-execution": "Command Execution",
  network: "Network",
  "reverse-shell": "Reverse Shell",
  obfuscation: "Obfuscation",
  deserialization: "Deserialization",
  "dangerous-import": "Dangerous Import",
  persistence: "Persistence",
  "credential-theft": "Credential Theft",
  "privilege-escalation": "Privilege Escalation",
  exfiltration: "Exfiltration",
  "anti-analysis": "Anti-Analysis",
  filesystem: "Filesystem",
  "hardcoded-secret": "Hardcoded Secret",
  "suspicious-pattern": "Suspicious Pattern",
};

export const CATEGORY_COLOR: Record<Category, string> = {
  "code-execution": "#ef4444",
  "command-execution": "#f97316",
  network: "#06b6d4",
  "reverse-shell": "#dc2626",
  obfuscation: "#a855f7",
  deserialization: "#ec4899",
  "dangerous-import": "#f59e0b",
  persistence: "#8b5cf6",
  "credential-theft": "#e11d48",
  "privilege-escalation": "#d946ef",
  exfiltration: "#0ea5e9",
  "anti-analysis": "#64748b",
  filesystem: "#78716c",
  "hardcoded-secret": "#f43f5e",
  "suspicious-pattern": "#6b7280",
};

export const VERDICT_META: Record<
  "clean" | "suspicious" | "malicious" | "dangerous",
  {
    label: string;
    color: string;
    ring: string;
    desc: string;
    glow: string;
    bgGrad: string;
    icon: string;
  }
> = {
  clean: {
    label: "Clean",
    color: "text-emerald-600 dark:text-emerald-400",
    ring: "ring-emerald-500/40",
    desc: "No backdoor patterns detected. Keep reviewing dependencies & inputs.",
    glow: "",
    bgGrad: "from-emerald-500/5 to-transparent",
    icon: "✓",
  },
  suspicious: {
    label: "Suspicious",
    color: "text-amber-600 dark:text-amber-400",
    ring: "ring-amber-500/40",
    desc: "Some risky patterns found. Manual review recommended before shipping.",
    glow: "verdict-glow-suspicious",
    bgGrad: "from-amber-500/5 to-transparent",
    icon: "⚠",
  },
  malicious: {
    label: "Malicious",
    color: "text-orange-600 dark:text-orange-400",
    ring: "ring-orange-500/40",
    desc: "Strong indicators of a backdoor. Treat as hostile until proven otherwise.",
    glow: "verdict-glow-malicious",
    bgGrad: "from-orange-500/5 to-transparent",
    icon: "⛔",
  },
  dangerous: {
    label: "Dangerous",
    color: "text-red-600 dark:text-red-400",
    ring: "ring-red-500/40",
    desc: "Critical backdoor confirmed. Do NOT execute. Quarantine & investigate.",
    glow: "verdict-glow-dangerous",
    bgGrad: "from-red-500/5 to-transparent",
    icon: "🚨",
  },
};

export function riskColor(score: number): string {
  if (score >= 70) return "text-red-500";
  if (score >= 40) return "text-orange-500";
  if (score >= 15) return "text-amber-500";
  if (score > 0) return "text-emerald-500";
  return "text-emerald-500";
}

export function riskStroke(score: number): string {
  if (score >= 70) return "#ef4444"; // red-500
  if (score >= 40) return "#f97316"; // orange-500
  if (score >= 15) return "#f59e0b"; // amber-500
  return "#10b981"; // emerald-500
}
