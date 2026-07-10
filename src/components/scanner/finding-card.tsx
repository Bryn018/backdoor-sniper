"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  ExternalLink,
  Lightbulb,
  Copy,
  Check,
  Brain,
  Loader2,
  Code2,
  ArrowRight,
  ShieldOff,
  Wand2,
  Skull,
  AlertOctagon,
  AlertTriangle,
  Info,
  Bug,
} from "lucide-react";
import type { Finding, Severity } from "@/lib/detector/types";
import {
  CATEGORY_LABEL,
  SEVERITY_BADGE,
  SEVERITY_LABEL,
} from "@/lib/severity";
import { toast } from "sonner";

/** Severity-specific icons for visual scanning — skull for critical, etc. */
const SEVERITY_ICON: Record<Severity, typeof Skull> = {
  critical: Skull,
  high: AlertOctagon,
  medium: AlertTriangle,
  low: Info,
  info: Bug,
};

/** Generate a simple remediation diff: show the dangerous line → show the safe replacement. */
export function generateDiff(finding: Finding): { before: string; after: string } | null {
  const s = finding.snippet.trim();
  if (!s) return null;

  // Pattern-based safe replacement suggestions
  const replacements: Array<{ pattern: RegExp; replace: (m: RegExpMatchArray) => string }> = [
    // eval → ast.literal_eval
    { pattern: /\beval\s*\(/, replace: () => s.replace(/\beval\s*\(/, "ast.literal_eval(") },
    // exec → removed
    { pattern: /\bexec\s*\(/, replace: () => `# REMOVED: exec() is dangerous — use subprocess or functions instead\n# ${s}` },
    // os.system → subprocess.run
    { pattern: /\bos\.system\s*\(/, replace: () => s.replace(/\bos\.system\s*\(/, "subprocess.run(").replace(/$/, "  # use shell=True only if absolutely necessary") },
    // subprocess.call with shell=True → subprocess.run without shell
    { pattern: /subprocess\.(call|Popen)\s*\([^)]*shell\s*=\s*True/, replace: () => s.replace(/shell\s*=\s*True/, "shell=False  # avoid shell=True") },
    // pickle.loads → removed
    { pattern: /\bpickle\.loads?\s*\(/, replace: () => s.replace(/\bpickle\.loads?\s*\(/, "# DANGEROUS: pickle.loads(").replace(/$/, "  # use json or yaml instead") },
    // socket connect (reverse shell indicator)
    { pattern: /\.connect\s*\(\s*\(/, replace: () => `# REMOVED: outbound socket connection to unknown host\n# ${s}` },
    // os.dup2 → removed
    { pattern: /\bos\.dup2\s*\(/, replace: () => `# REMOVED: file descriptor redirect (used in reverse shells)\n# ${s}` },
    // base64.b64decode + eval/exec
    { pattern: /base64\.b64decode/, replace: () => `# DANGEROUS: base64-decoded content being executed\n# ${s}` },
    // __import__ → import
    { pattern: /__import__\s*\(/, replace: () => s.replace(/__import__\s*\(\s*['"](\w+)['"]\s*\)/, "import $1") },
    // compile + eval → removed
    { pattern: /\bcompile\s*\(/, replace: () => `# REMOVED: dynamic code compilation\n# ${s}` },
    // marshal.loads → removed
    { pattern: /\bmarshal\.loads?\s*\(/, replace: () => `# DANGEROUS: marshal deserialization\n# ${s}` },
  ];

  for (const { pattern, replace } of replacements) {
    if (pattern.test(s)) {
      const after = replace(s.match(pattern)!);
      if (after !== s) return { before: s, after };
    }
  }

  // Generic fallback: add a comment
  return {
    before: s,
    after: `# REVIEW: ${finding.remediation.split(".")[0]}\n${s}`,
  };
}

export interface ApplyFixPayload {
  line: number;
  original: string;
  replacement: string;
}

interface FindingCardProps {
  finding: Finding;
  index: number;
  onJump?: (line: number) => void;
  defaultOpen?: boolean;
  suppressed?: boolean;
  onToggleSuppress?: () => void;
  onApplyFix?: (payload: ApplyFixPayload) => void;
  /** Full source lines, used to render context around the finding */
  sourceLines?: string[];
}

/** Build the URL for a CWE reference (e.g. "CWE-912" → https://cwe.mitre.org/data/definitions/912.html). */
function cweUrl(ref: string): string | null {
  const m = ref.match(/CWE[-\s]?(\d+)/i);
  if (!m) return null;
  return `https://cwe.mitre.org/data/definitions/${m[1]}.html`;
}

/** Build the URL for an OWASP reference. */
function owaspUrl(ref: string): string | null {
  const m = ref.match(/OWASP\s+([A-Z0-9:]+)/i);
  if (!m) return null;
  // Map known OWASP Top 10 codes to their wiki page
  const code = m[1].replace(/:/g, "_");
  return `https://owasp.org/www-community/controls/${code}`;
}

function refUrl(ref: string): string | null {
  if (/^https?:\/\//i.test(ref)) return ref;
  return cweUrl(ref) ?? owaspUrl(ref);
}

export function FindingCard({
  finding,
  index,
  onJump,
  defaultOpen,
  suppressed = false,
  onToggleSuppress,
  onApplyFix,
  sourceLines,
}: FindingCardProps) {
  const [open, setOpen] = useState(defaultOpen ?? index < 2);
  const [copied, setCopied] = useState(false);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [showDiff, setShowDiff] = useState(false);
  const s = SEVERITY_BADGE[finding.severity];
  const SeverityIcon = SEVERITY_ICON[finding.severity];
  const isCritical = finding.severity === "critical";

  const copySnippet = () => {
    navigator.clipboard.writeText(finding.snippet).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const getExplanation = async () => {
    setExplainLoading(true);
    try {
      const res = await fetch("/api/ai-analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: "single",
          findings: [finding],
        }),
      });
      if (!res.ok) throw new Error("AI explain failed");
      const data = await res.json();
      setExplanation(data.summary);
    } catch {
      toast.error("AI explanation unavailable — try again later");
    } finally {
      setExplainLoading(false);
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: suppressed ? 0.4 : 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.03, 0.3) }}
      className={`relative overflow-hidden rounded-lg border ${s.badge} ${s.leftBorder} bg-card/60 backdrop-blur finding-hover-lift card-glow card-glow-${finding.severity} ${isCritical && !suppressed ? "critical-pulse-border" : ""} ${suppressed ? "opacity-40" : ""}`}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-accent/30 transition-colors"
      >
        <span
          className={`mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md ${s.badge}`}
          title={`${SEVERITY_LABEL[finding.severity]} severity`}
        >
          <SeverityIcon className="h-3.5 w-3.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${s.badge}`}
            >
              {SEVERITY_LABEL[finding.severity]}
            </span>
            <span className="font-mono text-[10px] text-muted-foreground">
              {finding.ruleId}
            </span>
            <span className="text-[10px] text-muted-foreground">
              · {CATEGORY_LABEL[finding.category]}
            </span>
            <span className="ml-auto inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              line {finding.line}
            </span>
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <p
              className={`text-sm font-medium text-foreground ${suppressed ? "line-through decoration-muted-foreground" : ""}`}
            >
              {finding.title}
            </p>
            {suppressed && (
              <span className="inline-flex items-center rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-amber-600 dark:text-amber-400">
                Suppressed
              </span>
            )}
          </div>
        </div>
        {open ? (
          <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />
        )}
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-border/60"
          >
            <div className="space-y-3 px-4 py-3">
              {/* Code snippet with surrounding context */}
              <div className="code-snippet group relative">
                {(() => {
                  // Build 1-line above + line + 1-line below context
                  const lineIdx = finding.line - 1;
                  const hasContext =
                    sourceLines &&
                    sourceLines.length > 0 &&
                    lineIdx >= 0 &&
                    lineIdx < sourceLines.length;
                  const prevLine = hasContext ? sourceLines![lineIdx - 1] : null;
                  const nextLine = hasContext ? sourceLines![lineIdx + 1] : null;
                  const content = (
                    <>
                      {prevLine !== null && prevLine !== undefined && (
                        <div className="flex items-center gap-2 px-3 py-1 font-mono text-[11px] text-muted-foreground/50">
                          <span className="shrink-0 select-none">
                            {String(finding.line - 1).padStart(3, " ")}
                          </span>
                          <span className="min-w-0 flex-1 truncate">
                            {prevLine || "\u00a0"}
                          </span>
                        </div>
                      )}
                      <div
                        className={`flex items-center gap-2 px-3 py-1.5 font-mono text-xs ${
                          onJump ? "cursor-pointer hover:bg-muted/40" : ""
                        }`}
                        onClick={onJump ? () => onJump(finding.line) : undefined}
                      >
                        <span className="shrink-0 select-none font-bold text-red-500 dark:text-red-400">
                          {String(finding.line).padStart(3, " ")}
                        </span>
                        <span className="min-w-0 flex-1 truncate bg-red-500/10 px-1 -mx-1 rounded text-foreground group-hover:text-foreground">
                          {finding.snippet || "(empty line)"}
                        </span>
                        {onJump && (
                          <ExternalLink className="h-3 w-3 shrink-0 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                        )}
                      </div>
                      {nextLine !== null && nextLine !== undefined && (
                        <div className="flex items-center gap-2 px-3 py-1 font-mono text-[11px] text-muted-foreground/50">
                          <span className="shrink-0 select-none">
                            {String(finding.line + 1).padStart(3, " ")}
                          </span>
                          <span className="min-w-0 flex-1 truncate">
                            {nextLine || "\u00a0"}
                          </span>
                        </div>
                      )}
                    </>
                  );
                  return (
                    <div className="rounded-[5px] border border-border/60 bg-muted/20">
                      {content}
                    </div>
                  );
                })()}
                <button
                  onClick={copySnippet}
                  className="absolute right-2 top-2 rounded p-1 text-muted-foreground opacity-0 hover:bg-muted group-hover:opacity-100 transition-opacity"
                  title="Copy snippet"
                >
                  {copied ? (
                    <Check className="h-3 w-3 text-emerald-500" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>
              </div>

              {/* Why dangerous */}
              <div>
                <h5 className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  <ShieldAlert className="h-3.5 w-3.5 text-red-500/70" />
                  Why this is dangerous
                </h5>
                <p className="text-sm leading-relaxed text-foreground/80">
                  {finding.description}
                </p>
              </div>

              {/* How to fix */}
              <div>
                <h5 className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  <Lightbulb className="h-3.5 w-3.5 text-emerald-500/70" />
                  How to fix
                </h5>
                <p className="text-sm leading-relaxed text-foreground/80">
                  {finding.remediation}
                </p>
              </div>

              {/* Remediation Diff View */}
              <div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setShowDiff((d) => !d)}
                    className="flex items-center gap-1.5 text-[11px] font-medium text-emerald-600 hover:text-emerald-700 dark:text-emerald-400 transition-colors"
                  >
                    <Code2 className="h-3.5 w-3.5" />
                    {showDiff ? "Hide suggested fix" : "Show suggested fix"}
                  </button>
                  {onApplyFix && generateDiff(finding) && (
                    <button
                      onClick={() => {
                        const diff = generateDiff(finding);
                        if (diff) {
                          onApplyFix({
                            line: finding.line,
                            original: diff.before,
                            replacement: diff.after,
                          });
                        }
                      }}
                      className="flex items-center gap-1.5 text-[11px] font-medium text-amber-600 hover:text-amber-700 dark:text-amber-400 transition-colors"
                      title="Apply the suggested fix to the code editor"
                    >
                      <Wand2 className="h-3.5 w-3.5" />
                      Apply fix
                    </button>
                  )}
                </div>
                <AnimatePresence>
                  {showDiff && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="mt-2 overflow-hidden"
                    >
                      {(() => {
                        const diff = generateDiff(finding);
                        if (!diff) return null;
                        return (
                          <div className="rounded-lg border border-border overflow-hidden">
                            {/* Before */}
                            <div className="border-b border-border">
                              <div className="flex items-center gap-1.5 bg-red-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-red-600 dark:text-red-400">
                                <span className="inline-block h-1.5 w-1.5 rounded-full bg-red-500" />
                                Dangerous code
                              </div>
                              <pre className="overflow-x-auto bg-red-500/5 px-3 py-2 font-mono text-xs text-foreground/80">
                                {diff.before}
                              </pre>
                            </div>
                            {/* Arrow */}
                            <div className="flex items-center justify-center bg-muted/30 py-1">
                              <ArrowRight className="h-3.5 w-3.5 rotate-90 text-muted-foreground" />
                            </div>
                            {/* After */}
                            <div>
                              <div className="flex items-center gap-1.5 bg-emerald-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-emerald-600 dark:text-emerald-400">
                                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                                Safer alternative
                              </div>
                              <pre className="overflow-x-auto bg-emerald-500/5 px-3 py-2 font-mono text-xs text-foreground/80 whitespace-pre-wrap">
                                {diff.after}
                              </pre>
                            </div>
                          </div>
                        );
                      })()}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* AI explanation (lazy loaded) */}
              <AnimatePresence>
                {explanation && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-2.5"
                  >
                    <h5 className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-emerald-600 dark:text-emerald-400">
                      <Brain className="h-3.5 w-3.5" />
                      Plain-language explanation
                    </h5>
                    <p className="text-sm leading-relaxed text-foreground/80">
                      {explanation}
                    </p>
                    <button
                      onClick={() => setExplanation(null)}
                      className="mt-1.5 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Dismiss
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Confidence + actions */}
              <div className="flex flex-wrap items-center gap-2 pt-1 text-[10px] text-muted-foreground">
                <span>Confidence</span>
                <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
                  <div
                    className={`h-full rounded-full ${s.bar} transition-all duration-700`}
                    style={{
                      width: `${Math.round(finding.confidence * 100)}%`,
                    }}
                  />
                </div>
                <span className="font-mono">
                  {Math.round(finding.confidence * 100)}%
                </span>

                {/* Suppress / Unsuppress button */}
                {onToggleSuppress && (
                  <button
                    onClick={onToggleSuppress}
                    className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium transition-colors ${
                      suppressed
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 hover:bg-emerald-500/20 dark:text-emerald-400"
                        : "border-amber-500/30 bg-amber-500/10 text-amber-600 hover:bg-amber-500/20 dark:text-amber-400"
                    }`}
                    title={suppressed ? "Unsuppress this finding" : "Mark as false positive / suppress"}
                  >
                    <ShieldOff className="h-3 w-3" />
                    {suppressed ? "Unsuppress" : "Suppress"}
                  </button>
                )}

                {/* AI explain button */}
                {!explanation && (
                  <button
                    onClick={getExplanation}
                    disabled={explainLoading}
                    className="ml-auto inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-600 hover:bg-emerald-500/20 transition-colors disabled:opacity-50 dark:text-emerald-400"
                    title="Get a plain-language AI explanation of this finding"
                  >
                    {explainLoading ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <Brain className="h-3 w-3" />
                    )}
                    {explainLoading ? "Explaining…" : "AI explain"}
                  </button>
                )}

                {finding.references && finding.references.length > 0 && (
                  <span className="flex items-center gap-1">
                    {finding.references.map((r) => {
                      const url = refUrl(r);
                      return url ? (
                        <a
                          key={r}
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors group/ref"
                          title={`Open ${r} reference in new tab`}
                        >
                          {r}
                          <ExternalLink className="h-2.5 w-2.5 opacity-50 group-hover/ref:opacity-100" />
                        </a>
                      ) : (
                        <span
                          key={r}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]"
                        >
                          {r}
                        </span>
                      );
                    })}
                  </span>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
