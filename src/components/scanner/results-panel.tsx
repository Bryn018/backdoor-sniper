"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  ShieldAlert,
  ScanLine,
  ListFilter,
  FileWarning,
  Clock,
  Download,
  FileJson,
  FileText,
  FileDown,
  Copy,
  ChevronsUpDown,
  ChevronsDown,
  Brain,
  Loader2,
  EyeOff,
  Eye,
  Share2,
  GitCompare,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  X,
  Wand2,
  Skull,
  AlertOctagon,
  AlertTriangle,
  Info,
  Bug,
} from "lucide-react";
import type { ScanResult, Category } from "@/lib/detector/types";
import { RULE_COUNT } from "@/lib/detector/rules";
import { RiskGauge } from "./risk-gauge";
import { SeverityBreakdown } from "./severity-breakdown";
import { FindingCard, type ApplyFixPayload, generateDiff } from "./finding-card";
import { ThreatRadar } from "./threat-radar";
import {
  VERDICT_META,
  CATEGORY_LABEL,
  SEVERITY_LABEL,
  CATEGORY_COLOR,
} from "@/lib/severity";
import { scanResultToMarkdown, scanResultToCompactSummary } from "@/lib/markdown-export";
import type { Severity } from "@/lib/detector/types";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface ResultsPanelProps {
  result: ScanResult | null;
  scanning: boolean;
  error: string | null;
  onJump: (line: number) => void;
  onApplyFix?: (payload: ApplyFixPayload) => void;
  onApplyAllFixes?: (payloads: ApplyFixPayload[]) => void;
  source?: string;
}

export function ResultsPanel({
  result,
  scanning,
  error,
  onJump,
  onApplyFix,
  onApplyAllFixes,
  source,
}: ResultsPanelProps) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<Category | "all">("all");
  const [allExpanded, setAllExpanded] = useState<boolean | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [suppressedKeys, setSuppressedKeys] = useState<Set<string>>(new Set());
  const [showSuppressed, setShowSuppressed] = useState(true);
  const [compareOpen, setCompareOpen] = useState(false);
  const [previousScan, setPreviousScan] = useState<ScanResult | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  // Pre-compute source lines once for finding card context previews
  const sourceLines = useMemo(
    () => (source ? source.replace(/\r\n/g, "\n").split("\n") : undefined),
    [source]
  );

  const getAiAnalysis = useCallback(async () => {
    if (!result) return;
    setAiLoading(true);
    try {
      const res = await fetch("/api/ai-analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: result.findings,
          verdict: result.verdict,
          riskScore: result.riskScore,
        }),
      });
      if (!res.ok) throw new Error("AI analysis failed");
      const data = await res.json();
      setAiSummary(data.summary);
    } catch {
      toast.error("AI analysis unavailable — try again later");
    } finally {
      setAiLoading(false);
    }
  }, [result]);

  const loadPreviousScan = useCallback(async () => {
    if (!result) return;
    setCompareLoading(true);
    try {
      const res = await fetch("/api/history?limit=50");
      const data = await res.json();
      const records = data.records ?? [];
      // Find the most recent scan that isn't the current one
      const prev = records.find(
        (r: { id: string; sourceHash: string }) => r.sourceHash !== result.sourceHash
      );
      if (!prev) {
        toast.info("No previous scan to compare with");
        setCompareLoading(false);
        return;
      }
      // Fetch full details
      const detailRes = await fetch(`/api/history/${prev.id}`);
      if (!detailRes.ok) throw new Error("Failed to fetch previous scan");
      const detail = await detailRes.json();
      const restored: ScanResult = {
        findings: detail.findings ?? [],
        stats: {
          totalLines: detail.totalLines ?? 0,
          totalFindings: (detail.findings ?? []).length,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {},
        },
        riskScore: detail.riskScore ?? 0,
        verdict: detail.verdict ?? "clean",
        durationMs: 0,
        sourceHash: detail.sourceHash ?? "",
        scannedAt: detail.createdAt ?? new Date().toISOString(),
      };
      for (const f of restored.findings) {
        restored.stats.bySeverity[f.severity]++;
        restored.stats.byCategory[f.category] =
          (restored.stats.byCategory[f.category] ?? 0) + 1;
      }
      setPreviousScan(restored);
      setCompareOpen(true);
    } catch {
      toast.error("Could not load previous scan for comparison");
    } finally {
      setCompareLoading(false);
    }
  }, [result]);

  if (scanning) {
    return <LoadingState />;
  }
  if (error) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-red-500/10">
          <ShieldAlert className="h-7 w-7 text-red-500" />
        </div>
        <p className="text-sm font-medium text-foreground">Scan failed</p>
        <p className="max-w-xs text-xs text-muted-foreground">{error}</p>
      </div>
    );
  }
  if (!result) {
    return <EmptyState />;
  }

  // Compute adjusted risk score excluding suppressed findings
  const SEVERITY_WEIGHT: Record<Severity, number> = {
    critical: 25,
    high: 14,
    medium: 7,
    low: 3,
    info: 1,
  };

  const nonSuppressedFindings = result.findings.filter(
    (f) => !suppressedKeys.has(`${f.ruleId}:${f.line}`)
  );

  // Compute the "obfuscation bonus" from original score vs pure findings score
  const originalFindingsScore = result.findings.reduce(
    (sum, f) => sum + SEVERITY_WEIGHT[f.severity] * Math.max(0.4, f.confidence),
    0
  );
  const obfuscationBonus = Math.max(0, result.riskScore - originalFindingsScore);

  const adjustedFindingsScore = nonSuppressedFindings.reduce(
    (sum, f) => sum + SEVERITY_WEIGHT[f.severity] * Math.max(0.4, f.confidence),
    0
  );
  const hasCriticalExec = nonSuppressedFindings.some(
    (f) =>
      f.severity === "critical" &&
      (f.category === "code-execution" ||
        f.category === "reverse-shell" ||
        f.category === "deserialization")
  );
  let adjustedRiskScore = Math.round(adjustedFindingsScore + obfuscationBonus);
  if (hasCriticalExec) adjustedRiskScore = Math.max(adjustedRiskScore, 78);
  adjustedRiskScore = Math.min(100, Math.max(0, adjustedRiskScore));

  const adjustedVerdict: ScanResult["verdict"] =
    adjustedRiskScore >= 70
      ? "dangerous"
      : nonSuppressedFindings.some((f) => f.severity === "critical") || adjustedRiskScore >= 40
        ? "malicious"
        : nonSuppressedFindings.length > 0
          ? "suspicious"
          : "clean";

  const displayRiskScore = suppressedKeys.size > 0 ? adjustedRiskScore : result.riskScore;
  const displayVerdict = suppressedKeys.size > 0 ? adjustedVerdict : result.verdict;
  const displayV = VERDICT_META[displayVerdict];

  const toggleSuppress = (key: string) => {
    setSuppressedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // Apply both severity and category filters
  let filtered = result.findings;
  // Filter out suppressed findings if toggle is off
  if (!showSuppressed) {
    filtered = filtered.filter((f) => !suppressedKeys.has(`${f.ruleId}:${f.line}`));
  }
  if (filter !== "all") filtered = filtered.filter((f) => f.severity === filter);
  if (categoryFilter !== "all")
    filtered = filtered.filter((f) => f.category === categoryFilter);

  const topCategories = Object.entries(result.stats.byCategory)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Active categories for filter dropdown
  const activeCategories = Object.entries(result.stats.byCategory)
    .filter(([, n]) => n > 0)
    .map(([cat]) => cat as Category);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `backdoorsniper-report-${result.sourceHash}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Report exported as JSON");
  };

  const exportMarkdown = () => {
    const md = scanResultToMarkdown(result);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `backdoorsniper-report-${result.sourceHash}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Report exported as Markdown");
  };

  const copySummary = () => {
    const md = scanResultToMarkdown(result);
    navigator.clipboard.writeText(md).then(() => {
      toast.success("Markdown report copied to clipboard");
    });
  };

  const shareCompactSummary = () => {
    const summary = scanResultToCompactSummary(result);
    navigator.clipboard.writeText(summary).then(() => {
      toast.success("Compact summary copied — paste in Slack/Teams/email");
    });
  };

  const exportPdf = async () => {
    if (!result) return;
    setPdfLoading(true);
    try {
      const res = await fetch("/api/export-pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ result }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || "PDF export failed");
      }
      const data = await res.json();
      // Trigger download via the GET endpoint
      const a = document.createElement("a");
      a.href = `/api/export-pdf/download?file=${encodeURIComponent(data.filename)}`;
      a.download = data.filename;
      a.click();
      toast.success("PDF report downloaded");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "PDF export failed";
      toast.error(msg);
    } finally {
      setPdfLoading(false);
    }
  };

  const exportSarif = async () => {
    if (!result) return;
    try {
      const res = await fetch("/api/export-sarif", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ result }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || "SARIF export failed");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `backdoorsniper-${result.sourceHash}.sarif`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("SARIF report downloaded", {
        description: "Import into GitHub Code Scanning or Azure DevOps",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "SARIF export failed";
      toast.error(msg);
    }
  };

  const toggleAll = () => {
    setAllExpanded((prev) => !prev);
  };

  // Threat bar gradient colors based on verdict
  const THREAT_BAR_GRADIENT: Record<string, string> = {
    clean: "from-emerald-400 to-emerald-500",
    suspicious: "from-amber-400 to-amber-500",
    malicious: "from-orange-400 to-orange-500",
    dangerous: "from-red-500 to-red-600",
  };

  return (
    <div className="relative flex h-full flex-col overflow-hidden">
      {/* Threat level indicator bar */}
      <motion.div
        className={`h-[3px] shrink-0 bg-gradient-to-r ${THREAT_BAR_GRADIENT[displayVerdict] ?? "from-emerald-400 to-emerald-500"}`}
        initial={{ width: 0 }}
        animate={{ width: "100%" }}
        transition={{ duration: 0.8, ease: [0.4, 0, 0.2, 1] }}
      />

      {/* Header / verdict */}
      <div className={`border-b border-border bg-gradient-to-r ${displayV.bgGrad} p-4`}>
        <div className="flex items-center gap-4">
          <RiskGauge
            score={displayRiskScore}
            size={110}
            verdict={displayVerdict}
          />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span
                className={`text-2xl font-bold ${displayV.color} ${displayV.glow}`}
              >
                {displayV.label}
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                {nonSuppressedFindings.length}/{result.stats.totalFindings} findings
              </span>
              {suppressedKeys.size > 0 && (
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[9px] font-bold text-amber-600 dark:text-amber-400">
                  {suppressedKeys.size} suppressed
                </span>
              )}
            </div>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {displayV.desc}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {result.durationMs}ms
              </span>
              <span className="flex items-center gap-1">
                <ScanLine className="h-3 w-3" />
                {result.stats.totalLines} lines
              </span>
              <span>hash {result.sourceHash}</span>
            </div>
          </div>
        </div>

        {/* Severity breakdown + Radar side by side */}
        <div className="mt-4 flex gap-4">
          <div className="min-w-0 flex-1">
            <SeverityBreakdown stats={result.stats} />
          </div>
          {result.stats.totalFindings > 0 && (
            <div className="hidden sm:block">
              <ThreatRadar stats={result.stats} size={130} />
            </div>
          )}
        </div>

        {/* Top categories */}
        {topCategories.length > 0 && (
          <div className="mt-4">
            <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Top threat categories
            </p>
            <div className="flex flex-wrap gap-1.5">
              {topCategories.map(([cat, n]) => (
                <span
                  key={cat}
                  className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-2.5 py-0.5 text-[10px] text-foreground/80"
                >
                  <span
                    className="inline-block h-1.5 w-1.5 rounded-full"
                    style={{
                      backgroundColor:
                        CATEGORY_COLOR[cat as keyof typeof CATEGORY_COLOR] ??
                        "#6b7280",
                    }}
                  />
                  {CATEGORY_LABEL[cat as keyof typeof CATEGORY_LABEL]}
                  <span className="font-mono text-muted-foreground">{n}</span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* AI analysis section */}
      {result.stats.totalFindings > 0 && (
        <div className="border-b border-border">
          {aiSummary ? (
            <div className="space-y-1 bg-muted/20 px-4 py-3">
              <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                <Brain className="h-3.5 w-3.5 text-emerald-500" />
                AI Analysis
              </div>
              <p className="text-xs leading-relaxed text-foreground/80">
                {aiSummary}
              </p>
              <button
                onClick={() => setAiSummary(null)}
                className="text-[10px] text-muted-foreground hover:text-foreground transition-colors"
              >
                Dismiss
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 px-4 py-2">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 gap-1.5 text-[11px] text-emerald-600 hover:text-emerald-700 dark:text-emerald-400"
                onClick={getAiAnalysis}
                disabled={aiLoading}
              >
                {aiLoading ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Brain className="h-3 w-3" />
                )}
                {aiLoading ? "Analyzing…" : "Get AI analysis"}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 gap-1.5 text-[11px] text-muted-foreground hover:text-foreground"
                onClick={loadPreviousScan}
                disabled={compareLoading}
                title="Compare with the most recent previous scan in history"
              >
                {compareLoading ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <GitCompare className="h-3 w-3" />
                )}
                {compareLoading ? "Loading…" : "Compare"}
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Findings list */}
      <div className="flex min-h-0 flex-1 flex-col">
        <div className="sticky top-0 z-10 border-b border-border bg-card/95 px-4 py-2 backdrop-blur">
          <div className="flex items-center justify-between gap-2">
            <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <FileWarning className="h-3.5 w-3.5" />
              Findings
              <span className="font-mono text-foreground/60">
                ({filtered.length})
              </span>
            </h4>
            <div className="flex items-center gap-1.5">
              {/* Show/hide suppressed toggle */}
              {suppressedKeys.size > 0 && (
                <Button
                  variant="ghost"
                  size="icon"
                  className={`h-7 w-7 ${showSuppressed ? "text-amber-500" : "text-muted-foreground"}`}
                  onClick={() => setShowSuppressed((s) => !s)}
                  title={showSuppressed ? "Hide suppressed findings" : "Show suppressed findings"}
                >
                  {showSuppressed ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                </Button>
              )}

              {/* Apply All Fixes button */}
              {onApplyAllFixes && result.findings.some((f) => generateDiff(f)) && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1.5 text-[10px] text-amber-600 hover:text-amber-700 dark:text-amber-400"
                  onClick={() => {
                    const payloads: ApplyFixPayload[] = [];
                    for (const f of result.findings) {
                      if (suppressedKeys.has(`${f.ruleId}:${f.line}`)) continue;
                      const diff = generateDiff(f);
                      if (diff) {
                        payloads.push({
                          line: f.line,
                          original: diff.before,
                          replacement: diff.after,
                        });
                      }
                    }
                    if (payloads.length === 0) {
                      toast.info("No auto-fixable findings available");
                    } else {
                      onApplyAllFixes(payloads);
                      toast.success(`Applied ${payloads.length} fix${payloads.length === 1 ? "" : "es"} — re-scanning…`);
                    }
                  }}
                  title="Apply all available remediation fixes to the editor"
                >
                  <Wand2 className="h-3 w-3" />
                  Fix all
                  <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-bold">
                    {result.findings.filter((f) => !suppressedKeys.has(`${f.ruleId}:${f.line}`) && generateDiff(f)).length}
                  </span>
                </Button>
              )}

              {/* Category filter */}
              {activeCategories.length > 1 && (
                <Select
                  value={categoryFilter}
                  onValueChange={(v) =>
                    setCategoryFilter(v as Category | "all")
                  }
                >
                  <SelectTrigger className="h-7 w-[130px] text-[10px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all" className="text-[10px]">
                      All categories
                    </SelectItem>
                    {activeCategories.map((cat) => (
                      <SelectItem
                        key={cat}
                        value={cat}
                        className="text-[10px]"
                      >
                        {CATEGORY_LABEL[cat]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}

              {/* Expand/Collapse all */}
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={toggleAll}
                title={allExpanded ? "Collapse all" : "Expand all"}
              >
                {allExpanded ? (
                  <ChevronsUpDown className="h-3 w-3" />
                ) : (
                  <ChevronsDown className="h-3 w-3" />
                )}
              </Button>

              {/* Export menu */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    title="Export report"
                  >
                    <Download className="h-3 w-3" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <DropdownMenuItem onClick={exportJson} className="gap-2 text-xs">
                    <FileJson className="h-3.5 w-3.5 text-emerald-500" />
                    Export as JSON
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={exportMarkdown} className="gap-2 text-xs">
                    <FileText className="h-3.5 w-3.5 text-emerald-500" />
                    Export as Markdown
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={copySummary} className="gap-2 text-xs">
                    <Copy className="h-3.5 w-3.5 text-emerald-500" />
                    Copy Markdown to clipboard
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={shareCompactSummary} className="gap-2 text-xs">
                    <Share2 className="h-3.5 w-3.5 text-emerald-500" />
                    Share compact summary
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={exportPdf} className="gap-2 text-xs" disabled={pdfLoading}>
                    {pdfLoading ? (
                      <Loader2 className="h-3.5 w-3.5 text-emerald-500 animate-spin" />
                    ) : (
                      <FileDown className="h-3.5 w-3.5 text-emerald-500" />
                    )}
                    {pdfLoading ? "Generating PDF…" : "Export as PDF"}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={exportSarif} className="gap-2 text-xs">
                    <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
                    Export as SARIF (CI/CD)
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>

          {/* Severity filter chips - always visible when there are findings */}
          {result.stats.totalFindings > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <SeverityChip
                label="All"
                count={result.stats.totalFindings}
                active={filter === "all"}
                onClick={() => setFilter("all")}
                tone="muted"
              />
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => {
                const count = result.stats.bySeverity[s];
                if (count === 0) return null;
                return (
                  <SeverityChip
                    key={s}
                    label={SEVERITY_LABEL[s]}
                    count={count}
                    active={filter === s}
                    onClick={() =>
                      setFilter((prev) => (prev === s ? "all" : s))
                    }
                    tone={s}
                  />
                );
              })}
            </div>
          )}
        </div>

        <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3 custom-scrollbar">
          {filtered.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 py-12 text-center">
              <ShieldCheck className="h-8 w-8 text-emerald-500" />
              <p className="text-sm text-muted-foreground">
                No findings at this filter level.
              </p>
            </div>
          ) : (
            filtered.map((f, i) => (
              <FindingCard
                key={`${f.ruleId}-${f.line}-${i}`}
                finding={f}
                index={i}
                onJump={onJump}
                defaultOpen={allExpanded ?? i < 2}
                suppressed={suppressedKeys.has(`${f.ruleId}:${f.line}`)}
                onToggleSuppress={() => toggleSuppress(`${f.ruleId}:${f.line}`)}
                onApplyFix={onApplyFix}
                sourceLines={sourceLines}
              />
            ))
          )}
        </div>
      </div>

      {/* Scan Comparison Overlay */}
      <AnimatePresence>
        {compareOpen && previousScan && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 z-30 flex items-center justify-center bg-background/90 backdrop-blur-sm p-4"
          >
            <motion.div
              initial={{ scale: 0.95, y: 10 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.95, y: 10 }}
              className="relative w-full max-w-2xl max-h-full overflow-auto rounded-xl border border-border bg-card shadow-2xl custom-scrollbar"
            >
              <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-muted/30 px-5 py-3 backdrop-blur">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <GitCompare className="h-4 w-4 text-emerald-500" />
                  Scan Comparison
                </h3>
                <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setCompareOpen(false)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <div className="p-5 space-y-4">
                <ComparisonRow
                  label="Verdict"
                  current={result.verdict.toUpperCase()}
                  previous={previousScan.verdict.toUpperCase()}
                  type="verdict"
                />
                <ComparisonRow
                  label="Risk Score"
                  current={String(result.riskScore)}
                  previous={String(previousScan.riskScore)}
                  type="number"
                />
                <ComparisonRow
                  label="Findings"
                  current={String(result.stats.totalFindings)}
                  previous={String(previousScan.stats.totalFindings)}
                  type="number"
                />
                <ComparisonRow
                  label="Lines"
                  current={String(result.stats.totalLines)}
                  previous={String(previousScan.stats.totalLines)}
                  type="number"
                />

                {/* Severity comparison */}
                <div>
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Severity Breakdown
                  </p>
                  <div className="space-y-1.5">
                    {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => {
                      const curr = result.stats.bySeverity[sev];
                      const prev = previousScan.stats.bySeverity[sev];
                      if (curr === 0 && prev === 0) return null;
                      return (
                        <ComparisonRow
                          key={sev}
                          label={SEVERITY_LABEL[sev]}
                          current={String(curr)}
                          previous={String(prev)}
                          type="number"
                        />
                      );
                    })}
                  </div>
                </div>

                {/* New/Removed findings */}
                {(() => {
                  const currentKeys = new Set(result.findings.map((f) => `${f.ruleId}:${f.line}`));
                  const prevKeys = new Set(previousScan.findings.map((f) => `${f.ruleId}:${f.line}`));
                  const added = result.findings.filter((f) => !prevKeys.has(`${f.ruleId}:${f.line}`));
                  const removed = previousScan.findings.filter((f) => !currentKeys.has(`${f.ruleId}:${f.line}`));
                  return (
                    <>
                      {added.length > 0 && (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-red-500">
                            New Findings ({added.length})
                          </p>
                          <div className="space-y-1">
                            {added.slice(0, 5).map((f, i) => (
                              <div key={i} className="flex items-center gap-2 rounded bg-red-500/5 px-2.5 py-1.5 text-xs">
                                <ArrowUpRight className="h-3 w-3 shrink-0 text-red-500" />
                                <span className="font-mono text-[10px] text-muted-foreground">{f.ruleId}</span>
                                <span className="truncate text-foreground/80">{f.title}</span>
                                <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground">L{f.line}</span>
                              </div>
                            ))}
                            {added.length > 5 && (
                              <p className="text-[10px] text-muted-foreground pl-5">…and {added.length - 5} more</p>
                            )}
                          </div>
                        </div>
                      )}
                      {removed.length > 0 && (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-500">
                            Resolved Findings ({removed.length})
                          </p>
                          <div className="space-y-1">
                            {removed.slice(0, 5).map((f, i) => (
                              <div key={i} className="flex items-center gap-2 rounded bg-emerald-500/5 px-2.5 py-1.5 text-xs">
                                <ArrowDownRight className="h-3 w-3 shrink-0 text-emerald-500" />
                                <span className="font-mono text-[10px] text-muted-foreground">{f.ruleId}</span>
                                <span className="truncate text-foreground/80">{f.title}</span>
                                <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground">L{f.line}</span>
                              </div>
                            ))}
                            {removed.length > 5 && (
                              <p className="text-[10px] text-muted-foreground pl-5">…and {removed.length - 5} more</p>
                            )}
                          </div>
                        </div>
                      )}
                      {added.length === 0 && removed.length === 0 && (
                        <p className="text-xs text-muted-foreground text-center py-2">
                          No changes in findings between scans.
                        </p>
                      )}
                    </>
                  );
                })()}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="relative flex h-full flex-col items-center justify-center gap-5 overflow-hidden p-8 text-center">
      {/* Animated radar background */}
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5 }}
        className="radar-container relative flex h-32 w-32 items-center justify-center"
      >
        {/* Concentric rings */}
        <div className="absolute inset-0 rounded-full border border-emerald-500/20" />
        <div className="absolute inset-3 rounded-full border border-emerald-500/25" />
        <div className="absolute inset-6 rounded-full border border-emerald-500/30" />
        <div className="absolute inset-9 rounded-full border border-emerald-500/40" />

        {/* Rotating radar sweep */}
        <div className="radar-sweep absolute inset-0 rounded-full" />

        {/* Center icon */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="relative flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 ring-1 ring-emerald-500/30 animate-shield-float">
            <ShieldCheck className="h-6 w-6 text-emerald-500" />
          </div>
        </div>

        {/* Pulsing dot in corner (representing detected signal) */}
        <motion.div
          className="absolute right-3 top-3 h-2 w-2 rounded-full bg-emerald-400"
          animate={{ scale: [1, 1.5, 1], opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="absolute bottom-4 left-4 h-1.5 w-1.5 rounded-full bg-emerald-400"
          animate={{ scale: [1, 1.4, 1], opacity: [0.3, 0.8, 0.3] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut", delay: 0.7 }}
        />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="space-y-2"
      >
        <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
          </span>
          Awaiting input
        </div>
        <h3 className="text-lg font-bold text-foreground">
          Ready to scan
        </h3>
        <p className="mx-auto max-w-sm text-sm leading-relaxed text-muted-foreground">
          Paste Python source on the left, drop a{" "}
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
            .py
          </code>{" "}
          file, or load a sample. Then hit{" "}
          <span className="font-medium text-foreground">
            Scan for backdoors
          </span>
          .
        </p>
      </motion.div>

      <div className="grid w-full max-w-md grid-cols-2 gap-1.5 text-left text-[11px] text-muted-foreground sm:grid-cols-3">
        <Hint text="Reverse shells" />
        <Hint text="eval/exec injection" />
        <Hint text="Obfuscated payloads" />
        <Hint text="Pickle RCE" />
        <Hint text="Credential theft" />
        <Hint text="Persistence" />
      </div>

      <div className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
        <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5">
          Ctrl
        </kbd>
        <span>+</span>
        <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5">
          Enter
        </kbd>
        <span>to scan immediately</span>
      </div>
    </div>
  );
}

function Hint({ text }: { text: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-border/60 bg-muted/30 px-2 py-1 transition-colors hover:border-emerald-500/30 hover:bg-emerald-500/5">
      <span className="h-1 w-1 rounded-full bg-emerald-500" />
      {text}
    </span>
  );
}

function LoadingState() {
  const SCAN_CATEGORIES = [
    "Reverse shells",
    "Code injection",
    "Obfuscation",
    "Deserialization",
    "Network callbacks",
    "Credential theft",
    "Persistence",
    "Privilege escalation",
    "Exfiltration",
  ];

  const [categoryIndex, setCategoryIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCategoryIndex((prev) => (prev + 1) % SCAN_CATEGORIES.length);
    }, 350);
    return () => clearInterval(interval);
  }, []);

  const progress = ((categoryIndex + 1) / SCAN_CATEGORIES.length) * 100;

  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-8 text-center">
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
        className="relative flex h-16 w-16 items-center justify-center rounded-full border-2 border-muted border-t-emerald-500"
      >
        <ScanLine className="h-7 w-7 text-emerald-500" />
        {/* Pulsing scan line effect */}
        <div className="absolute inset-0 overflow-hidden rounded-full">
          <div className="animate-scan-line h-4 w-full bg-gradient-to-b from-emerald-500/20 to-transparent" />
        </div>
        {/* Outer pulsing ring */}
        <motion.div
          className="absolute inset-[-4px] rounded-full border border-emerald-500/20"
          animate={{ opacity: [0.2, 0.6, 0.2], scale: [1, 1.05, 1] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: "easeInOut" }}
        />
      </motion.div>

      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">
          Analyzing source…
        </p>
        <p className="text-xs text-muted-foreground">
          Running {RULE_COUNT} static analysis rules
        </p>
      </div>

      {/* Cycling category label with fade transition */}
      <div className="h-5 overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.p
            key={categoryIndex}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
            className="text-xs font-mono text-emerald-600 dark:text-emerald-400"
          >
            Checking {SCAN_CATEGORIES[categoryIndex]}…
          </motion.p>
        </AnimatePresence>
      </div>

      {/* Progress bar */}
      <div className="w-full max-w-xs space-y-1.5">
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <motion.div
            className="h-full rounded-full bg-gradient-to-r from-emerald-600 to-emerald-400"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3, ease: "easeOut" }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-muted-foreground">
          <span>
            Rule {categoryIndex + 1} of {SCAN_CATEGORIES.length}
          </span>
          <span>{Math.round(progress)}%</span>
        </div>
      </div>

      {/* Shimmer bars */}
      <div className="w-full max-w-xs space-y-2">
        {[80, 60, 90, 40].map((w, i) => (
          <motion.div
            key={i}
            className="h-3 rounded bg-muted"
            style={{ width: `${w}%` }}
            animate={{ opacity: [0.4, 1, 0.4] }}
            transition={{
              duration: 1.2,
              repeat: Infinity,
              delay: i * 0.15,
            }}
          />
        ))}
      </div>
    </div>
  );
}

function ComparisonRow({
  label,
  current,
  previous,
  type,
}: {
  label: string;
  current: string;
  previous: string;
  type: "number" | "verdict";
}) {
  const currNum = type === "number" ? parseInt(current, 10) : 0;
  const prevNum = type === "number" ? parseInt(previous, 10) : 0;
  const diff = currNum - prevNum;

  const diffIcon =
    diff > 0 ? (
      <ArrowUpRight className="h-3 w-3 text-red-500" />
    ) : diff < 0 ? (
      <ArrowDownRight className="h-3 w-3 text-emerald-500" />
    ) : (
      <Minus className="h-3 w-3 text-muted-foreground/40" />
    );

  const diffColor =
    diff > 0
      ? "text-red-500"
      : diff < 0
        ? "text-emerald-500"
        : "text-muted-foreground/40";

  return (
    <div className="flex items-center gap-3 rounded-lg border border-border/60 bg-muted/20 px-3 py-2">
      <span className="min-w-[80px] text-xs font-medium text-muted-foreground">
        {label}
      </span>
      <span className="min-w-[50px] font-mono text-sm font-bold text-foreground">
        {current}
      </span>
      <div className="flex items-center gap-1">
        {diffIcon}
        {type === "number" && diff !== 0 && (
          <span className={`font-mono text-[11px] ${diffColor}`}>
            {diff > 0 ? "+" : ""}
            {diff}
          </span>
        )}
      </div>
      <span className="ml-auto text-[10px] text-muted-foreground">
        prev: {previous}
      </span>
    </div>
  );
}

/** Severity filter chip — toggle button with count and severity-specific styling. */
const SEVERITY_CHIP_STYLE: Record<string, { dot: string; active: string; icon: typeof Skull }> = {
  critical: {
    dot: "bg-red-500",
    active: "border-red-500/50 bg-red-500/15 text-red-600 dark:text-red-400",
    icon: Skull,
  },
  high: {
    dot: "bg-orange-500",
    active: "border-orange-500/50 bg-orange-500/15 text-orange-600 dark:text-orange-400",
    icon: AlertOctagon,
  },
  medium: {
    dot: "bg-amber-500",
    active: "border-amber-500/50 bg-amber-500/15 text-amber-600 dark:text-amber-400",
    icon: AlertTriangle,
  },
  low: {
    dot: "bg-blue-500",
    active: "border-blue-500/50 bg-blue-500/15 text-blue-600 dark:text-blue-400",
    icon: Info,
  },
  info: {
    dot: "bg-zinc-500",
    active: "border-zinc-500/50 bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
    icon: Bug,
  },
  muted: {
    dot: "bg-emerald-500",
    active: "border-emerald-500/50 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    icon: ShieldCheck,
  },
};

function SeverityChip({
  label,
  count,
  active,
  onClick,
  tone,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
  tone: Severity | "muted";
}) {
  const style = SEVERITY_CHIP_STYLE[tone] ?? SEVERITY_CHIP_STYLE.muted;
  const Icon = style.icon;
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium transition-all hover:scale-[1.04] ${
        active
          ? style.active
          : "border-border bg-muted/40 text-muted-foreground hover:bg-muted/70"
      }`}
      title={`${active ? "Hide" : "Show"} ${label.toLowerCase()} findings`}
    >
      <Icon className="h-3 w-3" />
      <span className="uppercase tracking-wide">{label}</span>
      <span className="font-mono text-[9px] opacity-80">{count}</span>
    </button>
  );
}
