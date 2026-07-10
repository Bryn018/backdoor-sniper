"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  ScrollText,
  Github,
  Terminal,
  Zap,
  Layers,
  Bug,
  Keyboard,
  BarChart3,
  BookOpen,
  Wand2,
  Eye,
  HelpCircle,
  Bookmark,
  Building2,
  FolderTree,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { CodeInput } from "@/components/scanner/code-input";
import { ResultsPanel } from "@/components/scanner/results-panel";
import { type ApplyFixPayload } from "@/components/scanner/finding-card";
import { HistoryPanel } from "@/components/scanner/history-panel";
import { ThemeToggle } from "@/components/scanner/theme-toggle";
import { StatsModal } from "@/components/scanner/stats-modal";
import { RulesBrowser } from "@/components/scanner/rules-browser";
import {
  CustomRuleEditor,
  loadCustomRules,
  saveCustomRules,
  type CustomRule,
} from "@/components/scanner/custom-rule-editor";
import { KeyboardShortcuts } from "@/components/scanner/keyboard-shortcuts";
import {
  SnippetLibrary,
} from "@/components/scanner/snippet-library";
import {
  BatchResultsPanel,
  type BatchResult,
} from "@/components/scanner/batch-results-panel";
import {
  DetectionProfileSwitcher,
  loadProfileId,
} from "@/components/scanner/detection-profile-switcher";
import { EnterprisePanel } from "@/components/scanner/enterprise-panel";
import { ProjectScanPanel } from "@/components/scanner/project-scan-panel";
import { DETECTION_PROFILES, type DetectionProfile } from "@/lib/detector/profiles";
import { AnimatedCounter } from "@/components/scanner/animated-counter";
import { ALL_RULES, type CustomRuleSpec } from "@/lib/detector/scanner";
import type { ScanResult } from "@/lib/detector/types";
import { toast } from "sonner";

const RULE_COUNT = ALL_RULES.length;

const CATEGORY_COUNT = 16;

export default function Home() {
  const [code, setCode] = useState<string>("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeLine, setActiveLine] = useState<number | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [statsOpen, setStatsOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [customRulesOpen, setCustomRulesOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [snippetsOpen, setSnippetsOpen] = useState(false);
  const [enterpriseOpen, setEnterpriseOpen] = useState(false);
  const [projectScanOpen, setProjectScanOpen] = useState(false);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [disabledRules, setDisabledRules] = useState<Set<string>>(new Set());
  const [customRules, setCustomRules] = useState<CustomRule[]>([]);
  const [watchMode, setWatchMode] = useState(false);
  const [activeProfileId, setActiveProfileId] = useState<string>("all");
  const watchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastScannedCodeRef = useRef<string>("");

  // Batch scanning state
  const [batchResult, setBatchResult] = useState<BatchResult | null>(null);
  const [batchLoading, setBatchLoading] = useState(false);

  // Load custom rules + active profile from localStorage on mount (client-only)
  useEffect(() => {
    setCustomRules(loadCustomRules());
    const pid = loadProfileId();
    setActiveProfileId(pid);
    const p = DETECTION_PROFILES.find((x) => x.id === pid);
    if (p && p.disabledRuleIds.length > 0) {
      setDisabledRules(new Set(p.disabledRuleIds));
    }
  }, []);

  const enabledCustomRuleSpecs: CustomRuleSpec[] = customRules
    .filter((r) => r.enabled)
    .map(({ enabled, createdAt, ...spec }) => spec);

  const toggleRule = useCallback((ruleId: string) => {
    setDisabledRules((prev) => {
      const next = new Set(prev);
      if (next.has(ruleId)) next.delete(ruleId);
      else next.add(ruleId);
      return next;
    });
  }, []);

  const resetRules = useCallback(() => {
    setDisabledRules(new Set());
    setActiveProfileId("all");
    try {
      localStorage.setItem("backdoorsniper.profile.v1", "all");
    } catch {
      /* ignore */
    }
  }, []);

  const onChangeProfile = useCallback((p: DetectionProfile) => {
    setActiveProfileId(p.id);
    setDisabledRules(new Set(p.disabledRuleIds));
  }, []);

  const onScan = useCallback(async () => {
    if (!code.trim()) return;
    setScanning(true);
    setError(null);
    setResult(null);
    setBatchResult(null);
    setActiveLine(null);
    lastScannedCodeRef.current = code;
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          save: true,
          disabledRuleIds: disabledRules.size > 0 ? Array.from(disabledRules) : undefined,
          customRules: enabledCustomRuleSpecs.length > 0 ? enabledCustomRuleSpecs : undefined,
        }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e.error || `Scan failed (${res.status})`);
      }
      const data: ScanResult & { customRuleErrors?: { id: string; error: string }[] } =
        await res.json();
      setResult(data);
      setHistoryRefresh((k) => k + 1);
      if (data.customRuleErrors && data.customRuleErrors.length > 0) {
        toast.warning(`${data.customRuleErrors.length} custom rule(s) failed to compile`, {
          description: data.customRuleErrors[0].error,
        });
      }
      const verdictLabel = data.verdict;
      if (verdictLabel === "clean") {
        toast.success("Scan complete — no backdoors detected", {
          description: `${data.stats.totalFindings} findings · risk ${data.riskScore}/100`,
        });
      } else if (verdictLabel === "suspicious") {
        toast.warning("Suspicious patterns found", {
          description: `${data.stats.totalFindings} findings · risk ${data.riskScore}/100`,
        });
      } else {
        toast.error(`Backdoor detected: ${verdictLabel.toUpperCase()}`, {
          description: `${data.stats.totalFindings} findings · risk ${data.riskScore}/100`,
        });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setScanning(false);
    }
  }, [code, disabledRules, enabledCustomRuleSpecs.length]);

  // Watch mode — auto-rescan 800ms after code change (if code is non-trivial)
  useEffect(() => {
    if (!watchMode) return;
    if (!code.trim()) return;
    if (code === lastScannedCodeRef.current) return;
    if (watchDebounceRef.current) clearTimeout(watchDebounceRef.current);
    watchDebounceRef.current = setTimeout(() => {
      onScan();
    }, 800);
    return () => {
      if (watchDebounceRef.current) clearTimeout(watchDebounceRef.current);
    };
  }, [code, watchMode, onScan]);

  const onBatchFiles = useCallback(
    async (files: { name: string; content: string }[]) => {
      setBatchLoading(true);
      setBatchResult(null);
      setResult(null);
      setError(null);
      try {
        const res = await fetch("/api/scan/batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ files }),
        });
        if (!res.ok) {
          const e = await res.json().catch(() => ({}));
          throw new Error(e.error || `Batch scan failed (${res.status})`);
        }
        const data: BatchResult = await res.json();
        setBatchResult(data);
        setHistoryRefresh((k) => k + 1);
        const worstCount = data.results.filter(
          (r) => r.verdict === "dangerous" || r.verdict === "malicious"
        ).length;
        if (worstCount > 0) {
          toast.error(`Batch scan: ${worstCount} hostile file${worstCount === 1 ? "" : "s"}`, {
            description: `${data.totalFiles} files · ${data.totalFindings} findings · worst ${data.worstVerdict}`,
          });
        } else if (data.totalFindings > 0) {
          toast.warning(`Batch scan: ${data.totalFindings} suspicious finding${data.totalFindings === 1 ? "" : "s"}`, {
            description: `${data.totalFiles} files · worst ${data.worstVerdict}`,
          });
        } else {
          toast.success("Batch scan complete — all files clean", {
            description: `${data.totalFiles} files scanned`,
          });
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Unknown error");
      } finally {
        setBatchLoading(false);
      }
    },
    []
  );

  const onApplyFix = useCallback(
    (payload: ApplyFixPayload) => {
      setCode((prev) => {
        const lines = prev.replace(/\r\n/g, "\n").split("\n");
        const lineIndex = payload.line - 1; // Convert 1-based to 0-based
        if (lineIndex >= 0 && lineIndex < lines.length) {
          // The replacement may be multi-line (e.g. comment + original),
          // replace the single line with the full replacement
          lines[lineIndex] = payload.replacement.split("\n").pop() || lines[lineIndex];
        }
        return lines.join("\n");
      });
      toast.success("Fix applied — re-scanning...", {
        description: `Line ${payload.line} updated`,
      });
      // Auto-trigger scan after a short delay to let state update
      setTimeout(() => {
        onScan();
      }, 300);
    },
    [onScan]
  );

  // Apply multiple fixes in one pass — sort by line descending so earlier
  // line replacements don't shift later line indices.
  const onApplyAllFixes = useCallback(
    (payloads: ApplyFixPayload[]) => {
      if (payloads.length === 0) return;
      // Sort by line descending so we mutate from bottom-up
      const sorted = [...payloads].sort((a, b) => b.line - a.line);
      setCode((prev) => {
        const lines = prev.replace(/\r\n/g, "\n").split("\n");
        for (const p of sorted) {
          const idx = p.line - 1;
          if (idx >= 0 && idx < lines.length) {
            lines[idx] = p.replacement.split("\n").pop() || lines[idx];
          }
        }
        return lines.join("\n");
      });
      toast.success(`Applied ${payloads.length} fixes — re-scanning…`, {
        description: `${payloads.length} line${payloads.length === 1 ? "" : "s"} updated`,
      });
      setTimeout(() => {
        onScan();
      }, 350);
    },
    [onScan]
  );

  const onJump = useCallback((line: number) => {
    setActiveLine(line);
    if (typeof window !== "undefined") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, []);

  // Restore a past scan from history
  const onRestore = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/history/${id}`);
      if (!res.ok) throw new Error("Failed to load scan");
      const data = await res.json();
      const restored: ScanResult = {
        findings: data.findings ?? [],
        stats: {
          totalLines: data.totalLines ?? 0,
          totalFindings: (data.findings ?? []).length,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {},
        },
        riskScore: data.riskScore ?? 0,
        verdict: data.verdict ?? "clean",
        durationMs: 0,
        sourceHash: data.sourceHash ?? "",
        scannedAt: data.createdAt ?? new Date().toISOString(),
      };
      for (const f of restored.findings) {
        restored.stats.bySeverity[f.severity]++;
        restored.stats.byCategory[f.category] =
          (restored.stats.byCategory[f.category] ?? 0) + 1;
      }
      setResult(restored);
      setBatchResult(null);
      setCode(data.sourcePreview ?? "");
      lastScannedCodeRef.current = data.sourcePreview ?? "";
      setHistoryOpen(false);
      toast.success("Scan restored from history", {
        description: `${restored.findings.length} findings · risk ${restored.riskScore}/100`,
      });
    } catch {
      toast.error("Failed to restore scan");
    }
  }, []);

  // Keyboard shortcuts: Ctrl+Enter to scan, ? for help, etc.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Skip if user is typing in an input/textarea/select
      const target = e.target as HTMLElement | null;
      const isTypingTarget =
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable);

      // Ctrl/Cmd+Enter always works (even from textarea)
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        if (code.trim() && !scanning) onScan();
        return;
      }

      // Single-key shortcuts only when NOT typing
      if (isTypingTarget) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;

      switch (e.key.toLowerCase()) {
        case "?":
          // Shift+/ produces "?"
          if (e.shiftKey) {
            e.preventDefault();
            setShortcutsOpen((v) => !v);
          }
          break;
        case "h":
          e.preventDefault();
          setHistoryOpen((v) => !v);
          break;
        case "r":
          e.preventDefault();
          setRulesOpen((v) => !v);
          break;
        case "s":
          e.preventDefault();
          setStatsOpen((v) => !v);
          break;
        case "u":
          e.preventDefault();
          setCustomRulesOpen((v) => !v);
          break;
        case "t":
          e.preventDefault();
          // Trigger theme toggle by clicking the toggle button
          document.querySelector<HTMLButtonElement>("[aria-label='Toggle theme']")?.click();
          break;
        case "w":
          e.preventDefault();
          setWatchMode((v) => {
            const next = !v;
            toast.info(next ? "Watch mode on — auto-rescanning" : "Watch mode off");
            return next;
          });
          break;
        case "b":
          e.preventDefault();
          setSnippetsOpen((v) => !v);
          break;
        case "e":
          e.preventDefault();
          setEnterpriseOpen((v) => !v);
          break;
        case "p":
          e.preventDefault();
          setProjectScanOpen((v) => !v);
          break;
      case "c":
          e.preventDefault();
          if (code) {
            setCode("");
            setResult(null);
            toast.info("Editor cleared");
          }
          break;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [code, scanning, onScan]);

  const onChangeCustomRules = useCallback((next: CustomRule[]) => {
    setCustomRules(next);
    saveCustomRules(next);
  }, []);

  return (
    <div className="flex min-h-screen flex-col">
      {/* Header */}
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex h-14 max-w-[1600px] items-center gap-3 px-4">
          <div className="flex items-center gap-2.5">
            <div className="relative flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-600 shadow-lg shadow-emerald-600/20">
              <ShieldCheck className="h-5 w-5 text-white" />
              <div className="absolute inset-0 rounded-lg bg-emerald-500/20 animate-ring-pulse" />
            </div>
            <div className="leading-none">
              <h1 className="font-mono text-sm font-bold tracking-tight">
                BackdoorSniper
              </h1>
              <p className="text-[10px] text-muted-foreground">
                Python backdoor detector
              </p>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <div className="hidden items-center gap-3 rounded-lg border border-border bg-muted/30 px-3 py-1.5 font-mono text-[10px] text-muted-foreground sm:flex">
              <span className="flex items-center gap-1">
                <Zap className="h-3 w-3 text-emerald-500" />
                <AnimatedCounter value={RULE_COUNT} /> rules
              </span>
              <span className="h-3 w-px bg-border" />
              <span className="flex items-center gap-1">
                <Layers className="h-3 w-3 text-emerald-500" />
                {CATEGORY_COUNT} categories
              </span>
              {customRules.filter((r) => r.enabled).length > 0 && (
                <>
                  <span className="h-3 w-px bg-border" />
                  <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                    <Wand2 className="h-3 w-3" />
                    {customRules.filter((r) => r.enabled).length} custom
                  </span>
                </>
              )}
            </div>

            {/* Watch mode toggle */}
            <Button
              variant="outline"
              size="sm"
              className={`h-9 gap-1.5 ${watchMode ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 watch-active" : ""}`}
              onClick={() => {
                const next = !watchMode;
                setWatchMode(next);
                toast.info(next ? "Watch mode on — auto-rescanning" : "Watch mode off");
              }}
              title="Toggle watch mode (auto-rescan on code change)"
            >
              <Eye className="h-4 w-4" />
              <span className="hidden sm:inline">Watch</span>
            </Button>

            <Button
              variant="outline"
              size="sm"
              className={`h-9 gap-1.5 ${customRules.filter((r) => r.enabled).length > 0 ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : ""}`}
              onClick={() => setCustomRulesOpen(true)}
              title="Write custom detection rules"
            >
              <Wand2 className="h-4 w-4" />
              <span className="hidden sm:inline">Custom</span>
              {customRules.filter((r) => r.enabled).length > 0 && (
                <span className="rounded-full bg-emerald-500/20 px-1.5 py-0.5 text-[9px] font-bold">
                  {customRules.filter((r) => r.enabled).length}
                </span>
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              className={`h-9 gap-1.5 ${disabledRules.size > 0 ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400" : ""}`}
              onClick={() => setRulesOpen(true)}
              title={disabledRules.size > 0 ? `${disabledRules.size} rules disabled — click to manage` : "Browse all detection rules"}
            >
              <BookOpen className="h-4 w-4" />
              <span className="hidden sm:inline">Rules</span>
              {disabledRules.size > 0 && (
                <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-bold">
                  {disabledRules.size} off
                </span>
              )}
            </Button>

            <DetectionProfileSwitcher
              activeProfileId={activeProfileId}
              onChange={onChangeProfile}
            />

            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5"
              onClick={() => setSnippetsOpen(true)}
              title="Open snippet library (press B)"
            >
              <Bookmark className="h-4 w-4" />
              <span className="hidden sm:inline">Snippets</span>
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5"
              onClick={() => setStatsOpen(true)}
              title="View scan statistics"
            >
              <BarChart3 className="h-4 w-4" />
              <span className="hidden sm:inline">Stats</span>
            </Button>

            <Sheet open={historyOpen} onOpenChange={setHistoryOpen}>
              <SheetTrigger asChild>
                <Button variant="outline" size="sm" className="h-9 gap-1.5">
                  <ScrollText className="h-4 w-4" />
                  <span className="hidden sm:inline">History</span>
                </Button>
              </SheetTrigger>
              <SheetContent className="w-full sm:max-w-sm p-0">
                <SheetHeader className="sr-only">
                  <SheetTitle>Scan history</SheetTitle>
                </SheetHeader>
                <HistoryPanel
                  refreshKey={historyRefresh}
                  onDeleted={() => setHistoryRefresh((k) => k + 1)}
                  onRestore={onRestore}
                />
              </SheetContent>
            </Sheet>

            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20"
              onClick={() => setProjectScanOpen(true)}
              title="Project scan (zip / tar / multi-file) — press P"
            >
              <FolderTree className="h-4 w-4" />
              <span className="hidden sm:inline">Project Scan</span>
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20"
              onClick={() => setEnterpriseOpen(true)}
              title="Enterprise console (API keys, audit log, policies, compliance) — press E"
            >
              <Building2 className="h-4 w-4" />
              <span className="hidden sm:inline">Enterprise</span>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="h-9 w-9"
              onClick={() => setShortcutsOpen(true)}
              title="Keyboard shortcuts (press ?)"
            >
              <HelpCircle className="h-4 w-4" />
            </Button>

            <ThemeToggle />
          </div>
        </div>
        {/* Scan progress bar (visible only while scanning) */}
        {scanning && <div className="header-progress-bar" />}
      </header>

      {/* Hero */}
      <section className="relative grid-bg circuit-bg hero-gradient border-b border-border">
        <div className="mx-auto max-w-[1600px] px-4 py-8">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="max-w-3xl"
          >
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              <Bug className="h-3 w-3" />
              Static analysis · zero execution
            </div>
            <h2 className="text-balance text-3xl font-bold tracking-tight sm:text-4xl">
              Hunt{" "}
              <span className="bg-gradient-to-r from-emerald-500 to-emerald-400 bg-clip-text text-transparent">
                backdoors
              </span>{" "}
              hidden in Python source
            </h2>
            <p className="mt-3 max-w-2xl text-pretty text-sm leading-relaxed text-muted-foreground sm:text-base">
              Paste Python code, drop a{" "}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                .py
              </code>{" "}
              file, or load a real-world sample. BackdoorSniper runs{" "}
              <strong className="text-foreground">
                {RULE_COUNT} AST-aware detection rules
              </strong>{" "}
              covering reverse shells,{" "}
              <code className="font-mono">eval</code>/{" "}
              <code className="font-mono">exec</code> injection, obfuscated
              payloads, pickle deserialization, credential stealers, persistence
              mechanisms and more — without ever executing the code.
            </p>

            <div className="mt-5 flex flex-wrap items-center gap-2">
              <FeaturePill label="Reverse shells" />
              <FeaturePill label="Code injection" />
              <FeaturePill label="Obfuscation" />
              <FeaturePill label="Deserialization" />
              <FeaturePill label="Credential theft" />
              <FeaturePill label="Persistence" />
              <FeaturePill label="AI analysis" accent />
              <FeaturePill label="Syntax highlight" accent />
              <FeaturePill label="Batch scan" accent />
              <FeaturePill label="Custom rules" accent />
              <FeaturePill label="Watch mode" accent />
              <FeaturePill label="Snippet library" accent />
              <FeaturePill label="CWE references" accent />
              <FeaturePill label="API keys & audit" accent />
              <FeaturePill label="CI/CD gating" accent />
              <FeaturePill label="Compliance (PCI/OWASP/NIST)" accent />
              <FeaturePill label="Supply-chain rules" accent />
              <FeaturePill label="SIEM webhooks" accent />
              <FeaturePill label="Scheduled scans" accent />
              <FeaturePill label="Trends dashboard" accent />
              <FeaturePill label="150+ AST-aware rules" accent />
              <FeaturePill label="Multi-file project scans" accent />
              <FeaturePill label="Real-time SSE progress" accent />
            </div>

            <div className="mt-4 flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
              <Keyboard className="h-3 w-3" />
              <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5">
                Ctrl
              </kbd>
              <span>+</span>
              <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5">
                Enter
              </kbd>
              <span className="ml-1">to scan</span>
              <span className="mx-2">·</span>
              <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5">
                ?
              </kbd>
              <span className="ml-1">for shortcuts</span>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Workspace */}
      <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-4">
        <div className="grid h-[calc(100vh-13rem)] min-h-[560px] grid-cols-1 gap-4 lg:grid-cols-12">
          {/* Editor */}
          <motion.section
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="panel-border-glow overflow-hidden rounded-xl border border-border bg-card shadow-sm lg:col-span-6 xl:col-span-6"
          >
            <CodeInput
              code={code}
              onChange={setCode}
              onScan={onScan}
              scanning={scanning}
              activeLine={activeLine}
              findings={result?.findings}
              onBatchFiles={onBatchFiles}
            />
          </motion.section>

          {/* Results */}
          <motion.section
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.05 }}
            className="panel-border-glow overflow-hidden rounded-xl border border-border bg-card shadow-sm lg:col-span-6 xl:col-span-6"
          >
            {batchResult || batchLoading ? (
              <BatchResultsPanel
                result={batchResult}
                loading={batchLoading}
                onClose={() => {
                  setBatchResult(null);
                }}
              />
            ) : (
              <ResultsPanel
                result={result}
                scanning={scanning}
                error={error}
                onJump={onJump}
                onApplyFix={onApplyFix}
                onApplyAllFixes={onApplyAllFixes}
                source={code}
              />
            )}
          </motion.section>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-border bg-muted/20">
        <div className="mx-auto flex max-w-[1600px] flex-col items-center justify-between gap-2 px-4 py-4 text-xs text-muted-foreground sm:flex-row">
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-emerald-500" />
            <span>
              <strong className="text-foreground">BackdoorSniper</strong> ·
              static Python backdoor analysis
            </span>
          </div>
          <div className="flex items-center gap-4 font-mono text-[10px]">
            <span>{RULE_COUNT} rules</span>
            <span>·</span>
            <span>0 bytes executed</span>
            <span>·</span>
            <span>AI-powered analysis</span>
            <span>·</span>
            <span className="flex items-center gap-1">
              <Github className="h-3 w-3" />
              for defensive use
            </span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <StatsModal
        open={statsOpen}
        onClose={() => setStatsOpen(false)}
        refreshKey={historyRefresh}
      />
      <RulesBrowser
        open={rulesOpen}
        onClose={() => setRulesOpen(false)}
        disabledRules={disabledRules}
        onToggleRule={toggleRule}
        onResetRules={resetRules}
      />
      <CustomRuleEditor
        open={customRulesOpen}
        onClose={() => setCustomRulesOpen(false)}
        rules={customRules}
        onChange={onChangeCustomRules}
        testCode={code}
      />
      <KeyboardShortcuts
        open={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
      />
      <SnippetLibrary
        open={snippetsOpen}
        onOpenChange={setSnippetsOpen}
        code={code}
        onLoad={(loadedCode, name) => {
          setCode(loadedCode);
          setResult(null);
          toast.success(`Loaded snippet: ${name}`, {
            description: `${loadedCode.split("\n").length} lines inserted`,
          });
        }}
      />
      <EnterprisePanel
        open={enterpriseOpen}
        onOpenChange={setEnterpriseOpen}
        lastResult={result}
      />
      <ProjectScanPanel
        open={projectScanOpen}
        onOpenChange={setProjectScanOpen}
      />
    </div>
  );
}

function FeaturePill({
  label,
  accent,
}: {
  label: string;
  accent?: boolean;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] transition-all hover:scale-[1.03] ${
        accent
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "border-border bg-muted/40 text-foreground/80 hover:bg-muted/60"
      }`}
    >
      <ShieldCheck className="h-3 w-3 text-emerald-500/70" />
      {label}
    </span>
  );
}
