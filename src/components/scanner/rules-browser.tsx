"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  X,
  BookOpen,
  Filter,
  Shield,
  Loader2,
  ToggleLeft,
  ToggleRight,
  RotateCcw,
  Flame,
  TrendingUp,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { RULES } from "@/lib/detector/rules";
import {
  SEVERITY_BADGE,
  SEVERITY_LABEL,
  CATEGORY_LABEL,
  CATEGORY_COLOR,
} from "@/lib/severity";
import type { Severity, Category } from "@/lib/detector/types";

interface RuleHit {
  ruleId: string;
  hits: number;
  lastSeen: string;
}

interface RulesBrowserProps {
  open: boolean;
  onClose: () => void;
  disabledRules: Set<string>;
  onToggleRule: (ruleId: string) => void;
  onResetRules: () => void;
  /** Bumped by parent whenever a new scan completes, so hit frequencies refresh. */
  refreshKey?: number;
}

export function RulesBrowser({
  open,
  onClose,
  disabledRules,
  onToggleRule,
  onResetRules,
  refreshKey = 0,
}: RulesBrowserProps) {
  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [catFilter, setCatFilter] = useState<Category | "all">("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [ruleHits, setRuleHits] = useState<Map<string, RuleHit>>(new Map());
  const [hitsLoading, setHitsLoading] = useState(false);
  const [sortBy, setSortBy] = useState<"severity" | "hits" | "id">("severity");

  // Defensive guard: ensure disabledRules is always a Set (prevents runtime crash
  // if the parent state becomes stale during Fast Refresh).
  const safeDisabled = disabledRules instanceof Set ? disabledRules : new Set<string>();

  // Fetch per-rule hit frequency from history (refreshed on refreshKey change)
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setHitsLoading(true);
    fetch("/api/rule-stats")
      .then((r) => r.json())
      .then((data: { rules: RuleHit[] }) => {
        if (cancelled) return;
        const map = new Map<string, RuleHit>();
        for (const h of data.rules ?? []) map.set(h.ruleId, h);
        setRuleHits(map);
      })
      .catch(() => {
        /* ignore — hit frequency is a nice-to-have */
      })
      .finally(() => {
        if (!cancelled) setHitsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, refreshKey]);

  // ESC to close
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const sevRank: Record<Severity, number> = {
      critical: 0, high: 1, medium: 2, low: 3, info: 4,
    };
    const base = RULES.filter((r) => {
      if (sevFilter !== "all" && r.severity !== sevFilter) return false;
      if (catFilter !== "all" && r.category !== catFilter) return false;
      if (!q) return true;
      return (
        r.id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        (r.references ?? []).some((ref) => ref.toLowerCase().includes(q))
      );
    });
    // Apply sort
    const sorted = [...base];
    if (sortBy === "hits") {
      sorted.sort((a, b) => {
        const ha = ruleHits.get(a.id)?.hits ?? 0;
        const hb = ruleHits.get(b.id)?.hits ?? 0;
        if (hb !== ha) return hb - ha;
        return sevRank[a.severity] - sevRank[b.severity];
      });
    } else if (sortBy === "id") {
      sorted.sort((a, b) => a.id.localeCompare(b.id));
    } else {
      // severity (default) — by sev rank, then id
      sorted.sort((a, b) => {
        const r = sevRank[a.severity] - sevRank[b.severity];
        if (r !== 0) return r;
        return a.id.localeCompare(b.id);
      });
    }
    return sorted;
  }, [query, sevFilter, catFilter, sortBy, ruleHits]);

  // Group by category for display (only when sorting by severity/id — when
  // sorting by hits, we render a flat list so the "most triggered" ordering
  // is preserved)
  const grouped = useMemo(() => {
    if (sortBy === "hits") {
      return { _all: filtered } as Record<string, typeof RULES>;
    }
    const g: Record<string, typeof RULES> = {};
    for (const r of filtered) {
      (g[r.category] ??= []).push(r);
    }
    return g;
  }, [filtered, sortBy]);

  const totalRules = RULES.length;
  const activeRules = totalRules - safeDisabled.size;
  const criticalCount = RULES.filter((r) => r.severity === "critical").length;
  const highCount = RULES.filter((r) => r.severity === "high").length;

  if (!open) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 10 }}
          transition={{ type: "spring", stiffness: 280, damping: 24 }}
          className="glass relative flex h-[90vh] w-[95vw] max-w-5xl flex-col overflow-hidden rounded-xl border border-border shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border bg-muted/30 px-5 py-3">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/15">
                <BookOpen className="h-4 w-4 text-emerald-500" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Detection Rules Browser</h3>
                <p className="text-[10px] text-muted-foreground">
                  {activeRules}/{totalRules} active · {criticalCount} critical · {highCount} high · 15 categories
                  {ruleHits.size > 0 && (
                    <span className="ml-1 text-emerald-600 dark:text-emerald-400">· {ruleHits.size} triggered</span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {safeDisabled.size > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1.5 text-[10px] text-amber-600 hover:text-amber-700 dark:text-amber-400"
                  onClick={onResetRules}
                >
                  <RotateCcw className="h-3 w-3" />
                  Re-enable all ({safeDisabled.size} disabled)
                </Button>
              )}
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onClose}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/10 px-4 py-2.5">
            <div className="relative min-w-[200px] flex-1">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search rules by id, title, description, CWE…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="h-8 pl-8 text-xs"
              />
            </div>
            <Select value={sevFilter} onValueChange={(v) => setSevFilter(v as Severity | "all")}>
              <SelectTrigger className="h-8 w-[130px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All severities</SelectItem>
                {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
                  <SelectItem key={s} value={s} className="text-xs">
                    {SEVERITY_LABEL[s]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={catFilter} onValueChange={(v) => setCatFilter(v as Category | "all")}>
              <SelectTrigger className="h-8 w-[170px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All categories</SelectItem>
                {(Object.keys(CATEGORY_LABEL) as Category[]).map((c) => (
                  <SelectItem key={c} value={c} className="text-xs">
                    {CATEGORY_LABEL[c]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Badge variant="outline" className="h-8 gap-1 px-2 text-[10px]">
              <Filter className="h-3 w-3" />
              {filtered.length}/{totalRules}
            </Badge>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="h-8 w-[150px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="severity" className="text-xs">Sort: Severity</SelectItem>
                <SelectItem value="hits" className="text-xs">Sort: Most triggered</SelectItem>
                <SelectItem value="id" className="text-xs">Sort: Rule ID</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Disabled rules notice */}
          {safeDisabled.size > 0 && (
            <div className="flex items-center gap-2 border-b border-amber-500/20 bg-amber-500/5 px-4 py-2 text-[11px]">
              <Shield className="h-3.5 w-3.5 text-amber-500" />
              <span className="text-amber-700 dark:text-amber-400">
                {safeDisabled.size} rule{safeDisabled.size === 1 ? "" : "s"} disabled — these will be skipped during scanning
              </span>
              <button
                onClick={onResetRules}
                className="ml-auto text-[10px] font-medium text-amber-600 hover:text-amber-700 dark:text-amber-400 transition-colors"
              >
                Re-enable all
              </button>
            </div>
          )}

          {/* Body */}
          <ScrollArea className="thin-scrollbar flex-1">
            <div className="space-y-4 p-4">
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
                  <Search className="h-10 w-10 text-muted-foreground/30" />
                  <p className="text-sm text-muted-foreground">No rules match your filters</p>
                </div>
              ) : (
                Object.entries(grouped)
                  .sort(([a], [b]) => {
                    // When sorting by hits, the single _all group should come first
                    if (sortBy === "hits") return 0;
                    return CATEGORY_LABEL[a as keyof typeof CATEGORY_LABEL]?.localeCompare(
                      CATEGORY_LABEL[b as keyof typeof CATEGORY_LABEL] ?? b
                    ) ?? 0;
                  })
                  .map(([cat, rules]) => (
                    <div key={cat}>
                      {sortBy !== "hits" && (
                      <div className="mb-2 flex items-center gap-2">
                        <span
                          className="inline-block h-2 w-2 rounded-full"
                          style={{
                            backgroundColor:
                              CATEGORY_COLOR[cat as keyof typeof CATEGORY_COLOR] ?? "#6b7280",
                          }}
                        />
                        <h4 className="text-xs font-semibold uppercase tracking-wide text-foreground">
                          {CATEGORY_LABEL[cat as keyof typeof CATEGORY_LABEL] ?? cat}
                        </h4>
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {rules.filter((r) => !safeDisabled.has(r.id)).length}/{rules.length}
                        </span>
                        <div className="h-px flex-1 bg-border/60" />
                      </div>
                      )}
                      <div className="grid gap-1.5 sm:grid-cols-2">
                        {rules.map((r) => {
                          const s = SEVERITY_BADGE[r.severity];
                          const isOpen = expanded === r.id;
                          const isDisabled = safeDisabled.has(r.id);
                          const hit = ruleHits.get(r.id);
                          return (
                            <motion.div
                              key={r.id}
                              layout
                              className={`overflow-hidden rounded-lg border ${isDisabled ? "border-dashed opacity-50" : s.leftBorder} bg-card/40 transition-opacity`}
                            >
                              <div className="flex items-start">
                                <button
                                  onClick={() => setExpanded(isOpen ? null : r.id)}
                                  className="flex min-w-0 flex-1 items-start gap-2 px-3 py-2 text-left hover:bg-accent/30 transition-colors"
                                >
                                  <span
                                    className={`mt-1 inline-flex items-center rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${s.badge}`}
                                  >
                                    {SEVERITY_LABEL[r.severity].slice(0, 4)}
                                  </span>
                                  <div className="min-w-0 flex-1">
                                    <div className="flex items-center gap-1.5">
                                      <span className="font-mono text-[10px] text-muted-foreground">
                                        {r.id}
                                      </span>
                                      {isDisabled && (
                                        <span className="rounded bg-amber-500/15 px-1 py-0.5 text-[8px] font-bold uppercase text-amber-600 dark:text-amber-400">
                                          OFF
                                        </span>
                                      )}
                                      {hit && hit.hits > 0 && (
                                        <TooltipProvider delayDuration={200}>
                                          <Tooltip>
                                            <TooltipTrigger asChild>
                                              <span className="inline-flex items-center gap-0.5 rounded bg-emerald-500/10 px-1 py-0.5 text-[8px] font-bold uppercase text-emerald-600 dark:text-emerald-400">
                                                <Flame className="h-2.5 w-2.5" />
                                                {hit.hits}
                                              </span>
                                            </TooltipTrigger>
                                            <TooltipContent side="top" className="text-xs">
                                              <p>Triggered {hit.hits} time{hit.hits === 1 ? "" : "s"} in history</p>
                                              <p className="text-[10px] text-muted-foreground">
                                                Last seen: {new Date(hit.lastSeen).toLocaleString()}
                                              </p>
                                            </TooltipContent>
                                          </Tooltip>
                                        </TooltipProvider>
                                      )}
                                    </div>
                                    <p className="truncate text-xs font-medium text-foreground">
                                      {r.title}
                                    </p>
                                  </div>
                                </button>
                                {/* Toggle switch */}
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onToggleRule(r.id);
                                  }}
                                  className="flex shrink-0 items-center px-2 py-2 text-muted-foreground hover:text-foreground transition-colors"
                                  title={isDisabled ? "Enable this rule" : "Disable this rule"}
                                >
                                  {isDisabled ? (
                                    <ToggleLeft className="h-4 w-4 text-amber-500" />
                                  ) : (
                                    <ToggleRight className="h-4 w-4 text-emerald-500" />
                                  )}
                                </button>
                              </div>
                              <AnimatePresence initial={false}>
                                {isOpen && (
                                  <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: "auto", opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    transition={{ duration: 0.18 }}
                                    className="border-t border-border/60"
                                  >
                                    <div className="space-y-2 px-3 py-2.5">
                                      <p className="text-[11px] leading-relaxed text-foreground/80">
                                        {r.description}
                                      </p>
                                      <div className="rounded-md bg-emerald-500/5 px-2 py-1.5">
                                        <p className="text-[10px] font-semibold uppercase tracking-wide text-emerald-600 dark:text-emerald-400">
                                          Remediation
                                        </p>
                                        <p className="mt-0.5 text-[11px] leading-relaxed text-foreground/80">
                                          {r.remediation}
                                        </p>
                                      </div>
                                      {r.references && r.references.length > 0 && (
                                        <div className="flex flex-wrap gap-1">
                                          {r.references.map((ref) => (
                                            <span
                                              key={ref}
                                              className="rounded bg-muted px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground"
                                            >
                                              {ref}
                                            </span>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  </motion.div>
                                )}
                              </AnimatePresence>
                            </motion.div>
                          );
                        })}
                      </div>
                    </div>
                  ))
              )}
            </div>
          </ScrollArea>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
