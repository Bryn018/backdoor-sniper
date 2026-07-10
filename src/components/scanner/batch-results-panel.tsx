"use client";

import { motion, AnimatePresence } from "framer-motion";
import {
  Files,
  X,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  AlertTriangle,
  Loader2,
  ChevronDown,
  ChevronRight,
  FileCode2,
} from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import {
  SEVERITY_LABEL,
} from "@/lib/severity";
import type { Severity } from "@/lib/detector/types";

export interface BatchFileResult {
  fileName: string;
  riskScore?: number;
  verdict?: string;
  totalLines?: number;
  findingCount?: number;
  bySeverity?: Record<Severity, number>;
  topFindings?: Array<{
    ruleId: string;
    title: string;
    severity: Severity;
    category: string;
    line: number;
  }>;
  sourceHash?: string;
  error?: string;
}

export interface BatchResult {
  totalFiles: number;
  aggregateRisk: number;
  totalFindings: number;
  worstVerdict: string;
  results: BatchFileResult[];
}

interface BatchResultsPanelProps {
  result: BatchResult | null;
  loading: boolean;
  onClose: () => void;
  onFileOpen?: (file: BatchFileResult) => void;
}

const verdictIcon = (v?: string) => {
  switch (v) {
    case "dangerous": return <ShieldX className="h-4 w-4 text-red-500" />;
    case "malicious": return <ShieldAlert className="h-4 w-4 text-orange-500" />;
    case "suspicious": return <ShieldQuestion className="h-4 w-4 text-amber-500" />;
    case "clean": return <ShieldCheck className="h-4 w-4 text-emerald-500" />;
    default: return <AlertTriangle className="h-4 w-4 text-muted-foreground" />;
  }
};

const verdictColor = (v?: string) => {
  switch (v) {
    case "dangerous": return "text-red-500";
    case "malicious": return "text-orange-500";
    case "suspicious": return "text-amber-500";
    case "clean": return "text-emerald-500";
    default: return "text-muted-foreground";
  }
};

const verdictBorder = (v?: string) => {
  switch (v) {
    case "dangerous": return "border-l-red-500";
    case "malicious": return "border-l-orange-500";
    case "suspicious": return "border-l-amber-500";
    case "clean": return "border-l-emerald-500";
    default: return "border-l-muted-foreground";
  }
};

export function BatchResultsPanel({
  result,
  loading,
  onClose,
  onFileOpen,
}: BatchResultsPanelProps) {
  if (loading) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-8 text-center">
        <Loader2 className="h-10 w-10 animate-spin text-emerald-500" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-foreground">
            Scanning {result?.totalFiles ?? "…"} files…
          </p>
          <p className="text-xs text-muted-foreground">
            Running 70 detection rules per file
          </p>
        </div>
      </div>
    );
  }

  if (!result) return null;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header / aggregate verdict */}
      <div className={`border-b border-border bg-gradient-to-r ${
        result.worstVerdict === "dangerous" ? "from-red-500/10" :
        result.worstVerdict === "malicious" ? "from-orange-500/10" :
        result.worstVerdict === "suspicious" ? "from-amber-500/10" :
        "from-emerald-500/10"
      } to-transparent p-4`}>
        <div className="flex items-center gap-3">
          <div className={`flex h-12 w-12 items-center justify-center rounded-full ${
            result.worstVerdict === "dangerous" ? "bg-red-500/15" :
            result.worstVerdict === "malicious" ? "bg-orange-500/15" :
            result.worstVerdict === "suspicious" ? "bg-amber-500/15" :
            "bg-emerald-500/15"
          }`}>
            {verdictIcon(result.worstVerdict)}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className={`text-xl font-bold capitalize ${verdictColor(result.worstVerdict)}`}>
                {result.worstVerdict}
              </span>
              <Badge variant="outline" className="text-[10px]">
                <Files className="h-3 w-3" />
                {result.totalFiles} files
              </Badge>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Aggregate risk: <span className="font-mono font-bold text-foreground">{result.aggregateRisk}/100</span>
              {" · "}
              Total findings: <span className="font-mono font-bold text-foreground">{result.totalFindings}</span>
            </p>
          </div>
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* File list */}
      <div className="flex min-h-0 flex-1 flex-col">
        <div className="border-b border-border px-4 py-2">
          <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <FileCode2 className="h-3.5 w-3.5" />
            Files ({result.results.length})
          </h4>
        </div>
        <ScrollArea className="thin-scrollbar min-h-0 flex-1">
          <div className="space-y-2 p-3">
            {result.results.map((f, i) => (
              <FileResultCard
                key={`${f.fileName}-${i}`}
                file={f}
                index={i}
                onOpen={onFileOpen}
              />
            ))}
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}

function FileResultCard({
  file,
  index,
  onOpen,
}: {
  file: BatchFileResult;
  index: number;
  onOpen?: (file: BatchFileResult) => void;
}) {
  const [open, setOpen] = useState(file.verdict === "dangerous" || file.verdict === "malicious");

  if (file.error) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: Math.min(index * 0.03, 0.3) }}
        className="rounded-lg border border-l-2 border-border border-l-muted-foreground bg-card/40 p-3"
      >
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          <span className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">
            {file.fileName}
          </span>
          <Badge variant="outline" className="text-[10px] text-muted-foreground">
            {file.error}
          </Badge>
        </div>
      </motion.div>
    );
  }

  const sev = file.bySeverity ?? {};
  const hasFindings = (file.findingCount ?? 0) > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.03, 0.3) }}
      className={`overflow-hidden rounded-lg border border-border border-l-2 ${verdictBorder(file.verdict)} bg-card/40`}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left hover:bg-accent/30 transition-colors"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        )}
        {verdictIcon(file.verdict)}
        <span className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">
          {file.fileName}
        </span>
        <span className={`font-mono text-sm font-bold ${verdictColor(file.verdict)}`}>
          {file.riskScore ?? 0}
        </span>
        {hasFindings && (
          <Badge variant="outline" className="text-[10px]">
            {file.findingCount} finding{file.findingCount === 1 ? "" : "s"}
          </Badge>
        )}
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="border-t border-border/60"
          >
            <div className="space-y-2.5 px-3 py-2.5">
              {/* Stats row */}
              <div className="flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                <span className="rounded bg-muted/50 px-1.5 py-0.5 font-mono">
                  {file.totalLines ?? 0} lines
                </span>
                {file.sourceHash && (
                  <span className="rounded bg-muted/50 px-1.5 py-0.5 font-mono">
                    hash {file.sourceHash}
                  </span>
                )}
                <span className={`rounded px-1.5 py-0.5 font-mono capitalize ${verdictColor(file.verdict)}`}>
                  {file.verdict}
                </span>
              </div>

              {/* Severity mini bar */}
              {hasFindings && sev && (
                <div className="flex gap-0.5">
                  {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => {
                    const n = sev[s] ?? 0;
                    if (n === 0) return null;
                    const colors: Record<Severity, string> = {
                      critical: "bg-red-500",
                      high: "bg-orange-500",
                      medium: "bg-amber-500",
                      low: "bg-emerald-500",
                      info: "bg-slate-500",
                    };
                    return (
                      <div
                        key={s}
                        className={`${colors[s]} h-1.5 rounded-full`}
                        style={{ width: `${Math.max(8, n * 8)}px` }}
                        title={`${SEVERITY_LABEL[s]}: ${n}`}
                      />
                    );
                  })}
                </div>
              )}

              {/* Top findings */}
              {file.topFindings && file.topFindings.length > 0 ? (
                <div className="space-y-1">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Top findings
                  </p>
                  {file.topFindings.map((tf, j) => (
                    <div
                      key={j}
                      className="flex items-center gap-2 rounded bg-muted/30 px-2 py-1 text-[11px]"
                    >
                      <span
                        className={`inline-block h-1.5 w-1.5 rounded-full ${
                          tf.severity === "critical" ? "bg-red-500" :
                          tf.severity === "high" ? "bg-orange-500" :
                          tf.severity === "medium" ? "bg-amber-500" :
                          tf.severity === "low" ? "bg-emerald-500" : "bg-slate-500"
                        }`}
                      />
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {tf.ruleId}
                      </span>
                      <span className="min-w-0 flex-1 truncate text-foreground/80">
                        {tf.title}
                      </span>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        L{tf.line}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                !hasFindings && (
                  <p className="text-[11px] text-emerald-600 dark:text-emerald-400">
                    No suspicious patterns detected in this file.
                  </p>
                )
              )}

              {onOpen && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 w-full text-[11px] text-emerald-600 hover:text-emerald-700 dark:text-emerald-400"
                  onClick={() => onOpen(file)}
                >
                  View in main editor →
                </Button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
