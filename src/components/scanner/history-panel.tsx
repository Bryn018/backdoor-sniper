"use client";

import { useEffect, useState, useCallback } from "react";
import {
  History,
  Trash2,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  Filter,
  RotateCcw,
  Loader2,
  FileCode2,
  Clock,
  Search,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatDistanceToNow } from "date-fns";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "sonner";

interface HistoryRecord {
  id: string;
  sourceHash: string;
  fileName: string | null;
  riskScore: number;
  verdict: string;
  totalLines: number;
  sourcePreview: string | null;
  createdAt: string;
}

interface HistorySummary {
  total: number;
  dangerous: number;
  malicious: number;
  suspicious: number;
  clean: number;
  avgRisk: number;
}

interface HistoryPanelProps {
  refreshKey: number;
  onDeleted: () => void;
  onRestore?: (id: string) => void;
}

const verdictIcon = (v: string) => {
  switch (v) {
    case "dangerous":
      return <ShieldX className="h-3.5 w-3.5 text-red-500" />;
    case "malicious":
      return <ShieldAlert className="h-3.5 w-3.5 text-orange-500" />;
    case "suspicious":
      return <ShieldQuestion className="h-3.5 w-3.5 text-amber-500" />;
    default:
      return <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />;
  }
};

const verdictColor = (v: string) => {
  switch (v) {
    case "dangerous":
      return "text-red-500";
    case "malicious":
      return "text-orange-500";
    case "suspicious":
      return "text-amber-500";
    default:
      return "text-emerald-500";
  }
};

const verdictBorderColor = (v: string) => {
  switch (v) {
    case "dangerous":
      return "border-l-red-500";
    case "malicious":
      return "border-l-orange-500";
    case "suspicious":
      return "border-l-amber-500";
    default:
      return "border-l-emerald-500";
  }
};

const verdictBgColor = (v: string) => {
  switch (v) {
    case "dangerous":
      return "bg-red-500/5 hover:bg-red-500/10";
    case "malicious":
      return "bg-orange-500/5 hover:bg-orange-500/10";
    case "suspicious":
      return "bg-amber-500/5 hover:bg-amber-500/10";
    default:
      return "bg-emerald-500/5 hover:bg-emerald-500/10";
  }
};

export function HistoryPanel({
  refreshKey,
  onDeleted,
  onRestore,
}: HistoryPanelProps) {
  const [records, setRecords] = useState<HistoryRecord[]>([]);
  const [summary, setSummary] = useState<HistorySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");
  const [restoringId, setRestoringId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/history?limit=50");
      const data = await res.json();
      setRecords(data.records ?? []);
      setSummary(data.summary ?? null);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const del = async (id: string) => {
    await fetch(`/api/history/${id}`, { method: "DELETE" });
    load();
    onDeleted();
  };

  const restore = async (id: string) => {
    if (!onRestore) return;
    setRestoringId(id);
    try {
      await onRestore(id);
    } finally {
      setRestoringId(null);
    }
  };

  const filtered = records.filter((r) => {
    if (filter !== "all" && r.verdict !== filter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const name = (r.fileName || r.sourceHash).toLowerCase();
      return name.includes(q) || r.verdict.includes(q);
    }
    return true;
  });

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <History className="h-4 w-4 text-emerald-500" />
          Scan history
        </h3>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={load}
          disabled={loading}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
        </Button>
      </div>

      {summary && (
        <div className="grid grid-cols-4 gap-1.5 border-b border-border p-3">
          <Stat label="Total" value={summary.total} color="text-foreground" />
          <Stat label="Danger" value={summary.dangerous} color="text-red-500" />
          <Stat
            label="Malicious"
            value={summary.malicious}
            color="text-orange-500"
          />
          <Stat label="Clean" value={summary.clean} color="text-emerald-500" />
        </div>
      )}

      {/* Search + Filter */}
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="relative flex-1">
          <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by name…"
            className="h-7 w-full rounded-md border border-border bg-transparent pl-7 pr-2 text-[11px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
          />
        </div>
        <Filter className="h-3 w-3 text-muted-foreground" />
        <Select value={filter} onValueChange={setFilter}>
          <SelectTrigger className="h-7 w-[100px] text-[11px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all" className="text-[11px]">
              All
            </SelectItem>
            <SelectItem value="dangerous" className="text-[11px]">
              Dangerous
            </SelectItem>
            <SelectItem value="malicious" className="text-[11px]">
              Malicious
            </SelectItem>
            <SelectItem value="suspicious" className="text-[11px]">
              Suspicious
            </SelectItem>
            <SelectItem value="clean" className="text-[11px]">
              Clean
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-1.5 p-2">
          {filtered.length === 0 && !loading && (
            <p className="px-3 py-8 text-center text-xs text-muted-foreground">
              {records.length === 0
                ? "No scans yet. Run your first scan to populate history."
                : "No records match this filter."}
            </p>
          )}
          {filtered.map((r, idx) => (
            <motion.div
              key={r.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: Math.min(idx * 0.02, 0.2) }}
              className={`group relative rounded-lg border border-border/60 border-l-2 ${verdictBorderColor(r.verdict)} ${verdictBgColor(r.verdict)} p-2.5 transition-all`}
              onMouseEnter={() => setHoveredId(r.id)}
              onMouseLeave={() => setHoveredId(null)}
            >
              <div className="flex items-center gap-2">
                {verdictIcon(r.verdict)}
                <span
                  className={`font-mono text-sm font-bold ${verdictColor(r.verdict)}`}
                >
                  {r.riskScore}
                </span>
                <span className="min-w-0 flex-1 truncate text-xs text-foreground/80">
                  {r.fileName || `scan ${r.sourceHash.slice(0, 8)}`}
                </span>
                {onRestore && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100"
                    onClick={() => restore(r.id)}
                    disabled={restoringId === r.id}
                    title="Restore scan results"
                  >
                    {restoringId === r.id ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <RotateCcw className="h-3 w-3 text-muted-foreground" />
                    )}
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100"
                  onClick={() => {
                    del(r.id);
                    toast.success("Scan deleted from history");
                  }}
                >
                  <Trash2 className="h-3 w-3 text-muted-foreground" />
                </Button>
              </div>
              <div className="mt-1 flex items-center justify-between pl-6 font-mono text-[10px] text-muted-foreground">
                <div className="flex items-center gap-2">
                  <span className="capitalize">{r.verdict}</span>
                  <span className="inline-flex items-center gap-0.5">
                    <FileCode2 className="h-2.5 w-2.5" />
                    {r.totalLines}L
                  </span>
                </div>
                <span className="inline-flex items-center gap-0.5">
                  <Clock className="h-2.5 w-2.5" />
                  {formatDistanceToNow(new Date(r.createdAt))} ago
                </span>
              </div>

              {/* Source preview on hover */}
              <AnimatePresence>
                {hoveredId === r.id && r.sourcePreview && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    className="mt-2 overflow-hidden"
                  >
                    <pre className="max-h-24 overflow-y-auto rounded-md border border-border/40 bg-muted/30 p-2 font-mono text-[9px] leading-relaxed text-muted-foreground thin-scrollbar">
                      {r.sourcePreview.slice(0, 300)}
                      {r.sourcePreview.length > 300 ? "…" : ""}
                    </pre>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded bg-muted/40 px-2 py-1.5 text-center">
      <div className={`font-mono text-lg font-bold ${color}`}>{value}</div>
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
    </div>
  );
}
