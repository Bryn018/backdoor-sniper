"use client";

import { useEffect, useState, useCallback } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import {
  Activity,
  AlertOctagon,
  TrendingUp,
  FileStack,
  ShieldX,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  X,
  Loader2,
  Flame,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { CATEGORY_LABEL, CATEGORY_COLOR } from "@/lib/severity";
import { motion } from "framer-motion";

interface StatsData {
  summary: {
    total: number;
    totalFindings: number;
    totalLines: number;
    avgRisk: number;
    maxRisk: number;
    verdictCounts: {
      clean: number;
      suspicious: number;
      malicious: number;
      dangerous: number;
    };
  };
  severityCounts: Record<string, number>;
  topCategories: { category: string; count: number }[];
  timeline: {
    day: string;
    count: number;
    avgRisk: number;
    dangerous: number;
  }[];
}

interface StatsModalProps {
  open: boolean;
  onClose: () => void;
  refreshKey: number;
}

const VERDICT_PIE = [
  { key: "dangerous", label: "Dangerous", color: "#ef4444", icon: ShieldX },
  { key: "malicious", label: "Malicious", color: "#f97316", icon: ShieldAlert },
  {
    key: "suspicious",
    label: "Suspicious",
    color: "#f59e0b",
    icon: ShieldQuestion,
  },
  { key: "clean", label: "Clean", color: "#10b981", icon: ShieldCheck },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  info: "#64748b",
};

export function StatsModal({ open, onClose, refreshKey }: StatsModalProps) {
  const [data, setData] = useState<StatsData | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/stats");
      const d = await res.json();
      setData(d);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) load();
  }, [open, load, refreshKey]);

  if (!open) return null;

  const verdictPieData = data
    ? VERDICT_PIE.map((v) => ({
        name: v.label,
        value: data.summary.verdictCounts[v.key as keyof typeof data.summary.verdictCounts] ?? 0,
        color: v.color,
      })).filter((d) => d.value > 0)
    : [];

  const severityBarData = data
    ? Object.entries(data.severityCounts)
        .map(([sev, count]) => ({
          name: sev.charAt(0).toUpperCase() + sev.slice(1),
          count,
          color: SEVERITY_COLORS[sev] ?? "#64748b",
        }))
        .filter((d) => d.count > 0)
    : [];

  const categoryData = data
    ? data.topCategories.map((c) => ({
        name:
          CATEGORY_LABEL[c.category as keyof typeof CATEGORY_LABEL] ??
          c.category,
        count: c.count,
        color:
          CATEGORY_COLOR[c.category as keyof typeof CATEGORY_COLOR] ??
          "#6b7280",
      }))
    : [];

  const timelineData = data
    ? data.timeline.map((t) => ({
        day: t.day.slice(5), // MM-DD
        scans: t.count,
        avgRisk: t.avgRisk,
        dangerous: t.dangerous,
      }))
    : [];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="relative flex h-[90vh] w-[95vw] max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border bg-muted/30 px-5 py-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Activity className="h-4 w-4 text-emerald-500" />
            Scan Statistics
          </h3>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>

        {loading || !data ? (
          <div className="flex flex-1 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-emerald-500" />
          </div>
        ) : data.summary.total === 0 ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
            <Activity className="h-12 w-12 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">
              No scan data yet. Run some scans to populate statistics.
            </p>
          </div>
        ) : (
          <ScrollArea className="flex-1">
            <div className="space-y-5 p-5">
              {/* KPI cards */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <KpiCard
                  icon={FileStack}
                  label="Total Scans"
                  value={data.summary.total}
                  color="text-emerald-500"
                  accent="emerald"
                />
                <KpiCard
                  icon={AlertOctagon}
                  label="Total Findings"
                  value={data.summary.totalFindings}
                  color="text-orange-500"
                  accent="orange"
                />
                <KpiCard
                  icon={TrendingUp}
                  label="Avg Risk"
                  value={data.summary.avgRisk}
                  suffix="/100"
                  color="text-amber-500"
                  accent="amber"
                />
                <KpiCard
                  icon={Flame}
                  label="Max Risk"
                  value={data.summary.maxRisk}
                  suffix="/100"
                  color="text-red-500"
                  accent="red"
                />
              </div>

              {/* Timeline chart */}
              {timelineData.length > 0 && (
                <ChartCard title="Scan Activity Timeline" subtitle="Daily scan count vs. average risk score">
                  <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={timelineData} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                      <defs>
                        <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.45} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.4)" />
                      <XAxis
                        dataKey="day"
                        tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                        tickLine={false}
                        axisLine={{ stroke: "hsl(var(--border))" }}
                      />
                      <YAxis
                        tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                        tickLine={false}
                        axisLine={{ stroke: "hsl(var(--border))" }}
                        width={36}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "var(--popover)",
                          border: "1px solid var(--border)",
                          borderRadius: "8px",
                          fontSize: "12px",
                          color: "var(--popover-foreground)",
                        }}
                        labelStyle={{ color: "var(--popover-foreground)", fontWeight: 600 }}
                      />
                      <Legend wrapperStyle={{ fontSize: "11px", paddingTop: 4 }} iconType="circle" />
                      <Area
                        type="monotone"
                        dataKey="scans"
                        stroke="#10b981"
                        strokeWidth={2.5}
                        fill="url(#scanGrad)"
                        name="Scans"
                      />
                      <Area
                        type="monotone"
                        dataKey="avgRisk"
                        stroke="#f59e0b"
                        strokeWidth={2.5}
                        fill="url(#riskGrad)"
                        name="Avg Risk"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </ChartCard>
              )}

              {/* Verdict pie + severity bar */}
              <div className="grid gap-4 md:grid-cols-2">
                {verdictPieData.length > 0 && (
                  <ChartCard title="Verdict Distribution" subtitle="Final scan verdicts across all history">
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={verdictPieData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          outerRadius={68}
                          innerRadius={38}
                          paddingAngle={2}
                          stroke="hsl(var(--background))"
                          strokeWidth={2}
                        >
                          {verdictPieData.map((entry, i) => (
                            <Cell key={i} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "var(--popover)",
                            border: "1px solid var(--border)",
                            borderRadius: "8px",
                            fontSize: "12px",
                            color: "var(--popover-foreground)",
                          }}
                        />
                        <Legend
                          wrapperStyle={{ fontSize: "11px", paddingTop: 4 }}
                          iconType="circle"
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </ChartCard>
                )}

                {severityBarData.length > 0 && (
                  <ChartCard title="Findings by Severity" subtitle="Total findings broken down by severity tier">
                    <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={severityBarData} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.4)" vertical={false} />
                        <XAxis
                          dataKey="name"
                          tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                          tickLine={false}
                          axisLine={{ stroke: "hsl(var(--border))" }}
                        />
                        <YAxis
                          tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                          tickLine={false}
                          axisLine={{ stroke: "hsl(var(--border))" }}
                          allowDecimals={false}
                          width={36}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "var(--popover)",
                            border: "1px solid var(--border)",
                            borderRadius: "8px",
                            fontSize: "12px",
                            color: "var(--popover-foreground)",
                          }}
                          cursor={{ fill: "hsl(var(--muted) / 0.3)" }}
                        />
                        <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={56}>
                          {severityBarData.map((entry, i) => (
                            <Cell key={i} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </ChartCard>
                )}
              </div>

              {/* Category bar */}
              {categoryData.length > 0 && (
                <ChartCard title="Top Threat Categories" subtitle="Most frequently triggered rule categories">
                  <ResponsiveContainer width="100%" height={Math.max(200, categoryData.length * 36)}>
                    <BarChart
                      data={categoryData}
                      layout="vertical"
                      margin={{ top: 4, right: 12, left: 4, bottom: 4 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.4)" horizontal={false} />
                      <XAxis
                        type="number"
                        tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                        tickLine={false}
                        axisLine={{ stroke: "hsl(var(--border))" }}
                        allowDecimals={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                        tickLine={false}
                        axisLine={{ stroke: "hsl(var(--border))" }}
                        width={130}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "var(--popover)",
                          border: "1px solid var(--border)",
                          borderRadius: "8px",
                          fontSize: "12px",
                          color: "var(--popover-foreground)",
                        }}
                        cursor={{ fill: "hsl(var(--muted) / 0.3)" }}
                      />
                      <Bar dataKey="count" radius={[0, 6, 6, 0]} maxBarSize={28}>
                        {categoryData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </ChartCard>
              )}
            </div>
          </ScrollArea>
        )}
      </motion.div>
    </div>
  );
}

function KpiCard({
  icon: Icon,
  label,
  value,
  suffix,
  color,
  accent,
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  suffix?: string;
  color: string;
  accent?: "emerald" | "orange" | "amber" | "red" | "slate";
}) {
  const accentMap: Record<string, string> = {
    emerald: "from-emerald-500/10 to-transparent border-emerald-500/20",
    orange: "from-orange-500/10 to-transparent border-orange-500/20",
    amber: "from-amber-500/10 to-transparent border-amber-500/20",
    red: "from-red-500/10 to-transparent border-red-500/20",
    slate: "from-slate-500/10 to-transparent border-slate-500/20",
  };
  const accentClass = accent ? accentMap[accent] : "bg-muted/20 border-border";
  return (
    <div className={`relative overflow-hidden rounded-lg border bg-gradient-to-br p-3 ${accentClass}`}>
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
          {label}
        </span>
      </div>
      <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums">
        {value}
        {suffix && (
          <span className="ml-0.5 text-xs text-muted-foreground">{suffix}</span>
        )}
      </div>
    </div>
  );
}

function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-muted/10 p-4">
      <div className="mb-3">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          {title}
        </h4>
        {subtitle && (
          <p className="mt-0.5 text-[10px] text-muted-foreground/70">{subtitle}</p>
        )}
      </div>
      {children}
    </div>
  );
}
