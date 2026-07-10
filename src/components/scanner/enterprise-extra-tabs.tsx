"use client";

import { useState, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import {
  Webhook,
  Calendar,
  TrendingUp,
  Trash2,
  Plus,
  RefreshCw,
  Play,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Activity,
  Clock,
  Hash,
  Gauge,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { ALL_RULES } from "@/lib/detector";

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------
interface WebhookRow {
  id: string;
  name: string;
  url: string;
  sinkType: string;
  events: string[];
  signingSecret: string | null;
  enabled: boolean;
  lastStatus: string | null;
  lastDeliveryAt: string | null;
  lastError: string | null;
  successCount: number;
  failureCount: number;
  createdAt: string;
}

interface ScheduledScanRow {
  id: string;
  name: string;
  schedule: string;
  sourceType: string;
  sourceData: string;
  policyName: string | null;
  notifyOnFail: boolean;
  notifyOnCritical: boolean;
  enabled: boolean;
  lastRunAt: string | null;
  lastRunStatus: string | null;
  lastScanId: string | null;
  nextRunAt: string | null;
}

interface TrendsData {
  window: { days: number; since: string; until: string };
  summary: {
    totalScans: number;
    uniqueHashes: number;
    last24h: number;
    last7d: number;
    policyPassRate: number | null;
  };
  dailyScanVolume: { date: string; scans: number; criticalScans: number; avgRisk: number }[];
  topRules: { ruleId: string; title: string; hits: number; lastSeen: string }[];
  verdictBreakdown: { clean: number; suspicious: number; malicious: number; dangerous: number };
  severityBreakdown: { critical: number; high: number; medium: number; low: number; info: number };
  topCategories: { category: string; count: number }[];
  riskDistribution: { bucket: string; count: number }[];
  topScannedHashes: {
    sourceHash: string;
    fileName: string | null;
    scans: number;
    lastRisk: number;
    lastVerdict: string;
    lastScan: string;
  }[];
  scanModeBreakdown: { mode: string; count: number }[];
}

const SINK_TYPES = [
  { value: "generic", label: "Generic JSON POST" },
  { value: "slack", label: "Slack Incoming Webhook" },
  { value: "teams", label: "Microsoft Teams" },
  { value: "discord", label: "Discord Webhook" },
  { value: "splunk", label: "Splunk HEC" },
  { value: "datadog", label: "Datadog Events" },
  { value: "elasticsearch", label: "Elasticsearch" },
  { value: "pagerduty", label: "PagerDuty Events API v2" },
];

const EVENT_TYPES = [
  { value: "scan.run", label: "scan.run" },
  { value: "apikey.create", label: "apikey.create" },
  { value: "apikey.revoke", label: "apikey.revoke" },
  { value: "policy.create", label: "policy.create" },
  { value: "suppression.create", label: "suppression.create" },
  { value: "webhook.create", label: "webhook.create" },
  { value: "scheduledscan.run", label: "scheduledscan.run" },
  { value: "scheduledscan.create", label: "scheduledscan.create" },
  { value: "auth.denied", label: "auth.denied" },
];

const SCHEDULE_PRESETS = [
  { value: "every-15m", label: "Every 15 minutes" },
  { value: "every-30m", label: "Every 30 minutes" },
  { value: "every-1h", label: "Every hour" },
  { value: "every-6h", label: "Every 6 hours" },
  { value: "every-1d", label: "Every day" },
  { value: "0 2 * * *", label: "Daily at 02:00" },
  { value: "0 * * * 1", label: "Every Monday 00:00" },
  { value: "0 0 1 * *", label: "1st of month 00:00" },
];

// ---------------------------------------------------------------------------
// Trends tab — aggregated scan metrics + charts
// ---------------------------------------------------------------------------
export function TrendsTab() {
  const [data, setData] = useState<TrendsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [days, setDays] = useState(30);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/trends?days=${days}`);
      if (r.ok) setData(await r.json());
      else toast.error("Failed to load trends");
    } catch {
      toast.error("Network error loading trends");
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading && !data) {
    return (
      <div className="p-4 text-sm text-muted-foreground flex items-center gap-2">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading trends…
      </div>
    );
  }

  if (!data) return null;

  const maxDailyScans = Math.max(1, ...data.dailyScanVolume.map((d) => d.scans));
  const maxRiskBucket = Math.max(1, ...data.riskDistribution.map((d) => d.count));

  return (
    <ScrollArea className="h-full">
      <div className="p-4 space-y-5">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold flex items-center gap-1.5">
            <TrendingUp className="h-4 w-4 text-emerald-500" />
            Detection Trends ({data.window.days}d)
          </h3>
          <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
            <SelectTrigger className="h-7 w-28 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Summary KPI cards */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          <KpiCard icon={<Activity className="h-3.5 w-3.5" />} label="Total scans" value={data.summary.totalScans} accent="emerald" />
          <KpiCard icon={<Hash className="h-3.5 w-3.5" />} label="Unique files" value={data.summary.uniqueHashes} accent="sky" />
          <KpiCard icon={<Clock className="h-3.5 w-3.5" />} label="Last 24h" value={data.summary.last24h} accent="violet" />
          <KpiCard icon={<Calendar className="h-3.5 w-3.5" />} label="Last 7d" value={data.summary.last7d} accent="amber" />
          <KpiCard
            icon={<ShieldCheck className="h-3.5 w-3.5" />}
            label="Policy pass"
            value={data.summary.policyPassRate !== null ? `${data.summary.policyPassRate}%` : "—"}
            accent={data.summary.policyPassRate !== null && data.summary.policyPassRate >= 80 ? "emerald" : data.summary.policyPassRate !== null && data.summary.policyPassRate < 50 ? "rose" : "amber"}
          />
        </div>

        {/* Daily scan volume chart */}
        <Card title="Daily scan volume" subtitle="Bars: total scans · Line: avg risk score">
          {data.dailyScanVolume.length === 0 ? (
            <EmptyMini text="No scans in this window" />
          ) : (
            <div className="space-y-1.5">
              <div className="flex items-end gap-0.5 h-24">
                {data.dailyScanVolume.map((d) => {
                  const h = Math.round((d.scans / maxDailyScans) * 100);
                  const isCritical = d.criticalScans > 0;
                  return (
                    <div
                      key={d.date}
                      className="flex-1 group relative"
                      title={`${d.date}: ${d.scans} scans, ${d.criticalScans} critical, avg risk ${d.avgRisk}`}
                    >
                      <div
                        className={`w-full rounded-t ${isCritical ? "bg-rose-500/70" : "bg-emerald-500/70"} group-hover:bg-emerald-400 transition-colors`}
                        style={{ height: `${h}%` }}
                      />
                    </div>
                  );
                })}
              </div>
              <div className="flex justify-between text-[10px] text-muted-foreground font-mono">
                <span>{data.dailyScanVolume[0]?.date ?? ""}</span>
                <span>{data.dailyScanVolume[data.dailyScanVolume.length - 1]?.date ?? ""}</span>
              </div>
            </div>
          )}
        </Card>

        {/* Risk distribution histogram */}
        <Card title="Risk score distribution" subtitle="All scans bucketed by risk score">
          <div className="flex items-end gap-1 h-20">
            {data.riskDistribution.map((b) => {
              const h = Math.round((b.count / maxRiskBucket) * 100);
              const isHigh = Number(b.bucket.split("-")[0]) >= 70;
              return (
                <div key={b.bucket} className="flex-1 flex flex-col items-center gap-0.5" title={`${b.bucket}: ${b.count} scans`}>
                  <div
                    className={`w-full rounded-t ${isHigh ? "bg-rose-500/70" : Number(b.bucket.split("-")[0]) >= 40 ? "bg-amber-500/70" : "bg-emerald-500/70"}`}
                    style={{ height: `${h}%`, minHeight: b.count > 0 ? "2px" : 0 }}
                  />
                  <span className="text-[9px] text-muted-foreground font-mono">{b.bucket}</span>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Top rules by frequency */}
        <Card title="Top rules by frequency" subtitle="Most-frequently-firing detection rules">
          {data.topRules.length === 0 ? (
            <EmptyMini text="No findings recorded" />
          ) : (
            <div className="space-y-1">
              {data.topRules.map((r, i) => {
                const maxHits = data.topRules[0].hits || 1;
                const w = Math.round((r.hits / maxHits) * 100);
                return (
                  <div key={r.ruleId} className="flex items-center gap-2 text-xs">
                    <span className="w-5 text-muted-foreground font-mono text-[10px]">#{i + 1}</span>
                    <span className="font-mono text-[10px] text-emerald-600 dark:text-emerald-400 w-20 truncate">{r.ruleId}</span>
                    <div className="flex-1 h-4 bg-muted rounded overflow-hidden">
                      <div className="h-full bg-emerald-500/60" style={{ width: `${w}%` }} />
                    </div>
                    <span className="w-10 text-right font-mono text-[10px] font-semibold">{r.hits}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Verdict + severity breakdown */}
        <div className="grid grid-cols-2 gap-2">
          <Card title="Verdict breakdown">
            <div className="space-y-1 text-xs">
              {(["dangerous", "malicious", "suspicious", "clean"] as const).map((v) => {
                const count = data.verdictBreakdown[v];
                const total = data.summary.totalScans || 1;
                const pct = Math.round((count / total) * 100);
                const color =
                  v === "dangerous" ? "bg-rose-600" : v === "malicious" ? "bg-rose-500" : v === "suspicious" ? "bg-amber-500" : "bg-emerald-500";
                return (
                  <div key={v} className="flex items-center gap-2">
                    <span className="w-20 text-muted-foreground capitalize">{v}</span>
                    <div className="flex-1 h-3 bg-muted rounded overflow-hidden">
                      <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="w-10 text-right font-mono text-[10px]">{count} · {pct}%</span>
                  </div>
                );
              })}
            </div>
          </Card>
          <Card title="Severity breakdown">
            <div className="space-y-1 text-xs">
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
                const count = data.severityBreakdown[s];
                const color =
                  s === "critical" ? "bg-rose-600" : s === "high" ? "bg-rose-500" : s === "medium" ? "bg-amber-500" : s === "low" ? "bg-sky-500" : "bg-muted-foreground/40";
                return (
                  <div key={s} className="flex items-center gap-2">
                    <span className="w-16 text-muted-foreground capitalize">{s}</span>
                    <div className="flex-1 h-3 bg-muted rounded overflow-hidden">
                      <div className={`h-full ${color}`} style={{ width: `${Math.min(100, count * 5)}%` }} />
                    </div>
                    <span className="w-10 text-right font-mono text-[10px]">{count}</span>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>

        {/* Top scanned files + scan modes */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <Card title="Top scanned sources" subtitle="Most recurring source hashes">
            {data.topScannedHashes.length === 0 ? (
              <EmptyMini text="No scans recorded" />
            ) : (
              <div className="space-y-1 text-xs">
                {data.topScannedHashes.slice(0, 6).map((h) => (
                  <div key={h.sourceHash} className="flex items-center gap-2">
                    <Badge
                      variant="outline"
                      className={`text-[9px] font-mono px-1 ${
                        h.lastVerdict === "dangerous"
                          ? "border-rose-500 text-rose-600"
                          : h.lastVerdict === "suspicious"
                            ? "border-amber-500 text-amber-600"
                            : "border-emerald-500 text-emerald-600"
                      }`}
                    >
                      {h.lastRisk}
                    </Badge>
                    <span className="flex-1 truncate font-mono text-[10px] text-muted-foreground" title={h.fileName ?? h.sourceHash}>
                      {h.fileName ?? h.sourceHash.slice(0, 16)}
                    </span>
                    <span className="text-[10px] font-mono">×{h.scans}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
          <Card title="Scan sources" subtitle="By scan mode (manual/ci/cron/etc.)">
            {data.scanModeBreakdown.length === 0 ? (
              <EmptyMini text="No scan modes recorded" />
            ) : (
              <div className="space-y-1 text-xs">
                {data.scanModeBreakdown.map((m) => (
                  <div key={m.mode} className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] font-mono capitalize">{m.mode}</Badge>
                    <div className="flex-1 h-2 bg-muted rounded overflow-hidden">
                      <div className="h-full bg-sky-500/60" style={{ width: `${Math.min(100, (m.count / (data.summary.totalScans || 1)) * 100)}%` }} />
                    </div>
                    <span className="w-8 text-right font-mono text-[10px]">{m.count}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </ScrollArea>
  );
}

// ---------------------------------------------------------------------------
// Webhooks tab — outbound SIEM sink management
// ---------------------------------------------------------------------------
export function WebhooksTab() {
  const [hooks, setHooks] = useState<WebhookRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: "",
    url: "",
    sinkType: "slack",
    events: [] as string[],
    signingSecret: "",
  });
  const [testResult, setTestResult] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/webhooks");
      if (r.ok) {
        const d = await r.json();
        setHooks(d.rows ?? []);
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    if (!form.name.trim()) return toast.error("Name is required");
    if (!form.url.trim()) return toast.error("URL is required");
    try {
      const body: Record<string, unknown> = {
        name: form.name,
        url: form.url,
        sinkType: form.sinkType,
        events: form.events,
      };
      if (form.signingSecret) body.signingSecret = form.signingSecret;
      const r = await fetch("/api/webhooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (r.ok) {
        const d = await r.json();
        toast.success(`Webhook "${d.name}" created`);
        if (d.testDelivery) {
          const { delivered, succeeded, failed } = d.testDelivery;
          if (delivered === 0) {
            setTestResult("No endpoints matched this event (check events filter).");
          } else if (succeeded > 0) {
            setTestResult(`Test event delivered to ${succeeded} endpoint(s).`);
          } else {
            setTestResult(`Test event failed at ${failed} endpoint(s). Check the endpoint logs.`);
          }
        }
        setForm({ name: "", url: "", sinkType: "slack", events: [], signingSecret: "" });
        setShowCreate(false);
        load();
      } else {
        const e = await r.json().catch(() => ({}));
        toast.error(e.error ?? "Failed to create webhook");
      }
    } catch {
      toast.error("Network error creating webhook");
    }
  };

  const toggle = async (id: string, enabled: boolean) => {
    try {
      await fetch(`/api/webhooks/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !enabled }),
      });
      load();
    } catch {
      /* ignore */
    }
  };

  const remove = async (id: string, name: string) => {
    if (!confirm(`Delete webhook "${name}"?`)) return;
    try {
      await fetch(`/api/webhooks/${id}`, { method: "DELETE" });
      toast.success("Webhook deleted");
      load();
    } catch {
      /* ignore */
    }
  };

  return (
    <ScrollArea className="h-full">
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold flex items-center gap-1.5">
            <Webhook className="h-4 w-4 text-emerald-500" />
            Webhooks & SIEM Sinks ({hooks.length})
          </h3>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={load}>
              <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
            </Button>
            <Button size="sm" className="h-7 text-xs bg-emerald-600 hover:bg-emerald-700" onClick={() => setShowCreate((s) => !s)}>
              <Plus className="h-3.5 w-3.5 mr-1" /> New webhook
            </Button>
          </div>
        </div>

        {testResult && (
          <div className="text-xs p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300">
            {testResult}
          </div>
        )}

        {showCreate && (
          <div className="space-y-2 p-3 rounded-md border border-border bg-muted/30">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label className="text-xs">Name</Label>
                <Input className="h-8 text-xs" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="SOC Slack #alerts" />
              </div>
              <div>
                <Label className="text-xs">Sink type</Label>
                <Select value={form.sinkType} onValueChange={(v) => setForm({ ...form, sinkType: v })}>
                  <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SINK_TYPES.map((s) => (
                      <SelectItem key={s.value} value={s.value} className="text-xs">{s.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label className="text-xs">URL</Label>
              <Input className="h-8 text-xs font-mono" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://hooks.slack.com/services/..." />
            </div>
            <div>
              <Label className="text-xs">Signing secret (optional, HMAC-SHA256)</Label>
              <Input className="h-8 text-xs font-mono" value={form.signingSecret} onChange={(e) => setForm({ ...form, signingSecret: e.target.value })} placeholder="shared-secret-for-signature-verification" />
            </div>
            <div>
              <Label className="text-xs">Forward events (empty = all)</Label>
              <div className="flex flex-wrap gap-1 mt-1">
                {EVENT_TYPES.map((ev) => {
                  const active = form.events.includes(ev.value);
                  return (
                    <button
                      key={ev.value}
                      type="button"
                      onClick={() =>
                        setForm({
                          ...form,
                          events: active ? form.events.filter((x) => x !== ev.value) : [...form.events, ev.value],
                        })
                      }
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border transition-colors ${
                        active
                          ? "border-emerald-500 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                          : "border-border bg-background text-muted-foreground hover:border-emerald-500/50"
                      }`}
                    >
                      {ev.value}
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="flex gap-2 pt-1">
              <Button size="sm" className="h-7 text-xs bg-emerald-600 hover:bg-emerald-700" onClick={create}>
                Create & send test event
              </Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setShowCreate(false)}>Cancel</Button>
            </div>
          </div>
        )}

        {loading && hooks.length === 0 ? (
          <div className="text-xs text-muted-foreground p-4 text-center">
            <RefreshCw className="h-4 w-4 animate-spin inline mr-1" /> Loading…
          </div>
        ) : hooks.length === 0 ? (
          <div className="text-xs text-muted-foreground p-6 text-center border border-dashed border-border rounded-md">
            <Webhook className="h-6 w-6 mx-auto mb-2 opacity-50" />
            No webhook endpoints configured.
            <br />
            <span className="text-[10px]">Add a Slack / Splunk / Teams / Datadog / Discord / PagerDuty / generic endpoint to forward audit events in real time.</span>
          </div>
        ) : (
          <div className="space-y-2">
            {hooks.map((h) => {
              const sinkMeta = SINK_TYPES.find((s) => s.value === h.sinkType);
              const okRate = h.successCount + h.failureCount > 0
                ? Math.round((h.successCount / (h.successCount + h.failureCount)) * 100)
                : null;
              return (
                <div key={h.id} className="p-2.5 rounded-md border border-border bg-card">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm font-medium truncate">{h.name}</span>
                        <Badge variant="outline" className="text-[9px] font-mono uppercase">{h.sinkType}</Badge>
                        {!h.enabled && <Badge variant="outline" className="text-[9px] text-muted-foreground">DISABLED</Badge>}
                      </div>
                      <div className="text-[10px] font-mono text-muted-foreground truncate mt-0.5">{h.url}</div>
                      {h.events.length > 0 && (
                        <div className="flex flex-wrap gap-0.5 mt-1">
                          {h.events.slice(0, 5).map((e) => (
                            <span key={e} className="text-[9px] font-mono px-1 py-px rounded bg-muted text-muted-foreground">{e}</span>
                          ))}
                          {h.events.length > 5 && <span className="text-[9px] text-muted-foreground">+{h.events.length - 5}</span>}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <Switch checked={h.enabled} onCheckedChange={() => toggle(h.id, h.enabled)} />
                      <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-destructive" onClick={() => remove(h.id, h.name)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 mt-2 pt-2 border-t border-border text-[10px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      {h.lastStatus === "success" ? <CheckCircle2 className="h-3 w-3 text-emerald-500" /> : h.lastStatus === "failure" ? <XCircle className="h-3 w-3 text-rose-500" /> : <Clock className="h-3 w-3" />}
                      {h.lastDeliveryAt ? new Date(h.lastDeliveryAt).toLocaleString() : "never sent"}
                    </span>
                    <span className="text-emerald-600 dark:text-emerald-400">✓ {h.successCount}</span>
                    <span className="text-rose-600 dark:text-rose-400">✗ {h.failureCount}</span>
                    {okRate !== null && (
                      <span className={okRate >= 90 ? "text-emerald-600" : okRate >= 50 ? "text-amber-600" : "text-rose-600"}>
                        {okRate}% ok
                      </span>
                    )}
                    {h.signingSecret && <span className="font-mono">🔒 {h.signingSecret}</span>}
                  </div>
                  {h.lastError && (
                    <div className="text-[10px] text-rose-600 dark:text-rose-400 mt-1 font-mono break-all">{h.lastError}</div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </ScrollArea>
  );
}

// ---------------------------------------------------------------------------
// Scheduled scans tab — recurring scan jobs
// ---------------------------------------------------------------------------
export function ScheduledScansTab() {
  const [scans, setScans] = useState<ScheduledScanRow[]>([]);
  const [policies, setPolicies] = useState<{ name: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: "",
    schedule: "every-1d",
    sourceType: "paste",
    sourceData: "",
    policyName: "",
    notifyOnFail: true,
    notifyOnCritical: false,
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [r1, r2] = await Promise.all([
        fetch("/api/scheduled-scans"),
        fetch("/api/policies"),
      ]);
      if (r1.ok) {
        const d = await r1.json();
        setScans(d.rows ?? []);
      }
      if (r2.ok) {
        const d = await r2.json();
        setPolicies((d.policies ?? d.rows ?? []).map((p: { name: string }) => ({ name: p.name })));
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    if (!form.name.trim()) return toast.error("Name is required");
    if (!form.sourceData.trim()) return toast.error("Source is required");
    try {
      const body: Record<string, unknown> = {
        name: form.name,
        schedule: form.schedule,
        sourceType: form.sourceType,
        sourceData: form.sourceData,
        notifyOnFail: form.notifyOnFail,
        notifyOnCritical: form.notifyOnCritical,
      };
      if (form.policyName) body.policyName = form.policyName;
      const r = await fetch("/api/scheduled-scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (r.ok) {
        toast.success("Scheduled scan created");
        setForm({ name: "", schedule: "every-1d", sourceType: "paste", sourceData: "", policyName: "", notifyOnFail: true, notifyOnCritical: false });
        setShowCreate(false);
        load();
      } else {
        const e = await r.json().catch(() => ({}));
        toast.error(e.error ?? "Failed to create scheduled scan");
      }
    } catch {
      toast.error("Network error creating scheduled scan");
    }
  };

  const remove = async (id: string, name: string) => {
    if (!confirm(`Delete scheduled scan "${name}"?`)) return;
    try {
      await fetch(`/api/scheduled-scans/${id}`, { method: "DELETE" });
      toast.success("Scheduled scan deleted");
      load();
    } catch {
      /* ignore */
    }
  };

  const toggle = async (id: string, enabled: boolean) => {
    try {
      await fetch(`/api/scheduled-scans/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !enabled }),
      });
      load();
    } catch {
      /* ignore */
    }
  };

  const runNow = async (id: string) => {
    try {
      const r = await fetch(`/api/scheduled-scans/run?id=${id}`, { method: "POST" });
      if (r.ok) {
        const d = await r.json();
        toast.success(`Triggered: ${d.ran} ran, ${d.succeeded} succeeded, ${d.failed} failed`);
        load();
      } else {
        toast.error("Failed to trigger scan");
      }
    } catch {
      toast.error("Network error triggering scan");
    }
  };

  return (
    <ScrollArea className="h-full">
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold flex items-center gap-1.5">
            <Calendar className="h-4 w-4 text-emerald-500" />
            Scheduled Scans ({scans.length})
          </h3>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={load}>
              <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
            </Button>
            <Button size="sm" className="h-7 text-xs bg-emerald-600 hover:bg-emerald-700" onClick={() => setShowCreate((s) => !s)}>
              <Plus className="h-3.5 w-3.5 mr-1" /> New schedule
            </Button>
          </div>
        </div>

        <div className="text-[10px] p-2 rounded bg-sky-500/10 border border-sky-500/30 text-sky-700 dark:text-sky-300">
          <strong>How scheduling works:</strong> BackdoorSniper doesn't run a background timer — call <code className="font-mono">POST /api/scheduled-scans/run</code> from your CI/cron every minute to tick the scheduler. See the API docs.
        </div>

        {showCreate && (
          <div className="space-y-2 p-3 rounded-md border border-border bg-muted/30">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label className="text-xs">Name</Label>
                <Input className="h-8 text-xs" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Daily PyPI audit" />
              </div>
              <div>
                <Label className="text-xs">Schedule</Label>
                <Select value={form.schedule} onValueChange={(v) => setForm({ ...form, schedule: v })}>
                  <SelectTrigger className="h-8 text-xs font-mono"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCHEDULE_PRESETS.map((s) => (
                      <SelectItem key={s.value} value={s.value} className="text-xs font-mono">{s.label} ({s.value})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label className="text-xs">Source type</Label>
                <Select value={form.sourceType} onValueChange={(v) => setForm({ ...form, sourceType: v })}>
                  <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="paste" className="text-xs">Pasted source</SelectItem>
                    <SelectItem value="url" className="text-xs">Fetch from URL</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Policy (optional)</Label>
                <Select value={form.policyName} onValueChange={(v) => setForm({ ...form, policyName: v === "__none__" ? "" : v })}>
                  <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="No policy" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__" className="text-xs">— None —</SelectItem>
                    {policies.map((p) => (
                      <SelectItem key={p.name} value={p.name} className="text-xs">{p.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label className="text-xs">{form.sourceType === "url" ? "URL to fetch (.py or .txt)" : "Python source to scan"}</Label>
              {form.sourceType === "url" ? (
                <Input className="h-8 text-xs font-mono" value={form.sourceData} onChange={(e) => setForm({ ...form, sourceData: e.target.value })} placeholder="https://raw.githubusercontent.com/.../main/malicious.py" />
              ) : (
                <Textarea className="text-xs font-mono min-h-[100px] max-h-[200px]" value={form.sourceData} onChange={(e) => setForm({ ...form, sourceData: e.target.value })} placeholder="import socket…" />
              )}
            </div>
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                <Switch checked={form.notifyOnFail} onCheckedChange={(c) => setForm({ ...form, notifyOnFail: c })} />
                Notify on policy fail
              </label>
              <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                <Switch checked={form.notifyOnCritical} onCheckedChange={(c) => setForm({ ...form, notifyOnCritical: c })} />
                Notify on critical findings
              </label>
            </div>
            <div className="flex gap-2 pt-1">
              <Button size="sm" className="h-7 text-xs bg-emerald-600 hover:bg-emerald-700" onClick={create}>Create schedule</Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setShowCreate(false)}>Cancel</Button>
            </div>
          </div>
        )}

        {loading && scans.length === 0 ? (
          <div className="text-xs text-muted-foreground p-4 text-center">
            <RefreshCw className="h-4 w-4 animate-spin inline mr-1" /> Loading…
          </div>
        ) : scans.length === 0 ? (
          <div className="text-xs text-muted-foreground p-6 text-center border border-dashed border-border rounded-md">
            <Calendar className="h-6 w-6 mx-auto mb-2 opacity-50" />
            No scheduled scans configured.
            <br />
            <span className="text-[10px]">Recurring scans of pasted source or remote URLs — useful for monitoring upstream PyPI packages for backdoor insertion.</span>
          </div>
        ) : (
          <div className="space-y-2">
            {scans.map((s) => {
              const lastStatusColor =
                s.lastRunStatus === "success" ? "text-emerald-600" : s.lastRunStatus === "failure" ? "text-rose-600" : "text-muted-foreground";
              return (
                <div key={s.id} className="p-2.5 rounded-md border border-border bg-card">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm font-medium truncate">{s.name}</span>
                        {!s.enabled && <Badge variant="outline" className="text-[9px] text-muted-foreground">DISABLED</Badge>}
                        {s.policyName && <Badge variant="outline" className="text-[9px] font-mono">policy: {s.policyName}</Badge>}
                      </div>
                      <div className="flex flex-wrap items-center gap-2 mt-0.5 text-[10px] font-mono text-muted-foreground">
                        <span className="px-1.5 py-0.5 rounded bg-muted">{s.schedule}</span>
                        <span className="px-1.5 py-0.5 rounded bg-muted uppercase">{s.sourceType}</span>
                        <span className="truncate max-w-[180px]" title={s.sourceData}>{s.sourceData.slice(0, 40)}{s.sourceData.length > 40 ? "…" : ""}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => runNow(s.id)}>
                        <Play className="h-3 w-3 mr-1" /> Run now
                      </Button>
                      <Switch checked={s.enabled} onCheckedChange={() => toggle(s.id, s.enabled)} />
                      <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-destructive" onClick={() => remove(s.id, s.name)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 mt-2 pt-2 border-t border-border text-[10px] text-muted-foreground">
                    <span>
                      <span className="font-mono">Last run:</span>{" "}
                      <span className={lastStatusColor}>
                        {s.lastRunAt ? `${new Date(s.lastRunAt).toLocaleString()} (${s.lastRunStatus ?? "unknown"})` : "never"}
                      </span>
                    </span>
                    <span>
                      <span className="font-mono">Next:</span>{" "}
                      {s.nextRunAt ? new Date(s.nextRunAt).toLocaleString() : "—"}
                    </span>
                    {s.notifyOnFail && <span className="text-rose-600 dark:text-rose-400" title="Will fire webhook on policy failure">⚠ on-fail</span>}
                    {s.notifyOnCritical && <span className="text-amber-600 dark:text-amber-400" title="Will fire webhook on critical findings">⚠ on-critical</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </ScrollArea>
  );
}

// ---------------------------------------------------------------------------
// Small presentational helpers
// ---------------------------------------------------------------------------
function KpiCard({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  accent: "emerald" | "sky" | "violet" | "amber" | "rose";
}) {
  const accentClass = {
    emerald: "text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
    sky: "text-sky-600 dark:text-sky-400 border-sky-500/30 bg-sky-500/5",
    violet: "text-violet-600 dark:text-violet-400 border-violet-500/30 bg-violet-500/5",
    amber: "text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/5",
    rose: "text-rose-600 dark:text-rose-400 border-rose-500/30 bg-rose-500/5",
  }[accent];
  return (
    <div className={`rounded-md border p-2 ${accentClass}`}>
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
        {icon} {label}
      </div>
      <div className="text-lg font-bold mt-0.5 tabular-nums">{value}</div>
    </div>
  );
}

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-card p-3">
      <div className="flex items-baseline justify-between mb-2">
        <h4 className="text-xs font-semibold">{title}</h4>
        {subtitle && <span className="text-[10px] text-muted-foreground">{subtitle}</span>}
      </div>
      {children}
    </div>
  );
}

function EmptyMini({ text }: { text: string }) {
  return <div className="text-[10px] text-muted-foreground italic text-center py-3">{text}</div>;
}
