"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  KeyRound,
  ScrollText,
  ShieldCheck,
  Ban,
  ClipboardCopy,
  CheckCircle2,
  XCircle,
  Trash2,
  Plus,
  RefreshCw,
  Building2,
  AlertTriangle,
  Clock,
  Activity,
  Lock,
  Webhook,
  Calendar,
  TrendingUp,
} from "lucide-react";
import type { ScanResult } from "@/lib/detector/types";
import { ALL_RULES } from "@/lib/detector";
import { TrendsTab, WebhooksTab, ScheduledScansTab } from "./enterprise-extra-tabs";

interface EnterprisePanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  lastResult: ScanResult | null;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface ApiKeyRow {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdBy: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  expiresAt: string | null;
  useCount: number;
}

interface AuditRow {
  id: string;
  createdAt: string;
  actorType: string;
  actorId: string | null;
  actorName: string | null;
  actorIp: string | null;
  action: string;
  target: string | null;
  outcome: string;
  verdict: string | null;
  riskScore: number | null;
  policyPassed: boolean | null;
  metadata: unknown;
}

interface PolicyRow {
  id: string;
  name: string;
  description: string | null;
  rules: {
    maxRiskScore?: number;
    blockedSeverities?: string[];
    blockedRuleIds?: string[];
    maxFindings?: number;
    blockOnVerdict?: string[];
  };
  isDefault: boolean;
  createdBy: string;
  createdAt: string;
}

interface SuppressionRow {
  id: string;
  ruleId: string;
  sourceHash: string | null;
  fileName: string | null;
  line: number | null;
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
}

const ALL_SCOPES = ["scan:run", "scan:read", "policy:manage", "apikey:manage", "admin"];
const ALL_SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ALL_VERDICTS = ["dangerous", "malicious", "suspicious", "clean"];

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export function EnterprisePanel({ open, onOpenChange, lastResult }: EnterprisePanelProps) {
  const [tab, setTab] = useState("keys");

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-4xl p-0 flex flex-col overflow-hidden">
        <SheetHeader className="px-5 py-4 border-b border-border bg-gradient-to-r from-emerald-500/5 to-transparent">
          <SheetTitle className="flex items-center gap-2 text-base">
            <Building2 className="h-5 w-5 text-emerald-500" />
            Enterprise Console
            <Badge variant="outline" className="ml-1 text-[10px] font-mono">
              PROD-READY · v2.1
            </Badge>
          </SheetTitle>
        </SheetHeader>
        <Tabs value={tab} onValueChange={setTab} className="flex-1 flex flex-col overflow-hidden">
          <TabsList className="mx-4 mt-3 flex flex-wrap h-auto gap-1 bg-muted/50 p-1">
            <TabsTrigger value="keys" className="text-xs gap-1 flex-1 min-w-[80px]">
              <KeyRound className="h-3.5 w-3.5" /> Keys
            </TabsTrigger>
            <TabsTrigger value="audit" className="text-xs gap-1 flex-1 min-w-[80px]">
              <ScrollText className="h-3.5 w-3.5" /> Audit
            </TabsTrigger>
            <TabsTrigger value="policy" className="text-xs gap-1 flex-1 min-w-[80px]">
              <ShieldCheck className="h-3.5 w-3.5" /> Policy
            </TabsTrigger>
            <TabsTrigger value="suppress" className="text-xs gap-1 flex-1 min-w-[80px]">
              <Ban className="h-3.5 w-3.5" /> Baseline
            </TabsTrigger>
            <TabsTrigger value="compliance" className="text-xs gap-1 flex-1 min-w-[80px]">
              <Lock className="h-3.5 w-3.5" /> Compliance
            </TabsTrigger>
            <TabsTrigger value="webhooks" className="text-xs gap-1 flex-1 min-w-[80px]">
              <Webhook className="h-3.5 w-3.5" /> Webhooks
            </TabsTrigger>
            <TabsTrigger value="schedules" className="text-xs gap-1 flex-1 min-w-[80px]">
              <Calendar className="h-3.5 w-3.5" /> Schedules
            </TabsTrigger>
            <TabsTrigger value="trends" className="text-xs gap-1 flex-1 min-w-[80px]">
              <TrendingUp className="h-3.5 w-3.5" /> Trends
            </TabsTrigger>
          </TabsList>
          <TabsContent value="keys" className="flex-1 overflow-hidden mt-0">
            <ApiKeysTab />
          </TabsContent>
          <TabsContent value="audit" className="flex-1 overflow-hidden mt-0">
            <AuditTab />
          </TabsContent>
          <TabsContent value="policy" className="flex-1 overflow-hidden mt-0">
            <PolicyTab />
          </TabsContent>
          <TabsContent value="suppress" className="flex-1 overflow-hidden mt-0">
            <SuppressionTab />
          </TabsContent>
          <TabsContent value="compliance" className="flex-1 overflow-hidden mt-0">
            <ComplianceTab lastResult={lastResult} />
          </TabsContent>
          <TabsContent value="webhooks" className="flex-1 overflow-hidden mt-0">
            <WebhooksTab />
          </TabsContent>
          <TabsContent value="schedules" className="flex-1 overflow-hidden mt-0">
            <ScheduledScansTab />
          </TabsContent>
          <TabsContent value="trends" className="flex-1 overflow-hidden mt-0">
            <TrendsTab />
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------
// API Keys tab
// ---------------------------------------------------------------------------
function ApiKeysTab() {
  const [keys, setKeys] = useState<ApiKeyRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", scopes: ["scan:run", "scan:read"], expiresInDays: "" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/api-keys");
      if (r.ok) {
        const d = await r.json();
        setKeys(d.keys ?? []);
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
    if (!form.name.trim()) {
      toast.error("Key name is required");
      return;
    }
    try {
      const body: Record<string, unknown> = { name: form.name, scopes: form.scopes };
      if (form.expiresInDays) body.expiresInDays = Number(form.expiresInDays);
      const r = await fetch("/api/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (r.ok) {
        const d = await r.json();
        setNewKey(d.fullKey);
        setForm({ name: "", scopes: ["scan:run", "scan:read"], expiresInDays: "" });
        setShowCreate(false);
        toast.success(`API key "${d.name}" created`);
        load();
      } else {
        const e = await r.json().catch(() => ({}));
        toast.error(e.error ?? "Failed to create key");
      }
    } catch {
      toast.error("Network error creating key");
    }
  };

  const revoke = async (id: string, name: string) => {
    if (!confirm(`Revoke API key "${name}"? This cannot be undone.`)) return;
    try {
      const r = await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
      if (r.ok) {
        toast.success("Key revoked");
        load();
      } else {
        toast.error("Failed to revoke key");
      }
    } catch {
      toast.error("Network error");
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="text-xs text-muted-foreground">
          {keys.length} key{keys.length !== 1 ? "s" : ""} · hashed at rest (SHA-256)
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={load} disabled={loading} className="h-8">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </Button>
          <Button size="sm" onClick={() => setShowCreate((s) => !s)} className="h-8 gap-1.5">
            <Plus className="h-3.5 w-3.5" /> New key
          </Button>
        </div>
      </div>

      {showCreate && (
        <div className="border-b border-border bg-muted/30 p-4 space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs">Key name</Label>
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. github-actions-prod"
              className="h-8 text-sm"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Scopes</Label>
            <div className="flex flex-wrap gap-3">
              {ALL_SCOPES.map((s) => (
                <label key={s} className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <Checkbox
                    checked={form.scopes.includes(s)}
                    onCheckedChange={(c) =>
                      setForm({
                        ...form,
                        scopes: c
                          ? [...form.scopes, s]
                          : form.scopes.filter((x) => x !== s),
                      })
                    }
                  />
                  <span className="font-mono">{s}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="flex items-end gap-2">
            <div className="space-y-1.5 flex-1">
              <Label className="text-xs">Expires in (days, optional)</Label>
              <Input
                type="number"
                value={form.expiresInDays}
                onChange={(e) => setForm({ ...form, expiresInDays: e.target.value })}
                placeholder="90"
                className="h-8 text-sm"
              />
            </div>
            <Button size="sm" onClick={create} className="h-8">
              Generate key
            </Button>
          </div>
        </div>
      )}

      {newKey && (
        <div className="border-b border-emerald-500/30 bg-emerald-500/5 p-4 space-y-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
            <AlertTriangle className="h-4 w-4" />
            Copy your API key now — it will NOT be shown again.
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded bg-background border border-border px-2 py-1.5 text-xs font-mono break-all">
              {newKey}
            </code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                navigator.clipboard.writeText(newKey);
                toast.success("Copied to clipboard");
              }}
              className="h-8 shrink-0"
            >
              <ClipboardCopy className="h-3.5 w-3.5" />
            </Button>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setNewKey(null)} className="h-7 text-xs">
            Dismiss
          </Button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2">
        {keys.length === 0 && !loading && (
          <div className="text-center py-12 text-sm text-muted-foreground">
            <KeyRound className="h-10 w-10 mx-auto mb-3 opacity-30" />
            No API keys yet. Create one to enable CI/CD integration.
          </div>
        )}
        {keys.map((k) => (
          <div
            key={k.id}
            className="rounded-lg border border-border bg-card p-3 space-y-2 hover:border-emerald-500/30 transition-colors"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm truncate">{k.name}</span>
                  {k.revokedAt && (
                    <Badge variant="destructive" className="text-[10px]">REVOKED</Badge>
                  )}
                </div>
                <code className="text-xs text-muted-foreground font-mono">{k.prefix}…</code>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => revoke(k.id, k.name)}
                className="h-7 text-xs text-red-500 hover:text-red-600 hover:bg-red-500/10"
                disabled={!!k.revokedAt}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="flex flex-wrap gap-1">
              {k.scopes.map((s) => (
                <Badge key={s} variant="outline" className="text-[10px] font-mono">
                  {s}
                </Badge>
              ))}
            </div>
            <div className="flex items-center gap-3 text-[10px] text-muted-foreground font-mono">
              <span className="flex items-center gap-1">
                <Activity className="h-3 w-3" /> {k.useCount} uses
              </span>
              {k.lastUsedAt && (
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" /> {timeAgo(k.lastUsedAt)}
                </span>
              )}
              {k.expiresAt && (
                <span className="text-amber-500">expires {timeAgo(k.expiresAt)}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit tab
// ---------------------------------------------------------------------------
function AuditTab() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [action, setAction] = useState("all");
  const [offset, setOffset] = useState(0);
  const LIMIT = 50;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
      if (action !== "all") params.set("action", action);
      const r = await fetch(`/api/audit?${params}`);
      if (r.ok) {
        const d = await r.json();
        setRows(d.rows ?? []);
        setTotal(d.total ?? 0);
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, [action, offset]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <Select value={action} onValueChange={(v) => { setAction(v); setOffset(0); }}>
          <SelectTrigger className="h-8 w-44 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All actions</SelectItem>
            <SelectItem value="scan.run">scan.run</SelectItem>
            <SelectItem value="apikey.create">apikey.create</SelectItem>
            <SelectItem value="apikey.revoke">apikey.revoke</SelectItem>
            <SelectItem value="policy.create">policy.create</SelectItem>
            <SelectItem value="suppression.create">suppression.create</SelectItem>
            <SelectItem value="auth.denied">auth.denied</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto text-xs text-muted-foreground font-mono">
          {total} entr{total !== 1 ? "ies" : "y"}
        </div>
        <Button size="sm" variant="ghost" onClick={load} disabled={loading} className="h-8">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-card border-b border-border">
            <tr className="text-left text-muted-foreground">
              <th className="px-3 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Action</th>
              <th className="px-3 py-2 font-medium">Actor</th>
              <th className="px-3 py-2 font-medium">Result</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b border-border/50 hover:bg-muted/30">
                <td className="px-3 py-2 font-mono text-[10px] text-muted-foreground whitespace-nowrap">
                  {new Date(r.createdAt).toLocaleTimeString()}
                </td>
                <td className="px-3 py-2">
                  <code className="font-mono text-[11px]">{r.action}</code>
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-col">
                    <span className="text-[11px]">{r.actorName ?? r.actorType}</span>
                    {r.actorIp && (
                      <span className="text-[10px] text-muted-foreground font-mono">{r.actorIp}</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2">
                  {r.outcome === "success" ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                  ) : r.outcome === "denied" ? (
                    <Ban className="h-3.5 w-3.5 text-red-500" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-amber-500" />
                  )}
                  {r.verdict && (
                    <Badge
                      variant="outline"
                      className={`ml-1.5 text-[9px] ${verdictColor(r.verdict)}`}
                    >
                      {r.verdict} · {r.riskScore}
                    </Badge>
                  )}
                  {r.policyPassed === false && (
                    <Badge variant="destructive" className="ml-1.5 text-[9px]">POLICY FAIL</Badge>
                  )}
                </td>
              </tr>
            ))}
            {rows.length === 0 && !loading && (
              <tr>
                <td colSpan={4} className="text-center py-12 text-muted-foreground">
                  <ScrollText className="h-10 w-10 mx-auto mb-3 opacity-30" />
                  No audit entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {total > LIMIT && (
        <div className="flex items-center justify-between px-4 py-2 border-t border-border text-xs">
          <Button
            size="sm"
            variant="outline"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - LIMIT))}
            className="h-7"
          >
            Prev
          </Button>
          <span className="font-mono text-muted-foreground">
            {offset + 1}–{Math.min(offset + LIMIT, total)}
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={offset + LIMIT >= total}
            onClick={() => setOffset(offset + LIMIT)}
            className="h-7"
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Policy tab
// ---------------------------------------------------------------------------
function PolicyTab() {
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: "",
    description: "",
    maxRiskScore: "",
    blockedSeverities: ["critical"] as string[],
    blockOnVerdict: ["dangerous"] as string[],
    isDefault: false,
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/policies");
      if (r.ok) {
        const d = await r.json();
        setPolicies(d.policies ?? []);
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
    if (!form.name.trim()) {
      toast.error("Policy name is required");
      return;
    }
    try {
      const rules: Record<string, unknown> = {};
      if (form.maxRiskScore) rules.maxRiskScore = Number(form.maxRiskScore);
      if (form.blockedSeverities.length) rules.blockedSeverities = form.blockedSeverities;
      if (form.blockOnVerdict.length) rules.blockOnVerdict = form.blockOnVerdict;
      const r = await fetch("/api/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: form.name,
          description: form.description,
          rules,
          isDefault: form.isDefault,
        }),
      });
      if (r.ok) {
        toast.success(`Policy "${form.name}" created`);
        setForm({
          name: "",
          description: "",
          maxRiskScore: "",
          blockedSeverities: ["critical"],
          blockOnVerdict: ["dangerous"],
          isDefault: false,
        });
        setShowCreate(false);
        load();
      } else {
        const e = await r.json().catch(() => ({}));
        toast.error(e.error ?? "Failed to create policy");
      }
    } catch {
      toast.error("Network error");
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="text-xs text-muted-foreground">
          {policies.length} polic{policies.length !== 1 ? "ies" : "y"} · CI/CD gating
        </div>
        <Button size="sm" onClick={() => setShowCreate((s) => !s)} className="h-8 gap-1.5">
          <Plus className="h-3.5 w-3.5" /> New policy
        </Button>
      </div>

      {showCreate && (
        <div className="border-b border-border bg-muted/30 p-4 space-y-3">
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Policy name</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="strict-ci"
                className="h-8 text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Max risk score (optional)</Label>
              <Input
                type="number"
                value={form.maxRiskScore}
                onChange={(e) => setForm({ ...form, maxRiskScore: e.target.value })}
                placeholder="50"
                className="h-8 text-sm"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Description</Label>
            <Input
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="Block on any critical finding"
              className="h-8 text-sm"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Block on severities</Label>
            <div className="flex flex-wrap gap-3">
              {ALL_SEVERITIES.map((s) => (
                <label key={s} className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <Checkbox
                    checked={form.blockedSeverities.includes(s)}
                    onCheckedChange={(c) =>
                      setForm({
                        ...form,
                        blockedSeverities: c
                          ? [...form.blockedSeverities, s]
                          : form.blockedSeverities.filter((x) => x !== s),
                      })
                    }
                  />
                  <span className="font-mono">{s}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Block on verdict</Label>
            <div className="flex flex-wrap gap-3">
              {ALL_VERDICTS.map((v) => (
                <label key={v} className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <Checkbox
                    checked={form.blockOnVerdict.includes(v)}
                    onCheckedChange={(c) =>
                      setForm({
                        ...form,
                        blockOnVerdict: c
                          ? [...form.blockOnVerdict, v]
                          : form.blockOnVerdict.filter((x) => x !== v),
                      })
                    }
                  />
                  <span className="font-mono">{v}</span>
                </label>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2 text-xs cursor-pointer">
            <Checkbox
              checked={form.isDefault}
              onCheckedChange={(c) => setForm({ ...form, isDefault: !!c })}
            />
            Set as default policy
          </label>
          <Button size="sm" onClick={create} className="w-full h-8">
            Create policy
          </Button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2">
        {policies.length === 0 && !loading && (
          <div className="rounded-lg border border-dashed border-border p-6 text-center">
            <ShieldCheck className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm font-medium mb-1">No custom policies</p>
            <p className="text-xs text-muted-foreground mb-3">
              The default policy blocks on any <code className="font-mono">critical</code> finding
              or a <code className="font-mono">dangerous</code> verdict. Create a custom policy for
              stricter CI/CD gating.
            </p>
          </div>
        )}
        {policies.map((p) => (
          <div
            key={p.id}
            className="rounded-lg border border-border bg-card p-3 space-y-2 hover:border-emerald-500/30 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm">{p.name}</span>
              {p.isDefault && (
                <Badge className="text-[10px] bg-emerald-600">DEFAULT</Badge>
              )}
            </div>
            {p.description && <p className="text-xs text-muted-foreground">{p.description}</p>}
            <div className="flex flex-wrap gap-1">
              {p.rules.maxRiskScore !== undefined && (
                <Badge variant="outline" className="text-[10px] font-mono">
                  risk ≤ {p.rules.maxRiskScore}
                </Badge>
              )}
              {p.rules.blockedSeverities?.map((s) => (
                <Badge key={s} variant="outline" className="text-[10px] font-mono">
                  block {s}
                </Badge>
              ))}
              {p.rules.blockOnVerdict?.map((v) => (
                <Badge key={v} variant="outline" className="text-[10px] font-mono">
                  block {v}
                </Badge>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Suppression tab
// ---------------------------------------------------------------------------
function SuppressionTab() {
  const [rows, setRows] = useState<SuppressionRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    ruleId: "",
    sourceHash: "",
    line: "",
    reason: "",
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/suppressions");
      if (r.ok) {
        const d = await r.json();
        setRows(d.suppressions ?? []);
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
    if (!form.ruleId.trim()) {
      toast.error("Rule ID is required");
      return;
    }
    try {
      const body: Record<string, unknown> = {
        ruleId: form.ruleId,
        reason: form.reason || "Accepted risk (baseline).",
      };
      if (form.sourceHash) body.sourceHash = form.sourceHash;
      if (form.line) body.line = Number(form.line);
      const r = await fetch("/api/suppressions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (r.ok) {
        toast.success("Suppression added to baseline");
        setForm({ ruleId: "", sourceHash: "", line: "", reason: "" });
        setShowCreate(false);
        load();
      } else {
        const e = await r.json().catch(() => ({}));
        toast.error(e.error ?? "Failed to create suppression");
      }
    } catch {
      toast.error("Network error");
    }
  };

  const remove = async (id: string) => {
    if (!confirm("Remove this suppression?")) return;
    try {
      const r = await fetch(`/api/suppressions?id=${id}`, { method: "DELETE" });
      if (r.ok) {
        toast.success("Suppression removed");
        load();
      }
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="text-xs text-muted-foreground">
          {rows.length} baseline suppression{rows.length !== 1 ? "s" : ""}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={load} disabled={loading} className="h-8">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </Button>
          <Button size="sm" onClick={() => setShowCreate((s) => !s)} className="h-8 gap-1.5">
            <Plus className="h-3.5 w-3.5" /> Suppress
          </Button>
        </div>
      </div>

      {showCreate && (
        <div className="border-b border-border bg-muted/30 p-4 space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs">Rule ID</Label>
            <Select value={form.ruleId} onValueChange={(v) => setForm({ ...form, ruleId: v })}>
              <SelectTrigger className="h-8 text-sm">
                <SelectValue placeholder="Select a rule…" />
              </SelectTrigger>
              <SelectContent className="max-h-72">
                {ALL_RULES.map((r) => (
                  <SelectItem key={r.id} value={r.id} className="text-xs">
                    <span className="font-mono">{r.id}</span> · {r.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Source hash (optional = global)</Label>
              <Input
                value={form.sourceHash}
                onChange={(e) => setForm({ ...form, sourceHash: e.target.value })}
                placeholder="ab12cd34…"
                className="h-8 text-sm font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Line (optional = whole file)</Label>
              <Input
                type="number"
                value={form.line}
                onChange={(e) => setForm({ ...form, line: e.target.value })}
                placeholder="42"
                className="h-8 text-sm"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">Reason</Label>
            <Input
              value={form.reason}
              onChange={(e) => setForm({ ...form, reason: e.target.value })}
              placeholder="False positive — legitimate use in tests/"
              className="h-8 text-sm"
            />
          </div>
          <Button size="sm" onClick={create} className="w-full h-8">
            Add to baseline
          </Button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2">
        {rows.length === 0 && !loading && (
          <div className="text-center py-12 text-sm text-muted-foreground">
            <Ban className="h-10 w-10 mx-auto mb-3 opacity-30" />
            No baseline suppressions. Add one to mark a finding as an accepted risk.
          </div>
        )}
        {rows.map((s) => (
          <div
            key={s.id}
            className="rounded-lg border border-border bg-card p-3 space-y-1.5 hover:border-emerald-500/30 transition-colors"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <code className="text-xs font-mono font-semibold">{s.ruleId}</code>
                <div className="flex flex-wrap gap-2 mt-0.5 text-[10px] text-muted-foreground font-mono">
                  {s.sourceHash ? (
                    <span>file: {s.sourceHash}</span>
                  ) : (
                    <Badge variant="outline" className="text-[9px]">GLOBAL</Badge>
                  )}
                  {s.line != null && <span>line: {s.line}</span>}
                </div>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => remove(s.id)}
                className="h-7 text-xs text-red-500 hover:text-red-600 hover:bg-red-500/10"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground italic">"{s.reason}"</p>
            <div className="text-[10px] text-muted-foreground font-mono">
              by {s.createdBy} · {timeAgo(s.createdAt)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Compliance tab — maps current scan findings to PCI-DSS / OWASP / NIST / ISO
// ---------------------------------------------------------------------------
function ComplianceTab({ lastResult }: { lastResult: ScanResult | null }) {
  if (!lastResult || lastResult.findings.length === 0) {
    return (
      <div className="flex flex-col h-full items-center justify-center p-8 text-center">
        <Lock className="h-12 w-12 text-muted-foreground/30 mb-3" />
        <p className="text-sm font-medium mb-1">No compliance data yet</p>
        <p className="text-xs text-muted-foreground max-w-xs">
          Run a scan to see how detected findings map to PCI-DSS, OWASP Top 10, NIST 800-53 and
          ISO 27001 controls.
        </p>
      </div>
    );
  }

  // Aggregate compliance tags across all active (non-suppressed) findings.
  const active = lastResult.findings.filter((f) => !f.suppressed);
  const frameworks: Record<string, Record<string, { count: number; findings: string[] }>> = {
    "PCI-DSS 4.0": {},
    "OWASP Top 10": {},
    "NIST 800-53": {},
    "ISO 27001": {},
  };
  for (const f of active) {
    const c = f.compliance;
    if (!c) continue;
    for (const tag of c.pciDss ?? []) {
      const k = `PCI ${tag}`;
      (frameworks["PCI-DSS 4.0"][k] ??= { count: 0, findings: [] }).count++;
      frameworks["PCI-DSS 4.0"][k].findings.push(f.ruleId);
    }
    for (const tag of c.owasp ?? []) {
      (frameworks["OWASP Top 10"][tag] ??= { count: 0, findings: [] }).count++;
      frameworks["OWASP Top 10"][tag].findings.push(f.ruleId);
    }
    for (const tag of c.nist ?? []) {
      const k = `NIST ${tag}`;
      (frameworks["NIST 800-53"][k] ??= { count: 0, findings: [] }).count++;
      frameworks["NIST 800-53"][k].findings.push(f.ruleId);
    }
    for (const tag of c.iso27001 ?? []) {
      const k = `ISO ${tag}`;
      (frameworks["ISO 27001"][k] ??= { count: 0, findings: [] }).count++;
      frameworks["ISO 27001"][k].findings.push(f.ruleId);
    }
  }

  const frameworkColors: Record<string, string> = {
    "PCI-DSS 4.0": "text-amber-600 dark:text-amber-400 border-amber-500/30",
    "OWASP Top 10": "text-rose-600 dark:text-rose-400 border-rose-500/30",
    "NIST 800-53": "text-sky-600 dark:text-sky-400 border-sky-500/30",
    "ISO 27001": "text-violet-600 dark:text-violet-400 border-violet-500/30",
  };

  return (
    <div className="flex flex-col h-full overflow-y-auto custom-scrollbar p-4 space-y-4">
      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
        <div className="flex items-center gap-2 mb-1">
          <ShieldCheck className="h-4 w-4 text-emerald-500" />
          <span className="text-sm font-semibold">Compliance Impact Report</span>
        </div>
        <p className="text-xs text-muted-foreground">
          {active.length} active finding{active.length !== 1 ? "s" : ""} mapped across 4 compliance
          frameworks. Suppressed findings ({lastResult.findings.length - active.length}) are
          excluded as accepted-risk baselines.
        </p>
      </div>

      {Object.entries(frameworks).map(([fw, controls]) => {
        const entries = Object.entries(controls).sort((a, b) => b[1].count - a[1].count);
        if (entries.length === 0) return null;
        return (
          <div key={fw} className="space-y-2">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold">{fw}</h3>
              <Badge variant="outline" className={`text-[10px] ${frameworkColors[fw]}`}>
                {entries.length} control{entries.length !== 1 ? "s" : ""} impacted
              </Badge>
            </div>
            <div className="space-y-1.5">
              {entries.map(([control, data]) => (
                <div
                  key={control}
                  className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2"
                >
                  <div className="min-w-0">
                    <code className="text-xs font-mono font-medium">{control}</code>
                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                      {Array.from(new Set(data.findings)).slice(0, 4).join(", ")}
                      {new Set(data.findings).size > 4 && ` +${new Set(data.findings).size - 4}`}
                    </div>
                  </div>
                  <Badge
                    variant={data.count >= 3 ? "destructive" : "outline"}
                    className="text-[10px] shrink-0"
                  >
                    {data.count} hit{data.count !== 1 ? "s" : ""}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const abs = Math.abs(diff);
  const suffix = diff >= 0 ? " ago" : " from now";
  const s = Math.floor(abs / 1000);
  if (s < 60) return `${s}s${suffix}`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m${suffix}`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h${suffix}`;
  const d = Math.floor(h / 24);
  return `${d}d${suffix}`;
}

function verdictColor(v: string): string {
  switch (v) {
    case "dangerous":
      return "text-red-600 border-red-500/40";
    case "malicious":
      return "text-orange-600 border-orange-500/40";
    case "suspicious":
      return "text-amber-600 border-amber-500/40";
    default:
      return "text-emerald-600 border-emerald-500/40";
  }
}
