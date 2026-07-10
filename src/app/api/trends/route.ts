import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateApiKey, hasScope } from "@/lib/auth/api-key";

export const runtime = "nodejs";

/**
 * GET /api/trends — aggregated scan metrics for the trends dashboard.
 *
 * Returns:
 *  - dailyScanVolume: [{ date, scans, criticalScans, avgRisk }]
 *  - topRules: [{ ruleId, title, hits }] — most-frequently-firing rules
 *  - verdictBreakdown: { clean, suspicious, malicious, dangerous }
 *  - severityBreakdown: { critical, high, medium, low, info }
 *  - topCategories: [{ category, count }]
 *  - riskDistribution: [{ bucket, count }] — risk score histogram
 *  - topScannedHashes: [{ sourceHash, fileName, scans, lastRisk, lastVerdict }]
 *  - policyPassRate: number
 *  - totalScans, uniqueHashes, last24h, last7d
 *
 * Time window: defaults to last 30 days, override with ?days=7|30|90
 */
export async function GET(req: NextRequest) {
  const authKey = await validateApiKey(req.headers.get("authorization"));
  if (authKey && !hasScope(authKey, "scan:read")) {
    return NextResponse.json(
      { error: "Insufficient scope: scan:read required" },
      { status: 403 }
    );
  }

  const url = new URL(req.url);
  const days = Math.min(Math.max(Number(url.searchParams.get("days") ?? "30"), 1), 90);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  // Fetch all scans in window (we do the aggregation in JS — SQLite is small)
  const records = await db.scanRecord.findMany({
    where: { createdAt: { gte: since } },
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      sourceHash: true,
      fileName: true,
      riskScore: true,
      verdict: true,
      findings: true,
      policyPassed: true,
      createdAt: true,
      scanMode: true,
    },
  });

  // ---- Daily scan volume ----
  const dailyMap = new Map<string, { scans: number; criticalScans: number; riskSum: number }>();
  for (const r of records) {
    const date = r.createdAt.toISOString().slice(0, 10); // YYYY-MM-DD
    const entry = dailyMap.get(date) ?? { scans: 0, criticalScans: 0, riskSum: 0 };
    entry.scans++;
    if (r.verdict === "dangerous" || r.verdict === "malicious") entry.criticalScans++;
    entry.riskSum += r.riskScore;
    dailyMap.set(date, entry);
  }
  const dailyScanVolume = Array.from(dailyMap.entries())
    .map(([date, e]) => ({
      date,
      scans: e.scans,
      criticalScans: e.criticalScans,
      avgRisk: e.scans > 0 ? Math.round(e.riskSum / e.scans) : 0,
    }))
    .sort((a, b) => a.date.localeCompare(b.date));

  // ---- Top rules by hit frequency ----
  const ruleHits = new Map<string, { ruleId: string; title: string; hits: number; lastSeen: Date }>();
  for (const r of records) {
    let findings: Array<{ ruleId?: string; title?: string; severity?: string; category?: string }> = [];
    try {
      findings = JSON.parse(r.findings);
    } catch {
      continue;
    }
    for (const f of findings) {
      if (!f.ruleId) continue;
      const entry = ruleHits.get(f.ruleId) ?? {
        ruleId: f.ruleId,
        title: f.title ?? f.ruleId,
        hits: 0,
        lastSeen: r.createdAt,
      };
      entry.hits++;
      if (r.createdAt > entry.lastSeen) entry.lastSeen = r.createdAt;
      ruleHits.set(f.ruleId, entry);
    }
  }
  const topRules = Array.from(ruleHits.values())
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 15)
    .map((r) => ({ ...r, lastSeen: r.lastSeen.toISOString() }));

  // ---- Verdict breakdown ----
  const verdictBreakdown = { clean: 0, suspicious: 0, malicious: 0, dangerous: 0 };
  for (const r of records) {
    if (r.verdict in verdictBreakdown) verdictBreakdown[r.verdict as keyof typeof verdictBreakdown]++;
  }

  // ---- Severity + category breakdown (aggregated across all findings) ----
  const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categoryCount = new Map<string, number>();
  for (const r of records) {
    let findings: Array<{ severity?: string; category?: string }> = [];
    try {
      findings = JSON.parse(r.findings);
    } catch {
      continue;
    }
    for (const f of findings) {
      if (f.severity && f.severity in severityBreakdown)
        severityBreakdown[f.severity as keyof typeof severityBreakdown]++;
      if (f.category) categoryCount.set(f.category, (categoryCount.get(f.category) ?? 0) + 1);
    }
  }
  const topCategories = Array.from(categoryCount.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // ---- Risk distribution histogram (buckets of 10) ----
  const buckets = ["0-9", "10-19", "20-29", "30-39", "40-49", "50-59", "60-69", "70-79", "80-89", "90-100"];
  const riskDistribution = buckets.map((b) => ({ bucket: b, count: 0 }));
  for (const r of records) {
    const idx = r.riskScore >= 100 ? 9 : Math.floor(r.riskScore / 10);
    if (idx >= 0 && idx < riskDistribution.length) riskDistribution[idx].count++;
  }

  // ---- Top scanned hashes (most-recurring sources) ----
  const hashMap = new Map<string, { sourceHash: string; fileName: string | null; scans: number; lastRisk: number; lastVerdict: string; lastScan: Date }>();
  for (const r of records) {
    const entry = hashMap.get(r.sourceHash) ?? {
      sourceHash: r.sourceHash,
      fileName: r.fileName,
      scans: 0,
      lastRisk: r.riskScore,
      lastVerdict: r.verdict,
      lastScan: r.createdAt,
    };
    entry.scans++;
    if (r.createdAt >= entry.lastScan) {
      entry.lastRisk = r.riskScore;
      entry.lastVerdict = r.verdict;
      entry.lastScan = r.createdAt;
      entry.fileName = r.fileName ?? entry.fileName;
    }
    hashMap.set(r.sourceHash, entry);
  }
  const topScannedHashes = Array.from(hashMap.values())
    .sort((a, b) => b.scans - a.scans)
    .slice(0, 10)
    .map((h) => ({ ...h, lastScan: h.lastScan.toISOString() }));

  // ---- Policy pass rate ----
  const policyEvaluated = records.filter((r) => r.policyPassed !== null);
  const policyPassedCount = policyEvaluated.filter((r) => r.policyPassed === true).length;
  const policyPassRate = policyEvaluated.length > 0 ? Math.round((policyPassedCount / policyEvaluated.length) * 100) : null;

  // ---- Scan mode breakdown ----
  const scanModeCount = new Map<string, number>();
  for (const r of records) {
    scanModeCount.set(r.scanMode, (scanModeCount.get(r.scanMode) ?? 0) + 1);
  }
  const scanModeBreakdown = Array.from(scanModeCount.entries())
    .map(([mode, count]) => ({ mode, count }))
    .sort((a, b) => b.count - a.count);

  // ---- Summary numbers ----
  const totalScans = records.length;
  const uniqueHashes = hashMap.size;
  const now = Date.now();
  const last24h = records.filter((r) => r.createdAt.getTime() > now - 24 * 60 * 60 * 1000).length;
  const last7d = records.filter((r) => r.createdAt.getTime() > now - 7 * 24 * 60 * 60 * 1000).length;

  return NextResponse.json({
    window: { days, since: since.toISOString(), until: new Date().toISOString() },
    summary: {
      totalScans,
      uniqueHashes,
      last24h,
      last7d,
      policyPassRate,
    },
    dailyScanVolume,
    topRules,
    verdictBreakdown,
    severityBreakdown,
    topCategories,
    riskDistribution,
    topScannedHashes,
    scanModeBreakdown,
  });
}
