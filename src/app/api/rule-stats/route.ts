import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export const runtime = "nodejs";

/**
 * Aggregate per-rule hit frequency across all historical scans.
 * Returns: { ruleId, hits, lastSeen, severity, category, title }[]
 * Useful for surfacing "this rule has fired 47 times" in the Rules Browser.
 */
export async function GET() {
  const records = await db.scanRecord.findMany({
    orderBy: { createdAt: "asc" },
    select: {
      findings: true,
      createdAt: true,
    },
  });

  type Acc = {
    hits: number;
    lastSeen: string;
    firstSeen: string;
    // best-effort metadata derived from the most recent finding
    severity?: string;
    category?: string;
    title?: string;
  };

  const map = new Map<string, Acc>();

  for (const r of records) {
    if (!r.findings) continue;
    let findings: unknown[];
    try {
      findings = JSON.parse(r.findings) as unknown[];
    } catch {
      continue;
    }
    if (!Array.isArray(findings)) continue;
    for (const f of findings) {
      const fx = f as { ruleId?: string; severity?: string; category?: string; title?: string };
      if (!fx.ruleId) continue;
      const prev = map.get(fx.ruleId);
      if (prev) {
        prev.hits++;
        prev.lastSeen = r.createdAt.toISOString();
        // keep metadata fresh
        if (fx.severity) prev.severity = fx.severity;
        if (fx.category) prev.category = fx.category;
        if (fx.title) prev.title = fx.title;
      } else {
        map.set(fx.ruleId, {
          hits: 1,
          firstSeen: r.createdAt.toISOString(),
          lastSeen: r.createdAt.toISOString(),
          severity: fx.severity,
          category: fx.category,
          title: fx.title,
        });
      }
    }
  }

  const rules = Array.from(map.entries())
    .map(([ruleId, v]) => ({
      ruleId,
      hits: v.hits,
      firstSeen: v.firstSeen,
      lastSeen: v.lastSeen,
      severity: v.severity ?? "unknown",
      category: v.category ?? "unknown",
      title: v.title ?? "",
    }))
    .sort((a, b) => b.hits - a.hits);

  return NextResponse.json({
    totalScans: records.length,
    totalRulesTriggered: rules.length,
    rules,
  });
}
