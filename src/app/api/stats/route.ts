import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export const runtime = "nodejs";

export async function GET() {
  const all = await db.scanRecord.findMany({
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      riskScore: true,
      verdict: true,
      totalLines: true,
      createdAt: true,
      findings: true,
    },
  });

  const total = all.length;
  const verdictCounts = {
    clean: 0,
    suspicious: 0,
    malicious: 0,
    dangerous: 0,
  };
  let totalFindings = 0;
  let totalLines = 0;
  let totalRisk = 0;

  // category aggregation from findings JSON
  const categoryCounts: Record<string, number> = {};
  // severity aggregation
  const severityCounts: Record<string, number> = {};
  // timeline: group by day
  const timelineMap: Record<
    string,
    { count: number; totalRisk: number; dangerous: number }
  > = {};

  for (const r of all) {
    verdictCounts[r.verdict as keyof typeof verdictCounts]++;
    totalRisk += r.riskScore;
    totalLines += r.totalLines;

    // parse findings JSON
    try {
      const findings = r.findings ? JSON.parse(r.findings) : [];
      totalFindings += findings.length;
      for (const f of findings) {
        if (f.category) {
          categoryCounts[f.category] = (categoryCounts[f.category] ?? 0) + 1;
        }
        if (f.severity) {
          severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
        }
      }
    } catch {
      /* ignore parse errors */
    }

    // timeline by day
    const day = new Date(r.createdAt).toISOString().slice(0, 10); // YYYY-MM-DD
    if (!timelineMap[day]) {
      timelineMap[day] = { count: 0, totalRisk: 0, dangerous: 0 };
    }
    timelineMap[day].count++;
    timelineMap[day].totalRisk += r.riskScore;
    if (r.verdict === "dangerous") timelineMap[day].dangerous++;
  }

  // Build timeline array (last 30 days)
  const timeline = Object.entries(timelineMap)
    .map(([day, v]) => ({
      day,
      count: v.count,
      avgRisk: v.count > 0 ? Math.round(v.totalRisk / v.count) : 0,
      dangerous: v.dangerous,
    }))
    .sort((a, b) => a.day.localeCompare(b.day))
    .slice(-30);

  // Top categories sorted
  const topCategories = Object.entries(categoryCounts)
    .map(([cat, count]) => ({ category: cat, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return NextResponse.json({
    summary: {
      total,
      totalFindings,
      totalLines,
      avgRisk: total > 0 ? Math.round(totalRisk / total) : 0,
      maxRisk: all.length > 0 ? Math.max(...all.map((r) => r.riskScore)) : 0,
      verdictCounts,
    },
    severityCounts,
    topCategories,
    timeline,
  });
}
