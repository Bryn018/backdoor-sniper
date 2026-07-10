import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const limit = Math.min(
    Number(searchParams.get("limit") ?? "50"),
    200
  );

  const records = await db.scanRecord.findMany({
    orderBy: { createdAt: "desc" },
    take: limit,
    select: {
      id: true,
      sourceHash: true,
      fileName: true,
      riskScore: true,
      verdict: true,
      totalLines: true,
      createdAt: true,
    },
  });

  // summary counts
  const all = await db.scanRecord.findMany({
    select: { verdict: true, riskScore: true },
  });
  const summary = {
    total: all.length,
    dangerous: all.filter((r) => r.verdict === "dangerous").length,
    malicious: all.filter((r) => r.verdict === "malicious").length,
    suspicious: all.filter((r) => r.verdict === "suspicious").length,
    clean: all.filter((r) => r.verdict === "clean").length,
    avgRisk:
      all.length === 0
        ? 0
        : Math.round(
            all.reduce((s, r) => s + r.riskScore, 0) / all.length
          ),
  };

  return NextResponse.json({ records, summary });
}
