import { NextRequest, NextResponse } from "next/server";
import { scanPython } from "@/lib/detector";
import { db } from "@/lib/db";

export const runtime = "nodejs";

const MAX_FILES = 20;
const MAX_FILE_BYTES = 500_000;

interface BatchFile {
  name: string;
  content: string;
}

export async function POST(req: NextRequest) {
  let body: { files?: BatchFile[] };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const files = body.files ?? [];
  if (!Array.isArray(files) || files.length === 0) {
    return NextResponse.json(
      { error: "No files provided. Send { files: [{name, content}] }" },
      { status: 400 }
    );
  }
  if (files.length > MAX_FILES) {
    return NextResponse.json(
      { error: `Too many files. Maximum is ${MAX_FILES}.` },
      { status: 413 }
    );
  }

  const results = [];
  let aggregateRisk = 0;
  let totalFindings = 0;

  for (const file of files) {
    const name = (file.name ?? "unknown.py").toString().slice(0, 255);
    const content = (file.content ?? "").toString();

    if (Buffer.byteLength(content, "utf8") > MAX_FILE_BYTES) {
      results.push({
        fileName: name,
        error: `File too large (max ${MAX_FILE_BYTES} bytes)`,
      });
      continue;
    }

    if (!content.trim()) {
      results.push({
        fileName: name,
        error: "Empty file",
      });
      continue;
    }

    const result = scanPython(content);
    aggregateRisk = Math.max(aggregateRisk, result.riskScore);
    totalFindings += result.stats.totalFindings;

    // persist best-effort
    try {
      await db.scanRecord.create({
        data: {
          sourceHash: result.sourceHash,
          fileName: name,
          riskScore: result.riskScore,
          verdict: result.verdict,
          totalLines: result.stats.totalLines,
          findings: JSON.stringify(result.findings),
          sourcePreview: content.slice(0, 500),
        },
      });
    } catch (e) {
      console.error("Failed to persist batch scan record:", e);
    }

    results.push({
      fileName: name,
      riskScore: result.riskScore,
      verdict: result.verdict,
      totalLines: result.stats.totalLines,
      findingCount: result.stats.totalFindings,
      bySeverity: result.stats.bySeverity,
      topFindings: result.findings.slice(0, 5).map((f) => ({
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        category: f.category,
        line: f.line,
      })),
      sourceHash: result.sourceHash,
    });
  }

  // overall verdict = worst file
  const worstVerdict = results
    .map((r) => r.verdict ?? "clean")
    .reduce((worst, v) => {
      const order = ["clean", "suspicious", "malicious", "dangerous"];
      return order.indexOf(v) > order.indexOf(worst) ? v : worst;
    }, "clean");

  return NextResponse.json({
    totalFiles: results.length,
    aggregateRisk,
    totalFindings,
    worstVerdict,
    results,
  });
}
