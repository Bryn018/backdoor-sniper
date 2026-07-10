import { NextRequest, NextResponse } from "next/server";
import { scanProject, type ProjectFile } from "@/lib/detector";
import { db } from "@/lib/db";
import { validateApiKey } from "@/lib/auth/api-key";
import { enforceProjectRateLimit, actorKeyFromRequest } from "@/lib/auth/rate-limit";
import { recordAudit } from "@/lib/audit";

export const runtime = "nodejs";

/** Project-scan payload limits (much larger than single-file scans). */
const MAX_FILES = 500;
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB per file
const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB total payload

function getClientIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}

interface ProjectScanBody {
  files?: { path?: string; content?: string }[];
  save?: boolean;
  policyName?: string;
}

export async function POST(req: NextRequest) {
  const actorIp = getClientIp(req);
  const authHeader = req.headers.get("authorization");
  const apiKey = await validateApiKey(authHeader);

  // Project scans use a separate, more conservative rate-limit tier.
  const rateLimitRes = enforceProjectRateLimit(
    req,
    actorKeyFromRequest(req, apiKey?.id),
    !apiKey
  );
  if (rateLimitRes) return rateLimitRes;

  let body: ProjectScanBody;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const rawFiles = body.files ?? [];
  if (!Array.isArray(rawFiles) || rawFiles.length === 0) {
    return NextResponse.json(
      { error: "No files provided. Send { files: [{ path, content }] }" },
      { status: 400 }
    );
  }
  if (rawFiles.length > MAX_FILES) {
    return NextResponse.json(
      {
        error: `Too many files. Maximum is ${MAX_FILES} per project scan (received ${rawFiles.length}).`,
      },
      { status: 413 }
    );
  }

  // Validate per-file + total payload size BEFORE scanning.
  const files: ProjectFile[] = [];
  let totalBytes = 0;
  for (const f of rawFiles) {
    const path = (f.path ?? "unknown.py").toString().slice(0, 512);
    const content = (f.content ?? "").toString();
    const fileBytes = Buffer.byteLength(content, "utf8");
    if (fileBytes > MAX_FILE_BYTES) {
      return NextResponse.json(
        {
          error: `File "${path}" is ${fileBytes} bytes — exceeds the per-file limit of ${MAX_FILE_BYTES} bytes.`,
        },
        { status: 413 }
      );
    }
    totalBytes += fileBytes;
    if (totalBytes > MAX_TOTAL_BYTES) {
      return NextResponse.json(
        {
          error: `Total payload exceeds the ${MAX_TOTAL_BYTES}-byte limit.`,
        },
        { status: 413 }
      );
    }
    files.push({ path, content });
  }

  const save = body.save !== false; // default true
  const policyName = body.policyName?.toString().slice(0, 128) ?? null;

  // Run the project scan with bounded concurrency.
  const result = await scanProject(files, { concurrency: 4 });

  // Persist a ScanRecord per file (best-effort — never fail the request).
  if (save) {
    for (const fr of result.files) {
      if (fr.error) continue;
      try {
        await db.scanRecord.create({
          data: {
            sourceHash: fr.result.sourceHash,
            fileName: fr.path,
            riskScore: fr.result.riskScore,
            verdict: fr.result.verdict,
            totalLines: fr.result.stats.totalLines,
            findings: JSON.stringify(fr.result.findings),
            sourcePreview: "", // we don't persist the full source content for project scans
            apiKeyId: apiKey?.id ?? null,
            actorIp,
            policyName,
            scanMode: "batch",
          },
        });
      } catch (e) {
        console.error(`[scan.project] failed to persist record for ${fr.path}:`, e);
      }
    }
  }

  // One audit log entry summarizing the project scan.
  await recordAudit({
    actorType: apiKey ? "api_key" : "web",
    actorId: apiKey?.id ?? null,
    actorName: apiKey?.name ?? null,
    actorIp,
    action: "scan.project",
    target: null,
    outcome: "success",
    verdict: result.aggregate.worstVerdict,
    riskScore: result.aggregate.maxRiskScore,
    metadata: {
      fileCount: result.aggregate.totalFiles,
      totalFilesSubmitted: files.length,
      totalLines: result.aggregate.totalLines,
      totalFindings: result.aggregate.totalFindings,
      worstVerdict: result.aggregate.worstVerdict,
      maxRiskScore: result.aggregate.maxRiskScore,
      durationMs: result.durationMs,
      policyName,
    },
  });

  return NextResponse.json(result);
}

export async function GET() {
  return NextResponse.json({
    name: "BackdoorSniper — Project Scanner",
    limits: {
      maxFiles: MAX_FILES,
      maxFileBytes: MAX_FILE_BYTES,
      maxTotalBytes: MAX_TOTAL_BYTES,
    },
    usage:
      "POST /api/scan/project  { files: [{ path, content }], save?, policyName? }  — scans up to 500 Python files in parallel and returns an aggregated ProjectScanResult.",
  });
}
