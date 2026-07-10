import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import path from "path";
import fs from "fs";
import os from "os";
import type { ScanResult } from "@/lib/detector/types";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 500_000; // 500 KB cap

const SCRIPT_PATH = path.join(
  process.cwd(),
  "scripts",
  "generate-pdf-report.py"
);

export async function POST(req: NextRequest) {
  // Size check
  const contentLength = req.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: `Request too large. Limit is ${MAX_BODY_BYTES} bytes.` },
      { status: 413 }
    );
  }

  let body: { result?: ScanResult };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body" },
      { status: 400 }
    );
  }

  const result = body.result;
  if (!result) {
    return NextResponse.json(
      { error: "Missing 'result' field in request body." },
      { status: 400 }
    );
  }

  // Basic validation
  if (!result.sourceHash || result.verdict === undefined) {
    return NextResponse.json(
      { error: "Invalid ScanResult: missing required fields." },
      { status: 400 }
    );
  }

  try {
    // Write JSON to a temp file, then pass file path to Python script
    const inputJson = JSON.stringify(result);
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `backdoorsniper-input-${result.sourceHash}.json`);
    fs.writeFileSync(tmpFile, inputJson, "utf8");

    const scriptResult = await runPythonScript(SCRIPT_PATH, tmpFile);

    // Clean up temp file
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }

    if (!scriptResult.success || !scriptResult.path) {
      console.error("PDF script error:", scriptResult.error);
      return NextResponse.json(
        { error: scriptResult.error || "PDF generation failed." },
        { status: 500 }
      );
    }

    // Verify the file exists
    if (!fs.existsSync(scriptResult.path)) {
      return NextResponse.json(
        { error: "Generated PDF file not found on disk." },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      filename: scriptResult.filename,
      path: scriptResult.path,
      downloadUrl: `/api/export-pdf/download?file=${encodeURIComponent(scriptResult.filename)}`,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("PDF export error:", message);
    return NextResponse.json(
      { error: `PDF generation failed: ${message}` },
      { status: 500 }
    );
  }
}

function runPythonScript(
  scriptPath: string,
  inputFilePath: string
): Promise<{ success?: boolean; path?: string; filename?: string; error?: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [scriptPath, inputFilePath], {
      timeout: 30_000,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      if (code !== 0) {
        console.error("Python script stderr:", stderr);
        reject(new Error(stderr.trim() || `Script exited with code ${code}`));
        return;
      }

      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch {
        console.error("PDF script output parse error:", stdout, stderr);
        reject(new Error("PDF generation script returned unexpected output."));
      }
    });

    proc.on("error", (err) => {
      reject(err);
    });
  });
}
