import { NextRequest, NextResponse } from "next/server";
import type { ScanResult } from "@/lib/detector/types";
import { scanResultToSarif } from "@/lib/sarif-export";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 500_000;

export async function POST(req: NextRequest) {
  const contentLength = req.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: `Request too large. Limit is ${MAX_BODY_BYTES} bytes.` },
      { status: 413 }
    );
  }

  let body: { result?: ScanResult; fileName?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const result = body.result;
  if (!result) {
    return NextResponse.json(
      { error: "Missing 'result' field in request body." },
      { status: 400 }
    );
  }

  if (!result.sourceHash || result.verdict === undefined) {
    return NextResponse.json(
      { error: "Invalid ScanResult: missing required fields." },
      { status: 400 }
    );
  }

  const sarif = scanResultToSarif(result, body.fileName ?? "scanned.py");
  const json = JSON.stringify(sarif, null, 2);

  return new NextResponse(json, {
    status: 200,
    headers: {
      "Content-Type": "application/sarif+json; charset=utf-8",
      "Content-Disposition": `attachment; filename="backdoorsniper-${result.sourceHash}.sarif"`,
      "Content-Length": Buffer.byteLength(json, "utf8").toString(),
    },
  });
}
