import { NextRequest, NextResponse } from "next/server";
import path from "path";
import fs from "fs";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const file = url.searchParams.get("file");

  if (!file) {
    return NextResponse.json(
      { error: "Missing 'file' query parameter." },
      { status: 400 }
    );
  }

  // Sanitize filename to prevent path traversal
  const safeName = path.basename(file);
  if (safeName !== file || !safeName.startsWith("backdoorsniper-report-")) {
    return NextResponse.json(
      { error: "Invalid filename." },
      { status: 400 }
    );
  }

  const filePath = path.join(os.tmpdir(), safeName);

  if (!fs.existsSync(filePath)) {
    return NextResponse.json(
      { error: "File not found." },
      { status: 404 }
    );
  }

  const fileBuffer = fs.readFileSync(filePath);

  return new NextResponse(fileBuffer, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="${safeName}"`,
      "Content-Length": fileBuffer.length.toString(),
    },
  });
}
