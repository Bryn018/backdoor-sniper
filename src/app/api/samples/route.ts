import { NextResponse } from "next/server";
import { SAMPLES } from "@/lib/samples/threats";

export const runtime = "nodejs";

export async function GET() {
  return NextResponse.json(
    SAMPLES.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
      expectedVerdict: s.expectedVerdict,
      tags: s.tags,
    }))
  );
}
