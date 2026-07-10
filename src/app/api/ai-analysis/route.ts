import { NextRequest, NextResponse } from "next/server";
import ZAI from "z-ai-web-dev-sdk";

export const runtime = "nodejs";

interface FindingInput {
  ruleId: string;
  title: string;
  severity: string;
  category: string;
  line: number;
  snippet: string;
  description?: string;
  remediation?: string;
}

export async function POST(req: NextRequest) {
  let body: {
    findings?: FindingInput[];
    verdict?: string;
    riskScore?: number;
    /** If "single", explain just one finding in detail. Otherwise, summarize all. */
    mode?: "single" | "summary";
  };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const {
    findings = [],
    verdict = "unknown",
    riskScore = 0,
    mode = "summary",
  } = body;

  if (findings.length === 0) {
    return NextResponse.json({
      summary:
        "No backdoor patterns were detected in this code. The source appears clean, but keep reviewing dependencies and external inputs.",
    });
  }

  try {
    const zai = await ZAI.create();

    if (mode === "single") {
      // Detailed explanation of a single finding (junior-dev friendly)
      const f = findings[0];
      const completion = await zai.chat.completions.create({
        messages: [
          {
            role: "assistant",
            content:
              "You are a patient security mentor explaining Python backdoor findings to a junior developer. Be specific, plain-language, and concrete. Use 2-4 short sentences. Explain what the line does, why it's dangerous, and what an attacker could do if they exploited it. Avoid jargon when possible.",
          },
          {
            role: "user",
            content: `Explain this Python security finding in plain language:\n\nRule: ${f.ruleId}\nSeverity: ${f.severity}\nCategory: ${f.category}\nTitle: ${f.title}\nLine ${f.line}: ${f.snippet}\n\nTechnical description: ${f.description ?? ""}\nSuggested fix: ${f.remediation ?? ""}\n\nExplain to a junior developer what this code does and why it's risky.`,
          },
        ],
        thinking: { type: "disabled" },
      });

      const summary =
        completion.choices?.[0]?.message?.content ??
        `This finding (${f.ruleId}) on line ${f.line} matches a known backdoor pattern. Review the snippet and the remediation guidance above.`;
      return NextResponse.json({ summary });
    }

    // Default: overall summary
    const findingsSummary = findings
      .slice(0, 15)
      .map(
        (f) =>
          `- [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.title} (line ${f.line}) — ${f.snippet}`
      )
      .join("\n");

    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: "assistant",
          content:
            "You are a senior security analyst specializing in Python malware and backdoor analysis. Provide concise, actionable analysis in plain language. Be specific about the threat and what the attacker can do. Keep your response under 3 sentences.",
        },
        {
          role: "user",
          content: `Analyze these Python backdoor detection findings:\n\nVerdict: ${verdict}\nRisk Score: ${riskScore}/100\n\nFindings:\n${findingsSummary}\n\nProvide a brief plain-language summary of the overall threat and what the attacker could accomplish.`,
        },
      ],
      thinking: { type: "disabled" },
    });

    const summary =
      completion.choices?.[0]?.message?.content ??
      "Analysis unavailable. Review the individual findings above for details.";

    return NextResponse.json({ summary });
  } catch (e) {
    console.error("AI analysis error:", e);

    if (mode === "single") {
      const f = findings[0];
      return NextResponse.json({
        summary: `${f.title} (rule ${f.ruleId}, line ${f.line}). ${f.description ?? ""} Review the snippet above and apply the suggested fix: ${f.remediation ?? "see rule documentation"}`,
      });
    }

    // Fallback: generate a simple rule-based summary
    const critCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;
    const cats = [...new Set(findings.map((f) => f.category))];

    let fallback = `This code is flagged as **${verdict}** (risk ${riskScore}/100) with ${findings.length} finding(s).`;
    if (critCount > 0) {
      fallback += ` ${critCount} critical issue(s) found — these represent immediate backdoor capabilities.`;
    }
    if (highCount > 0) {
      fallback += ` ${highCount} high-severity issue(s) could allow an attacker significant control.`;
    }
    fallback += ` Threat categories: ${cats.join(", ")}.`;

    return NextResponse.json({ summary: fallback });
  }
}
