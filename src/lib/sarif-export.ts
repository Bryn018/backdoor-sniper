import type { ScanResult, Finding } from "@/lib/detector/types";
import {
  SEVERITY_LABEL,
  CATEGORY_LABEL,
  VERDICT_META,
} from "@/lib/severity";

/**
 * Map BackdoorSniper severity tiers to SARIF level values.
 * SARIF defines: none | note | warning | error
 */
function sarifLevel(sev: Finding["severity"]): "none" | "note" | "warning" | "error" {
  switch (sev) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    case "info":
    default:
      return "none";
  }
}

/**
 * Convert a BackdoorSniper ScanResult to a SARIF 2.1.0 log object.
 * Suitable for importing into GitHub Code Scanning, Azure DevOps,
 * SonarQube, or any CI/CD tool that consumes SARIF.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
export function scanResultToSarif(
  result: ScanResult,
  fileName: string = "scanned.py"
): unknown {
  const v = VERDICT_META[result.verdict];

  // Build a stable rule index map (deduplicated by rule id)
  const ruleIds = Array.from(new Set(result.findings.map((f) => f.ruleId)));
  const ruleIndexMap = new Map<string, number>();
  ruleIds.forEach((id, idx) => ruleIndexMap.set(id, idx));

  // Rules metadata
  const rules = ruleIds.map((id) => {
    const finding = result.findings.find((f) => f.ruleId === id)!;
    return {
      id,
      name: id,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      helpUri:
        finding.references?.find((r) => r.startsWith("CWE-")) ?
          `https://cwe.mitre.org/data/definitions/${finding.references
            .find((r) => r.startsWith("CWE-"))!
            .replace("CWE-", "")}.html`
        : undefined,
      help: { text: finding.remediation },
      defaultConfiguration: { level: sarifLevel(finding.severity) },
      properties: {
        category: finding.category,
        categoryLabel:
          CATEGORY_LABEL[finding.category as keyof typeof CATEGORY_LABEL] ??
          finding.category,
        severity: finding.severity,
        tags: finding.references ?? [],
      },
    };
  });

  // Results (one per finding)
  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndexMap.get(f.ruleId)!,
    level: sarifLevel(f.severity),
    message: { text: f.title },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: fileName,
            uriBaseId: "%SRCROOT%",
          },
          region: {
            startLine: f.line,
            snippet: { text: f.snippet || "" },
          },
        },
        logicalLocations: [
          {
            fullyQualifiedName: `${fileName}#${f.line}`,
          },
        ],
      },
    ],
    partialFingerprints: {
      "primaryLocationLineHash": `${f.ruleId}:${f.line}:${f.sourceHash ?? result.sourceHash}`,
    },
    properties: {
      confidence: Math.round(f.confidence * 100) / 100,
      category: f.category,
      references: f.references ?? [],
    },
  }));

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "BackdoorSniper",
            version: "1.0.0",
            informationUri: "https://example.com/backdoorsniper",
            rules,
            properties: {
              verdict: v.label,
              riskScore: result.riskScore,
              totalFindings: result.stats.totalFindings,
              totalLines: result.stats.totalLines,
            },
          },
        },
        artifacts: [
          {
            location: { uri: fileName, uriBaseId: "%SRCROOT%" },
            length: result.stats.totalLines,
            hashes: {
              "sha-256": result.sourceHash,
            },
          },
        ],
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: result.scannedAt,
            endTimeUtc: result.scannedAt,
            toolExecutionNotifications: [
              {
                level: "note",
                message: {
                  text: `Scan completed in ${result.durationMs}ms. Verdict: ${v.label}, risk ${result.riskScore}/100.`,
                },
              },
            ],
          },
        ],
      },
    ],
    properties: {
      scanHash: result.sourceHash,
      scannedAt: result.scannedAt,
      verdict: v.label,
      riskScore: result.riskScore,
    },
  };
}
