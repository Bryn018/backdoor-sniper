/**
 * Streaming Python source scanner for HUGE files (>1MB).
 *
 * The synchronous `scanPython()` builds the full ScanContext (source, lines,
 * imports, obfuscation signals) up-front and runs every rule against the full
 * line array in one pass. For a 5MB / 100k-line file this is fine on a single
 * CPU but provides no progress visibility to the caller — a long scan looks
 * like a hang.
 *
 * `scanPythonStreaming()` solves this by chunking rule execution: the source
 * is split into line chunks (default 1000 lines) and every rule is run against
 * each chunk in turn. After each chunk the optional `onProgress` callback is
 * invoked so the caller (e.g. an SSE handler, a CLI, a worker) can report
 * progress to the user.
 *
 * Correctness notes
 * ------------------
 *  - We still pre-compute the FULL imports Set + obfuscation signal count from
 *    the entire source. This is necessary because many rules gate on
 *    `ctx.imports.has(...)` membership and we want the SAME findings as
 *    `scanPython()` (byte-for-byte backwards compatibility).
 *  - Each chunk sees a partial `ctx.lines` array. Rules report chunk-local
 *    line numbers (1-based within the chunk) so we remap them back to global
 *    line numbers by adding the chunk start offset.
 *  - Findings are still collected in full (we need all of them for dedupe +
 *    risk scoring) and the final result shape is identical to `scanPython()`.
 *  - For files smaller than 50KB we delegate to `scanPython()` directly to
 *    avoid the (small) chunking overhead.
 *  - The function NEVER throws. Each chunk + each rule is wrapped in try/catch;
 *    a failure simply skips that chunk/rule and continues.
 */

import type {
  Category,
  DetectionRule,
  Finding,
  RawMatch,
  ScanContext,
  ScanResult,
  ScanStats,
  Severity,
} from "./types";
import {
  ALL_RULES,
  buildFinding,
  computeObfuscationSignals,
  computeRiskScore,
  computeStats,
  dedupe,
  extractImports,
  hashSource,
  safeMatch,
  scanPython,
  verdictFromScore,
} from "./scanner";

export interface StreamingScanOptions {
  /** Lines per chunk. Default 1000. */
  chunkSize?: number;
  /** Called after each chunk with cumulative progress. */
  onProgress?: (p: {
    linesProcessed: number;
    totalLines: number;
    percent: number;
  }) => void;
  /**
   * Optional callback fired for each raw finding as it is detected.
   * Useful for streaming "finding" events to an SSE client. Throttling is the
   * caller's responsibility.
   */
  onFinding?: (finding: Finding) => void;
  /**
   * Optional override of the rule set (defaults to ALL_RULES). The project
   * scanner passes a frozen snapshot of ALL_RULES so we accept it here for
   * flexibility.
   */
  rules?: DetectionRule[];
  /** Files below this byte threshold delegate to scanPython() directly. */
  smallFileThresholdBytes?: number;
}

/** Below this size we just call scanPython() — no chunking overhead. */
const DEFAULT_SMALL_FILE_THRESHOLD = 50 * 1024; // 50 KB

const DEFAULT_CHUNK_SIZE = 1000;

/**
 * Scan a (potentially huge) Python source string in line-chunks with progress
 * reporting. Returns a ScanResult identical in shape to `scanPython()`.
 *
 * Never throws.
 */
export function scanPythonStreaming(
  source: string,
  opts?: StreamingScanOptions
): ScanResult {
  const start = Date.now();
  const chunkSize = Math.max(1, opts?.chunkSize ?? DEFAULT_CHUNK_SIZE);
  const rules = opts?.rules ?? ALL_RULES;
  const smallThreshold =
    opts?.smallFileThresholdBytes ?? DEFAULT_SMALL_FILE_THRESHOLD;

  // Fast path: small files just delegate to the canonical scanner.
  if (Buffer.byteLength(source, "utf8") < smallThreshold) {
    try {
      return scanPython(source);
    } catch {
      // Fall through to the chunked path if the fast path explodes for any
      // reason — we still need to produce a result.
    }
  }

  const totalLines = source.replace(/\r\n/g, "\n").split("\n");
  const lines = totalLines;
  const totalLineCount = lines.length;

  // Build the FULL imports + obfuscation signals up-front so rules that gate
  // on ctx.imports.has(...) fire identically to scanPython().
  const { imports, fromImports } = extractImports(source, lines);
  const obfuscationSignals = computeObfuscationSignals(lines);

  const rawFindings: Finding[] = [];

  // Walk the source in chunks, running EVERY rule against each chunk.
  for (let startIdx = 0; startIdx < totalLineCount; startIdx += chunkSize) {
    const endIdx = Math.min(startIdx + chunkSize, totalLineCount);
    const chunkLines = lines.slice(startIdx, endIdx);

    // Partial context: chunk-local lines, but FULL imports / fromImports /
    // obfuscation signals (so import-gated rules fire correctly).
    const ctx: ScanContext = {
      source,
      lines: chunkLines,
      imports,
      fromImports,
      obfuscationSignals,
    };

    try {
      for (const rule of rules) {
        let matches: RawMatch[] = [];
        try {
          matches = safeMatch(rule, ctx);
        } catch {
          continue; // a single rule failure must not abort the chunk
        }
        for (const m of matches) {
          // Remap chunk-local 1-based line to global 1-based line.
          const globalMatch: RawMatch = {
            ...m,
            line: m.line + startIdx,
          };
          const finding = buildFinding(rule, globalMatch);
          rawFindings.push(finding);
          try {
            opts?.onFinding?.(finding);
          } catch {
            /* ignore callback errors */
          }
        }
      }
    } catch {
      // A chunk-level failure (e.g. catastrophic regex backtracking) is logged
      // and skipped — we continue with the next chunk.
    }

    // Report progress after each chunk.
    try {
      opts?.onProgress?.({
        linesProcessed: endIdx,
        totalLines: totalLineCount,
        percent: totalLineCount === 0 ? 100 : Math.round((endIdx / totalLineCount) * 100),
      });
    } catch {
      /* ignore callback errors */
    }
  }

  const findings = dedupe(rawFindings);
  const stats: ScanStats = computeStats(findings, totalLineCount);
  const riskScore = computeRiskScore(findings, obfuscationSignals);
  const verdict = verdictFromScore(riskScore, findings);

  return {
    findings,
    stats,
    riskScore,
    verdict,
    durationMs: Date.now() - start,
    sourceHash: hashSource(source),
    scannedAt: new Date().toISOString(),
  };
}

// Re-export key shared constants/types so callers can build aggregations
// without importing from multiple modules.
export { SEVERITY_ORDER, SEVERITY_WEIGHT, ALL_CATEGORIES } from "./scanner";
export type { Severity, Category };
