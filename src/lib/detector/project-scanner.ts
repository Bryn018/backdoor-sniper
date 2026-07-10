/**
 * Project-level Python scanner for multi-file codebases.
 *
 * Given an array of `{ path, content }` files, runs the streaming scanner
 * against each `.py` file in parallel (bounded concurrency) and aggregates
 * the results into a single `ProjectScanResult`.
 *
 * Design notes
 * ------------
 *  - We hand-roll a tiny promise-pool instead of pulling in `p-limit` to keep
 *    the dependency footprint minimal.
 *  - Each file is scanned with `scanPythonStreaming()` so progress can be
 *    surfaced per file (and individual huge files don't block the pool).
 *  - A single file failure NEVER aborts the project scan — we record the
 *    error string on the file result and continue.
 *  - Aggregations: worst verdict (clean < suspicious < malicious < dangerous),
 *    max risk score, summed severity + category counts, top 50 findings
 *    project-wide (sorted by severity then per-finding risk contribution),
 *    and top 20 hotspot files (highest risk concentration).
 */

import type { Category, Finding, ScanResult, Severity } from "./types";
import { ALL_CATEGORIES, SEVERITY_ORDER } from "./scanner";
import { scanPythonStreaming } from "./scanner-streaming";

export interface ProjectFile {
  /** Relative path within the project, e.g. "src/utils/net.py". */
  path: string;
  content: string;
}

export interface ProjectFileResult {
  path: string;
  result: ScanResult;
  error?: string;
}

export interface ProjectScanAggregate {
  totalFiles: number;
  totalLines: number;
  totalFindings: number;
  worstVerdict: ScanResult["verdict"];
  maxRiskScore: number;
  bySeverity: Record<Severity, number>;
  byCategory: Partial<Record<Category, number>>;
  /** Top 50 findings across the project, sorted by severity then risk contribution. */
  topFindings: { path: string; finding: Finding }[];
  /** Top 20 files by risk score / finding concentration. */
  hotspotFiles: { path: string; riskScore: number; findingCount: number }[];
}

export interface ProjectScanResult {
  files: ProjectFileResult[];
  aggregate: ProjectScanAggregate;
  durationMs: number;
}

export interface ProjectScanOptions {
  /** Max parallel file scans. Default 4. */
  concurrency?: number;
  /** Called after each file completes (success or failure). */
  onFileComplete?: (path: string, result: ScanResult) => void;
  /** Called after each file completes with overall progress. */
  onProgress?: (p: { completed: number; total: number; percent: number }) => void;
}

const VERDICT_ORDER: ScanResult["verdict"][] = [
  "clean",
  "suspicious",
  "malicious",
  "dangerous",
];

function worstVerdictOf(a: ScanResult["verdict"], b: ScanResult["verdict"]): ScanResult["verdict"] {
  return VERDICT_ORDER.indexOf(a) >= VERDICT_ORDER.indexOf(b) ? a : b;
}

/** Per-finding risk contribution = severity weight * max(0.4, confidence). */
function findingRiskContribution(f: Finding): number {
  const weightMap: Record<Severity, number> = {
    critical: 25,
    high: 14,
    medium: 7,
    low: 3,
    info: 1,
  };
  return weightMap[f.severity] * Math.max(0.4, f.confidence);
}

/** Returns true if the path looks like a Python source file. */
export function isPythonFile(path: string): boolean {
  return /\.py$/i.test(path);
}

/**
 * Scan a project (collection of files) in parallel and aggregate the results.
 *
 * Never throws — file-level errors are recorded per-file in the result.
 */
export async function scanProject(
  files: ProjectFile[],
  opts?: ProjectScanOptions
): Promise<ProjectScanResult> {
  const start = Date.now();
  const concurrency = Math.max(1, opts?.concurrency ?? 4);

  // Filter to .py files only — callers may send any files (e.g. extracted
  // from a zip) and we silently skip non-Python ones.
  const pyFiles = files.filter((f) => isPythonFile(f.path));

  const fileResults: ProjectFileResult[] = new Array(pyFiles.length);
  let completed = 0;

  // Hand-rolled promise pool. We pick the next file whenever a worker frees
  // up, bounded by `concurrency`.
  let cursor = 0;
  const total = pyFiles.length;

  async function worker() {
    while (true) {
      const idx = cursor++;
      if (idx >= total) return;
      const file = pyFiles[idx];
      const path = file.path;

      let result: ScanResult;
      let error: string | undefined;
      try {
        result = scanPythonStreaming(file.content);
      } catch (e) {
        // scanPythonStreaming is supposed to never throw, but we belt-and-
        // braces here so a single bad file can't kill the project scan.
        const msg = e instanceof Error ? e.message : String(e);
        // Construct an empty ScanResult so the caller has something to render.
        result = emptyScanResult(file.content);
        error = msg;
      }

      fileResults[idx] = { path, result, error };

      completed++;
      try {
        opts?.onFileComplete?.(path, result);
      } catch {
        /* ignore callback errors */
      }
      try {
        opts?.onProgress?.({
          completed,
          total,
          percent: total === 0 ? 100 : Math.round((completed / total) * 100),
        });
      } catch {
        /* ignore callback errors */
      }
    }
  }

  // Spawn `concurrency` workers and await them all.
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(concurrency, total); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  // ---- Aggregate ----
  const aggregate = aggregateResults(fileResults);

  return {
    files: fileResults,
    aggregate,
    durationMs: Date.now() - start,
  };
}

/** Build an empty "clean" ScanResult for a failed file. */
function emptyScanResult(source: string): ScanResult {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const emptyByCategory = {} as Record<Category, number>;
  for (const c of ALL_CATEGORIES) emptyByCategory[c] = 0;
  return {
    findings: [],
    stats: {
      totalLines: lines.length,
      totalFindings: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byCategory: emptyByCategory,
    },
    riskScore: 0,
    verdict: "clean",
    durationMs: 0,
    sourceHash: "",
    scannedAt: new Date().toISOString(),
  };
}

/** Aggregate per-file results into a project-wide summary. */
function aggregateResults(fileResults: ProjectFileResult[]): ProjectScanAggregate {
  let totalLines = 0;
  let totalFindings = 0;
  let worstVerdict: ScanResult["verdict"] = "clean";
  let maxRiskScore = 0;

  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const byCategory: Partial<Record<Category, number>> = {};

  const allFindings: { path: string; finding: Finding; contribution: number }[] = [];
  const hotspotCandidates: { path: string; riskScore: number; findingCount: number }[] = [];

  for (const fr of fileResults) {
    if (fr.error) continue; // skip failed files in aggregation
    const r = fr.result;
    totalLines += r.stats.totalLines;
    totalFindings += r.stats.totalFindings;
    worstVerdict = worstVerdictOf(worstVerdict, r.verdict);
    maxRiskScore = Math.max(maxRiskScore, r.riskScore);

    for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
      bySeverity[sev] += r.stats.bySeverity[sev] ?? 0;
    }
    for (const [cat, count] of Object.entries(r.stats.byCategory)) {
      const c = cat as Category;
      byCategory[c] = (byCategory[c] ?? 0) + (count ?? 0);
    }

    for (const f of r.findings) {
      allFindings.push({
        path: fr.path,
        finding: f,
        contribution: findingRiskContribution(f),
      });
    }

    hotspotCandidates.push({
      path: fr.path,
      riskScore: r.riskScore,
      findingCount: r.stats.totalFindings,
    });
  }

  // Top 50 findings across the project — sort by severity (critical first),
  // then by per-finding risk contribution (highest first), then by path+line
  // for stable ordering.
  allFindings.sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf(a.finding.severity);
    const sb = SEVERITY_ORDER.indexOf(b.finding.severity);
    if (sa !== sb) return sa - sb;
    if (b.contribution !== a.contribution) return b.contribution - a.contribution;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    return a.finding.line - b.finding.line;
  });
  const topFindings = allFindings.slice(0, 50).map((af) => ({
    path: af.path,
    finding: af.finding,
  }));

  // Top 20 hotspot files — sort by risk score desc, then finding count desc.
  hotspotCandidates.sort((a, b) => {
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    return b.findingCount - a.findingCount;
  });
  const hotspotFiles = hotspotCandidates.slice(0, 20);

  return {
    totalFiles: fileResults.filter((f) => !f.error).length,
    totalLines,
    totalFindings,
    worstVerdict,
    maxRiskScore,
    bySeverity,
    byCategory,
    topFindings,
    hotspotFiles,
  };
}
