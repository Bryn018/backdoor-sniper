/**
 * Lightweight cron expression parser + scheduled-scan runner.
 *
 * Supports two schedule formats:
 *   1. Standard 5-field cron: "0 2 * * *" (minute hour day month weekday)
 *      Weekday: 0/7 = Sunday, 1..6 = Mon..Sat. Supports ranges, lists, and `*`.
 *      Does NOT support step values (slash-N), `L`, `W`, `#` macros — kept
 *      minimal to avoid pulling in a heavy dependency.
 *   2. Shorthand: "every-Nm" (e.g. "every-15m", "every-2h", "every-1d")
 *      N must be a positive integer; m=minutes, h=hours, d=days.
 */

export type ParsedSchedule =
  | { ok: true; kind: "cron"; fields: { minute: number[]; hour: number[]; day: number[]; month: number[]; weekday: number[] } }
  | { ok: true; kind: "interval"; unit: "m" | "h" | "d"; value: number }
  | { ok: false; error: string };

const CRON_RANGES = {
  minute: [0, 59],
  hour: [0, 23],
  day: [1, 31],
  month: [1, 12],
  weekday: [0, 7], // 0 and 7 both = Sunday
} as const;

function parseCronField(value: string, range: readonly [number, number]): number[] {
  const [lo, hi] = range;
  const out = new Set<number>();
  for (const part of value.split(",")) {
    const trimmed = part.trim();
    if (trimmed === "*") {
      for (let i = lo; i <= hi; i++) out.add(i);
      continue;
    }
    const rangeMatch = /^(\d+)-(\d+)$/.exec(trimmed);
    if (rangeMatch) {
      const a = Number(rangeMatch[1]);
      const b = Number(rangeMatch[2]);
      if (a < lo || b > hi || a > b) throw new Error(`Invalid range: ${trimmed}`);
      for (let i = a; i <= b; i++) out.add(i);
      continue;
    }
    const singleMatch = /^\d+$/.exec(trimmed);
    if (singleMatch) {
      const n = Number(trimmed);
      if (n < lo || n > hi) throw new Error(`Out of range: ${trimmed}`);
      out.add(n === 7 && range === CRON_RANGES.weekday ? 0 : n);
      continue;
    }
    throw new Error(`Invalid field: ${trimmed}`);
  }
  return Array.from(out).sort((a, b) => a - b);
}

export function parseSchedule(s: string): ParsedSchedule {
  const trimmed = s.trim();

  // Shorthand: every-Nm / every-Nh / every-Nd
  const intervalMatch = /^every-(\d+)([mhd])$/.exec(trimmed);
  if (intervalMatch) {
    const value = Number(intervalMatch[1]);
    if (value <= 0) return { ok: false, error: "Interval must be positive" };
    if (intervalMatch[2] === "m" && value < 1) return { ok: false, error: "Minute interval must be ≥ 1" };
    if (intervalMatch[2] === "h" && value > 168) return { ok: false, error: "Hour interval must be ≤ 168" };
    if (intervalMatch[2] === "d" && value > 365) return { ok: false, error: "Day interval must be ≤ 365" };
    return { ok: true, kind: "interval", unit: intervalMatch[2] as "m" | "h" | "d", value };
  }

  // 5-field cron
  const fields = trimmed.split(/\s+/);
  if (fields.length !== 5) {
    return {
      ok: false,
      error: "Schedule must be 5-field cron or 'every-Nm/Nh/Nd' shorthand",
    };
  }
  try {
    const [minute, hour, day, month, weekday] = fields.map((f, i) =>
      parseCronField(f, Object.values(CRON_RANGES)[i] as readonly [number, number])
    );
    return { ok: true, kind: "cron", fields: { minute, hour, day, month, weekday } };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Invalid cron expression" };
  }
}

/** Compute the next run time from a parsed schedule, starting from `from` (default: now). */
export function computeNextRunAt(
  parsed: Extract<ParsedSchedule, { ok: true }>,
  from: Date = new Date()
): Date {
  if (parsed.kind === "interval") {
    const ms =
      parsed.unit === "m" ? parsed.value * 60_000 : parsed.unit === "h" ? parsed.value * 3_600_000 : parsed.value * 86_400_000;
    return new Date(from.getTime() + ms);
  }

  // Cron: walk forward minute-by-minute, up to ~366 days
  const next = new Date(from);
  next.setSeconds(0, 0);
  next.setMinutes(next.getMinutes() + 1);

  for (let i = 0; i < 366 * 24 * 60; i++) {
    const m = next.getMinutes();
    const h = next.getHours();
    const day = next.getDate();
    const month = next.getMonth() + 1;
    let wd = next.getDay();
    if (parsed.fields.minute.includes(m) &&
        parsed.fields.hour.includes(h) &&
        parsed.fields.day.includes(day) &&
        parsed.fields.month.includes(month) &&
        parsed.fields.weekday.includes(wd)) {
      return next;
    }
    next.setMinutes(next.getMinutes() + 1);
  }
  // Fallback: 1 year out (should never happen for valid expressions)
  return new Date(from.getTime() + 365 * 86_400_000);
}

/**
 * Find all scheduled scans whose nextRunAt is due (<= now), execute them
 * (single-pass), and reschedule. Returns the number of scans executed.
 *
 * Called by the /api/scheduled-scans/run API on a timer (every minute).
 */
export async function runDueScheduledScans(): Promise<{ ran: number; succeeded: number; failed: number }> {
  // Import lazily to avoid pulling into client bundles
  const { db } = await import("@/lib/db");
  const { scanSource } = await import("@/lib/scheduled-scan-runner");

  const now = new Date();
  const due = await db.scheduledScan.findMany({
    where: { enabled: true, nextRunAt: { lte: now } },
    take: 20,
  });

  let ran = 0;
  let succeeded = 0;
  let failed = 0;

  for (const job of due) {
    ran++;
    // Mark as running
    const runRecord = await db.scheduledScanRun.create({
      data: {
        scheduledScanId: job.id,
        status: "running",
        startedAt: now,
      },
    });
    await db.scheduledScan.update({
      where: { id: job.id },
      data: { lastRunAt: now, lastRunStatus: "running" },
    });

    try {
      const result = await scanSource(job.sourceType, job.sourceData, job.policyName ?? undefined, job.id);
      await db.scheduledScanRun.update({
        where: { id: runRecord.id },
        data: {
          status: "success",
          finishedAt: new Date(),
          scanRecordId: result.scanRecordId,
          riskScore: result.riskScore,
          verdict: result.verdict,
          findingCount: result.findingCount,
          policyPassed: result.policyPassed,
        },
      });
      await db.scheduledScan.update({
        where: { id: job.id },
        data: {
          lastRunStatus: "success",
          lastScanId: result.scanRecordId,
        },
      });
      succeeded++;
    } catch (e) {
      await db.scheduledScanRun.update({
        where: { id: runRecord.id },
        data: {
          status: "failure",
          finishedAt: new Date(),
          error: e instanceof Error ? e.message.slice(0, 1000) : String(e),
        },
      });
      await db.scheduledScan.update({
        where: { id: job.id },
        data: { lastRunStatus: "failure" },
      });
      failed++;
    }

    // Reschedule regardless of success/failure
    const parsed = parseSchedule(job.schedule);
    if (parsed.ok) {
      const next = computeNextRunAt(parsed, now);
      await db.scheduledScan.update({
        where: { id: job.id },
        data: { nextRunAt: next },
      });
    }
  }

  return { ran, succeeded, failed };
}
