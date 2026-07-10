"use client";

import type { ScanStats } from "@/lib/detector/types";
import { SEVERITY_BADGE, SEVERITY_LABEL } from "@/lib/severity";
import type { Severity } from "@/lib/detector/types";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityBreakdown({ stats }: { stats: ScanStats }) {
  const total = stats.totalFindings || 1;
  return (
    <div className="space-y-2.5">
      {ORDER.map((sev) => {
        const count = stats.bySeverity[sev];
        const pct = (count / total) * 100;
        const s = SEVERITY_BADGE[sev];
        return (
          <div key={sev} className="flex items-center gap-3">
            <span
              className={`inline-flex h-2 w-2 shrink-0 rounded-full ${s.dot}`}
            />
            <span className="w-16 text-xs font-medium text-foreground/80">
              {SEVERITY_LABEL[sev]}
            </span>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full ${s.bar} transition-all duration-700`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="w-8 text-right font-mono text-xs tabular-nums text-muted-foreground">
              {count}
            </span>
          </div>
        );
      })}
    </div>
  );
}
