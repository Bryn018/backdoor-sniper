"use client";

import { useState } from "react";
import type { ScanStats, Category } from "@/lib/detector/types";
import { CATEGORY_LABEL, CATEGORY_COLOR } from "@/lib/severity";

interface ThreatRadarProps {
  stats: ScanStats;
  size?: number;
}

/** Active categories to show on the radar (most threat-relevant). */
const RADAR_CATEGORIES: Category[] = [
  "code-execution",
  "command-execution",
  "reverse-shell",
  "network",
  "obfuscation",
  "deserialization",
  "credential-theft",
  "persistence",
];

export function ThreatRadar({ stats, size = 130 }: ThreatRadarProps) {
  const [hovered, setHovered] = useState<number | null>(null);
  const cx = size / 2;
  const cy = size / 2;
  const maxR = size / 2 - 20;

  // Build data points from stats
  const points = RADAR_CATEGORIES.map((cat) => ({
    cat,
    count: stats.byCategory[cat] ?? 0,
  }));

  const maxCount = Math.max(1, ...points.map((p) => p.count));

  // Compute polygon points
  const n = points.length;
  const angleStep = (2 * Math.PI) / n;

  const getXY = (i: number, value: number) => {
    const angle = angleStep * i - Math.PI / 2;
    const r = (value / maxCount) * maxR;
    return {
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    };
  };

  // Grid rings
  const rings = [0.25, 0.5, 0.75, 1.0];

  // Data polygon path
  const dataPath = points
    .map((p, i) => {
      const { x, y } = getXY(i, p.count);
      return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ") + " Z";

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Grid rings */}
        {rings.map((r, ri) => {
          const ringR = r * maxR;
          const ringPath = Array.from({ length: n }, (_, i) => {
            const angle = angleStep * i - Math.PI / 2;
            const x = cx + ringR * Math.cos(angle);
            const y = cy + ringR * Math.sin(angle);
            return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
          }).join(" ") + " Z";
          return (
            <path
              key={ri}
              d={ringPath}
              fill="none"
              stroke="currentColor"
              strokeWidth={0.5}
              className="text-muted-foreground/15"
            />
          );
        })}

        {/* Axis lines */}
        {points.map((_, i) => {
          const angle = angleStep * i - Math.PI / 2;
          const x = cx + maxR * Math.cos(angle);
          const y = cy + maxR * Math.sin(angle);
          return (
            <line
              key={i}
              x1={cx}
              y1={cy}
              x2={x}
              y2={y}
              stroke="currentColor"
              strokeWidth={0.5}
              className={
                hovered === i
                  ? "text-emerald-500/40"
                  : "text-muted-foreground/15"
              }
            />
          );
        })}

        {/* Data polygon fill */}
        {points.some((p) => p.count > 0) && (
          <>
            <path
              d={dataPath}
              fill="oklch(0.7 0.15 160 / 15%)"
              stroke="oklch(0.7 0.15 160 / 60%)"
              strokeWidth={1.5}
              strokeLinejoin="round"
            />
            {/* Data points with hover */}
            {points.map((p, i) => {
              if (p.count === 0) return null;
              const { x, y } = getXY(i, p.count);
              const color =
                CATEGORY_COLOR[p.cat as keyof typeof CATEGORY_COLOR] ??
                "#6b7280";
              return (
                <g key={i}>
                  {/* Invisible larger hit area */}
                  <circle
                    cx={x}
                    cy={y}
                    r={8}
                    fill="transparent"
                    className="cursor-pointer"
                    onMouseEnter={() => setHovered(i)}
                    onMouseLeave={() => setHovered(null)}
                  />
                  <circle
                    cx={x}
                    cy={y}
                    r={hovered === i ? 5 : 3}
                    fill={color}
                    stroke="var(--background)"
                    strokeWidth={1.5}
                    style={{ transition: "r 0.15s ease" }}
                    className="pointer-events-none"
                  />
                </g>
              );
            })}
          </>
        )}

        {/* Category labels (initials) */}
        {points.map((p, i) => {
          const angle = angleStep * i - Math.PI / 2;
          const labelR = maxR + 14;
          const x = cx + labelR * Math.cos(angle);
          const y = cy + labelR * Math.sin(angle);
          const anchor =
            Math.abs(Math.cos(angle)) < 0.1
              ? "middle"
              : Math.cos(angle) > 0
                ? "start"
                : "end";
          return (
            <text
              key={i}
              x={x}
              y={y}
              textAnchor={anchor}
              dominantBaseline="central"
              className={
                hovered === i ? "fill-foreground" : "fill-muted-foreground"
              }
              fontSize={6}
              fontFamily="var(--font-geist-sans)"
              style={{ transition: "fill 0.15s ease" }}
            >
              {(CATEGORY_LABEL[p.cat as keyof typeof CATEGORY_LABEL] ?? p.cat)
                .split(" ")
                .map((w) => w[0])
                .join("")}
            </text>
          );
        })}
      </svg>

      {/* Hover tooltip */}
      {hovered !== null && points[hovered] && (
        <div
          className="pointer-events-none absolute left-1/2 top-1/2 z-10 -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-popover px-2.5 py-1.5 text-center shadow-lg"
          style={{ minWidth: "90px" }}
        >
          <div className="flex items-center justify-center gap-1.5">
            <span
              className="inline-block h-1.5 w-1.5 rounded-full"
              style={{
                backgroundColor:
                  CATEGORY_COLOR[
                    points[hovered].cat as keyof typeof CATEGORY_COLOR
                  ] ?? "#6b7280",
              }}
            />
            <span className="text-[10px] font-medium text-foreground">
              {CATEGORY_LABEL[
                points[hovered].cat as keyof typeof CATEGORY_LABEL
              ] ?? points[hovered].cat}
            </span>
          </div>
          <div className="font-mono text-sm font-bold text-foreground">
            {points[hovered].count}{" "}
            <span className="text-[9px] font-normal text-muted-foreground">
              finding{points[hovered].count !== 1 ? "s" : ""}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
