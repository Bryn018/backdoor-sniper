"use client";

import { useEffect, useState, useRef } from "react";
import { riskStroke } from "@/lib/severity";

interface RiskGaugeProps {
  score: number;
  size?: number;
  verdict?: "clean" | "suspicious" | "malicious" | "dangerous";
}

export function RiskGauge({ score, size = 160, verdict }: RiskGaugeProps) {
  const [displayScore, setDisplayScore] = useState(0);
  const startRef = useRef<number | null>(null);
  const fromRef = useRef(0);
  const rafRef = useRef<number>(0);

  const clampedScore = Math.min(100, Math.max(0, score));
  const duration = 800;

  // Animate the score counter from 0 to the actual value
  useEffect(() => {
    fromRef.current = displayScore;
    startRef.current = null;

    const tick = (now: number) => {
      if (startRef.current === null) startRef.current = now;
      const elapsed = now - startRef.current;
      const t = Math.min(1, elapsed / duration);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - t, 3);
      const current = Math.round(
        fromRef.current + (clampedScore - fromRef.current) * eased
      );
      setDisplayScore(current);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [score]);

  const stroke = 12;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (clampedScore / 100) * c;
  const color = riskStroke(score);

  // Pulse animation for dangerous scores
  const needsPulse = verdict === "dangerous" || score >= 70;

  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
    >
      {/* Glow ring behind gauge for dangerous */}
      {needsPulse && (
        <div
          className="absolute inset-0 rounded-full animate-pulse-glow"
          style={{
            background: `radial-gradient(circle, ${color}20 0%, transparent 70%)`,
          }}
        />
      )}

      <svg width={size} height={size} className="-rotate-90">
        {/* Background track with subtle gradient */}
        <defs>
          <linearGradient id="gauge-track" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.15" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.05" />
          </linearGradient>
          <linearGradient id="gauge-fill" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={color} stopOpacity="1" />
            <stop offset="100%" stopColor={color} stopOpacity="0.7" />
          </linearGradient>
          <filter id="gauge-glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="url(#gauge-track)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="url(#gauge-fill)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          filter={needsPulse ? "url(#gauge-glow)" : undefined}
          style={{
            transition: "stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)",
          }}
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-mono text-4xl font-bold tabular-nums"
          style={{ color }}
        >
          {displayScore}
        </span>
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
          Risk Score
        </span>
      </div>
    </div>
  );
}
