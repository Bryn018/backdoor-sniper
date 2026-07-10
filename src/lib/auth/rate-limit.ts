import { NextRequest, NextResponse } from "next/server";

/**
 * In-memory token-bucket rate limiter (per-actor).
 *
 * For a single-process Next.js deployment this is sufficient and adds zero
 * external dependencies. For multi-instance deployments, swap the `buckets`
 * Map for a Redis backend without changing the call sites.
 *
 * Buckets refill at `refillPerSec` tokens per second up to `capacity`.
 */

interface Bucket {
  tokens: number;
  lastRefill: number;
}

interface RateLimitConfig {
  capacity: number;
  refillPerSec: number;
}

const DEFAULTS: RateLimitConfig = {
  capacity: 30, // burst of 30
  refillPerSec: 5, // 5 / sec sustained
};

const ANON_DEFAULTS: RateLimitConfig = {
  capacity: 10, // anonymous (web UI) gets a smaller burst
  refillPerSec: 2,
};

/**
 * Project-scan rate-limit tier — these scans are far more expensive than a
 * single-file scan (up to 500 files per request), so we use a separate,
 * more conservative bucket.
 *
 * Authenticated API keys: 5 project scans per minute (burst 5, refill 5/60s).
 * Anonymous web UI:       1 project scan per 5 minutes (burst 1, refill 1/300s).
 */
const PROJECT_DEFAULTS: RateLimitConfig = {
  capacity: 5,
  refillPerSec: 5 / 60, // ~0.0833 tokens/sec → 5 per minute sustained
};

const PROJECT_ANON_DEFAULTS: RateLimitConfig = {
  capacity: 1,
  refillPerSec: 1 / 300, // 1 per 5 minutes sustained
};

const buckets = new Map<string, Bucket>();

// Periodically purge stale buckets to avoid unbounded memory growth.
const PURGE_INTERVAL_MS = 5 * 60 * 1000;
const STALE_MS = 30 * 60 * 1000;
let lastPurge = Date.now();

function purgeStale() {
  const now = Date.now();
  if (now - lastPurge < PURGE_INTERVAL_MS) return;
  lastPurge = now;
  for (const [k, b] of buckets) {
    if (now - b.lastRefill > STALE_MS) buckets.delete(k);
  }
}

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  retryAfterMs: number;
  limit: number;
}

/**
 * Check the rate limit for an actor. Mutates the bucket in place.
 * Returns ok=false if the bucket is exhausted.
 */
export function checkRateLimit(
  actorKey: string,
  config?: Partial<RateLimitConfig>
): RateLimitResult {
  purgeStale();
  const cfg = { ...DEFAULTS, ...config };
  const now = Date.now();
  let b = buckets.get(actorKey);
  if (!b) {
    b = { tokens: cfg.capacity, lastRefill: now };
    buckets.set(actorKey, b);
  } else {
    const elapsed = (now - b.lastRefill) / 1000;
    b.tokens = Math.min(cfg.capacity, b.tokens + elapsed * cfg.refillPerSec);
    b.lastRefill = now;
  }
  if (b.tokens >= 1) {
    b.tokens -= 1;
    return { ok: true, remaining: Math.floor(b.tokens), retryAfterMs: 0, limit: cfg.capacity };
  }
  const retryAfterMs = Math.ceil((1 - b.tokens) / cfg.refillPerSec * 1000);
  return { ok: false, remaining: 0, retryAfterMs, limit: cfg.capacity };
}

/**
 * Convenience: enforce the rate limit on a request. Returns a 429 response
 * if the limit is exceeded, otherwise returns null and the caller continues.
 */
export function enforceRateLimit(
  req: NextRequest,
  actorKey: string,
  anonymous = false
): NextResponse | null {
  const cfg = anonymous ? ANON_DEFAULTS : DEFAULTS;
  const res = checkRateLimit(actorKey, cfg);
  if (res.ok) return null;
  return NextResponse.json(
    {
      error: "Rate limit exceeded. Slow down.",
      retryAfter: Math.ceil(res.retryAfterMs / 1000),
    },
    {
      status: 429,
      headers: {
        "Retry-After": String(Math.ceil(res.retryAfterMs / 1000)),
        "X-RateLimit-Limit": String(res.limit),
        "X-RateLimit-Remaining": "0",
      },
    }
  );
}

/** Build a stable actor key from a request (IP + optional API key id). */
export function actorKeyFromRequest(req: NextRequest, apiKeyId?: string | null): string {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown";
  return apiKeyId ? `key:${apiKeyId}` : `ip:${ip}`;
}

/**
 * Enforce the project-scan rate-limit tier. Uses a separate bucket
 * (namespaced with "project:") so it does NOT consume the single-file
 * scan budget. Returns a 429 response if exceeded, otherwise null.
 */
export function enforceProjectRateLimit(
  req: NextRequest,
  actorKey: string,
  anonymous = false
): NextResponse | null {
  const cfg = anonymous ? PROJECT_ANON_DEFAULTS : PROJECT_DEFAULTS;
  // Namespace the bucket so project scans don't share the single-file budget.
  const res = checkRateLimit(`project:${actorKey}`, cfg);
  if (res.ok) return null;
  return NextResponse.json(
    {
      error: "Project-scan rate limit exceeded. Project scans are limited to 5/min (API key) or 1/5min (anonymous).",
      retryAfter: Math.ceil(res.retryAfterMs / 1000),
    },
    {
      status: 429,
      headers: {
        "Retry-After": String(Math.ceil(res.retryAfterMs / 1000)),
        "X-RateLimit-Limit": String(res.limit),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Tier": "project",
      },
    }
  );
}
