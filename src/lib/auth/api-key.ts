import { createHash, randomBytes } from "node:crypto";
import { db } from "@/lib/db";

/**
 * API key authentication for enterprise / CI-CD access.
 *
 * Keys are prefixed `bdp_live_` and shown in full only ONCE at creation time.
 * Only the SHA-256 hash is persisted to the database, so a DB leak does not
 * expose usable keys.
 */

export const KEY_PREFIX = "bdp_live_";

export const VALID_SCOPES = [
  "scan:run", // POST /api/scan
  "scan:read", // GET /api/history, /api/stats, /api/audit
  "policy:manage", // create / edit / delete policies
  "apikey:manage", // create / revoke api keys
  "admin", // everything
] as const;

export type Scope = (typeof VALID_SCOPES)[number];

export interface AuthenticatedKey {
  id: string;
  name: string;
  scopes: Scope[];
  prefix: string;
}

/** Generate a new full API key string and its SHA-256 hash. */
export function generateApiKey(): { fullKey: string; keyHash: string; prefix: string } {
  const raw = randomBytes(32).toString("base64url");
  const fullKey = KEY_PREFIX + raw;
  const keyHash = hashKey(fullKey);
  const prefix = fullKey.slice(0, 14); // bdp_live_XXXX
  return { fullKey, keyHash, prefix };
}

/** Hash a full key for storage. SHA-256 is sufficient because keys are 32 bytes of entropy. */
export function hashKey(fullKey: string): string {
  return createHash("sha256").update(fullKey).digest("hex");
}

/** Parse scopes from a JSON string, returning only valid scopes. */
export function parseScopes(raw: string): Scope[] {
  try {
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) return [];
    return arr.filter((s): s is Scope => (VALID_SCOPES as readonly string[]).includes(s as string));
  } catch {
    return [];
  }
}

/**
 * Validate a Bearer token from the Authorization header.
 * Returns the key record if valid & not revoked & not expired, else null.
 */
export async function validateApiKey(authHeader: string | null): Promise<AuthenticatedKey | null> {
  if (!authHeader) return null;
  const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  if (!m) return null;
  const fullKey = m[1].trim();
  if (!fullKey.startsWith(KEY_PREFIX)) return null;

  const keyHash = hashKey(fullKey);
  let record;
  try {
    record = await db.apiKey.findUnique({
      where: { keyHash },
    });
  } catch {
    return null;
  }
  if (!record) return null;
  if (record.revokedAt) return null;
  if (record.expiresAt && record.expiresAt < new Date()) return null;

  // Fire-and-forget usage update (do not block the request on it).
  db.apiKey
    .update({
      where: { id: record.id },
      data: { lastUsedAt: new Date(), useCount: { increment: 1 } },
    })
    .catch(() => {
      /* ignore */
    });

  return {
    id: record.id,
    name: record.name,
    scopes: parseScopes(record.scopes),
    prefix: record.prefix,
  };
}

/** Check whether an authenticated key has a given scope. */
export function hasScope(key: AuthenticatedKey | null, scope: Scope): boolean {
  if (!key) return false;
  if (key.scopes.includes("admin")) return true;
  return key.scopes.includes(scope);
}
