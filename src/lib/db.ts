// Prisma-compatible D1 facade (Cloudflare deployment).
//
// Backdoor Sniper's route handlers call `db.<model>.<method>(options)` using the
// Prisma client API. To migrate to Cloudflare D1 without rewriting every route,
// this module exposes a drop-in facade backed by Drizzle running on the D1 binding.
//
// Supported Prisma operations (those actually used by the app):
//   findUnique, findFirst, findMany, create, createMany, update, updateMany,
//   upsert, delete, deleteMany, count
//
// Option fields supported:
//   where, data, select, orderBy, take, skip, cursor, distinct
// Booleans are stored as 0/1 in SQLite and coerced on read. JSON columns are
// stored as TEXT and parsed on read.
import { drizzle, type DrizzleD1Database } from "drizzle-orm/d1";
import { sql } from "drizzle-orm";
import {
  tables,
  type TableName,
} from "./db-schema";
import type { SQLiteTable } from "drizzle-orm/sqlite-core";

// ---- D1 binding access ----------------------------------------------------
// On Cloudflare (OpenNext Cloudflare runtime) the D1 binding is exposed via the
// `cloudflare:workers` `env` module. We read it lazily so this file can be
// imported anywhere. In local/Node context (tests, `wrangler dev`) we fall
// back to `process.env` / a globally-injected binding.
type D1Like = {
  prepare: (query: string) => any;
  exec: (query: string) => any;
  batch?: (stmts: any[]) => Promise<any[]>;
};

let _db: DrizzleD1Database<any> | null = null;
let _bindingOverride: D1Like | null = null;

// Allow tests / local harness to inject a binding directly.
export function __setD1BindingForTests(b: D1Like) {
  _bindingOverride = b;
  _db = null;
}

function getD1Binding(): D1Like | null {
  if (_bindingOverride) return _bindingOverride;

  // 1) OpenNext Cloudflare runtime sets the Cloudflare context (with `env`,
  //    containing our D1 binding) on a global symbol. Read it directly —
  //    `opennextjs/cloudflare` is NOT resolvable at runtime in the Worker.
  try {
    const sym = Symbol.for("__cloudflare-context__");
    const ctx = (globalThis as any)[sym];
    if (ctx?.env?.DB) return ctx.env.DB as D1Like;
  } catch {
    /* not on the OpenNext Cloudflare runtime */
  }

  // 2) Cloudflare Workers built-in module (ESM). Guarded so it never breaks
  //    the Node / better-sqlite3 test path.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const cf = require("cloudflare:workers") as { env?: { DB?: D1Like } };
    if (cf?.env?.DB) return cf.env.DB as D1Like;
  } catch {
    /* not on a Workers runtime */
  }

  // 3) wrangler dev / Node fallback
  const env = (globalThis as any).process?.env;
  if (env?.DB) return env.DB as D1Like;
  return null;
}

export function getDb() {
  if (_db) return _db;
  const binding = getD1Binding();
  if (!binding) {
    throw new Error(
      "D1 binding 'DB' is not available. Ensure wrangler.toml declares [[d1_databases]] name = \"DB\" and the app runs on Cloudflare.",
    );
  }
  _db = drizzle(binding as any);
  return _db;
}

// Expose a settable DB for local tests with better-sqlite3.
export function __setDbForTests(d: DrizzleD1Database<any>) {
  _db = d;
}

// ---- value coercion -------------------------------------------------------
const JSON_COLS = new Set([
  "findings",
  "policyViolations",
  "scopes",
  "rules",
  "events",
  "metadata",
  "payload",
]);

// Only genuine SQLite-stored BOOLEAN columns (0/1). Integers such as
// riskScore/useCount are NOT booleans and must not be coerced.
const BOOL_COLS = new Set([
  "published",
  "isDefault",
  "policyPassed",
  "enabled",
  "notifyOnFail",
  "notifyOnCritical",
]);

// Date columns — stored as epoch-ms integers, exposed as Date objects.
const DATE_COLS = new Set([
  "createdAt",
  "updatedAt",
  "lastUsedAt",
  "revokedAt",
  "expiresAt",
  "lastRunAt",
  "nextRunAt",
  "startedAt",
  "finishedAt",
  "lastDeliveryAt",
  "deliveredAt",
]);

function toStorage(row: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(row)) {
    if (v === undefined) continue;
    if (JSON_COLS.has(k) && v != null && typeof v !== "string") {
      out[k] = JSON.stringify(v);
    } else if (DATE_COLS.has(k) && v != null) {
      out[k] = v instanceof Date ? v.getTime() : Number(v);
    } else if (typeof v === "boolean") {
      out[k] = v ? 1 : 0;
    } else if (v instanceof Date) {
      out[k] = v.getTime();
    } else {
      out[k] = v;
    }
  }
  return out;
}

function fromStorage(
  row: Record<string, any> | undefined,
  select?: Record<string, boolean>,
): Record<string, any> | undefined {
  if (!row) return row;
  const hasSelect = select && Object.keys(select).length > 0;
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(row)) {
    if (hasSelect && !(k in select)) continue;
    if (v === null) {
      out[k] = null; // preserve null (nullable bools/json)
      continue;
    }
    if (JSON_COLS.has(k) && typeof v === "string") {
      try {
        out[k] = JSON.parse(v);
      } catch {
        out[k] = v;
      }
    } else if (DATE_COLS.has(k) && v != null) {
      out[k] = new Date(Number(v));
    } else if (BOOL_COLS.has(k)) {
      out[k] = v === 1 || v === true;
    } else {
      out[k] = v;
    }
  }
  return out;
}

type Where = Record<string, any>;

function sqlCond(table: SQLiteTable, key: string, op: string, val: any) {
  const col = (table as any)[key];
  const v = val instanceof Date ? val.getTime() : val;
  switch (op) {
    case "equals":
    case "eq":
    case "is":
      return sql`${col} = ${v}`;
    case "not":
      return sql`${col} != ${v}`;
    case "contains":
      return sql`${col} LIKE ${"%" + String(v) + "%"}`;
    case "startsWith":
      return sql`${col} LIKE ${String(v) + "%"}`;
    case "endsWith":
      return sql`${col} LIKE ${"%" + String(v)}`;
    case "gt":
      return sql`${col} > ${v}`;
    case "gte":
      return sql`${col} >= ${v}`;
    case "lt":
      return sql`${col} < ${v}`;
    case "lte":
      return sql`${col} <= ${v}`;
    case "in":
      return sql`${col} IN ${v}`;
    case "notIn":
      return sql`${col} NOT IN ${v}`;
    default:
      return sql`${col} = ${v}`;
  }
}

function buildClauseSQL(
  table: SQLiteTable,
  where: Where,
): any {
  // returns a drizzle sql fragment for the where object (used for OR/AND/NOT)
  let fragment: any = null;
  for (const [key, cond] of Object.entries(where)) {
    if (key === "OR" || key === "AND") {
      const clauses = (Array.isArray(cond) ? cond : [cond]) as Record<
        string,
        any
      >[];
      const built = clauses.map((c) => buildClauseSQL(table, c));
      const joined = sql.join(built, key === "OR" ? sql` OR ` : sql` AND `);
      const f = sql`(${joined})`;
      fragment = fragment ? sql`${fragment} AND ${f}` : f;
      continue;
    }
    if (key === "NOT") {
      const f = sql`NOT (${buildClauseSQL(table, cond)})`;
      fragment = fragment ? sql`${fragment} AND ${f}` : f;
      continue;
    }
    const f =
      cond && typeof cond === "object" && !Array.isArray(cond)
        ? sql.join(
            Object.entries(cond).map(([op, val]) =>
              sqlCond(table, key, op, val),
            ),
            sql` AND `,
          )
        : (() => {
            const col = (table as any)[key];
            return sql`${col} = ${cond}`;
          })();
    fragment = fragment ? sql`${fragment} AND ${f}` : f;
  }
  return fragment ?? sql`1=1`;
}

function buildWhere(
  query: any,
  table: SQLiteTable,
  where?: Where,
): any {
  if (!where) return query;
  return query.where(buildClauseSQL(table, where));
}

function applyOpts(
  query: any,
  table: SQLiteTable,
  opts: any,
) {
  query = buildWhere(query, table, opts?.where);
  if (opts?.orderBy) {
    const ob = Array.isArray(opts.orderBy) ? opts.orderBy : [opts.orderBy];
    for (const o of ob) {
      for (const [k, dir] of Object.entries(o as Record<string, string>)) {
        const col = (table as any)[k];
        query =
          dir === "desc"
            ? query.orderBy(sql`${col} DESC`)
            : query.orderBy(sql`${col} ASC`);
      }
    }
  }
  if (opts?.take != null) query = query.limit(opts.take);
  if (opts?.skip != null) query = query.offset(opts.skip);
  return query;
}

// ---- facade model ---------------------------------------------------------
function makeModel(name: TableName) {
  const table = (tables as any)[name] as SQLiteTable;
  return {
    async findUnique(opts: any) {
      const rows = await applyOpts(
        getDb().select().from(table),
        table,
        { where: opts?.where },
      ).limit(1).all();
      const row = rows[0];
      return fromStorage(row, opts?.select);
    },
    async findFirst(opts: any = {}) {
      const rows = await applyOpts(
        getDb().select().from(table),
        table,
        { where: opts?.where, orderBy: opts?.orderBy },
      ).limit(1).all();
      return fromStorage(rows[0], opts?.select);
    },
    async findMany(opts: any = {}) {
      const rows = await applyOpts(
        getDb().select().from(table),
        table,
        opts,
      ).all();
      return rows.map((r: any) => fromStorage(r, opts?.select));
    },
    async create(opts: any) {
      const data = toStorage(opts?.data ?? {});
      // Mirror Prisma defaults: auto-generate id (cuid-like) and timestamps.
      if (data.id == null) data.id = crypto.randomUUID();
      if (data.createdAt == null) data.createdAt = Date.now();
      if (data.updatedAt != null) data.updatedAt = Date.now();
      else if ("updatedAt" in (table as any)) data.updatedAt = Date.now();
      await getDb().insert(table).values(data).run();
      const created = await getDb()
        .select()
        .from(table)
        .where(sql`${(table as any).id} = ${data.id}`)
        .limit(1)
        .all();
      return fromStorage(created[0]);
    },
    async createMany(opts: any) {
      const rows = Array.isArray(opts?.data)
        ? opts.data
        : [opts?.data];
      const values = rows.map((r: any) => {
        const d = toStorage(r);
        if (d.id == null) d.id = crypto.randomUUID();
        if (d.createdAt == null) d.createdAt = Date.now();
        if ("updatedAt" in (table as any)) d.updatedAt = Date.now();
        return d;
      });
      if (values.length) await getDb().insert(table).values(values).run();
      return { count: values.length };
    },
    async update(opts: any) {
      const data = toStorage(opts?.data ?? {});
      if ("updatedAt" in (table as any) && data.updatedAt == null)
        data.updatedAt = Date.now();
      await getDb()
        .update(table)
        .set(data)
        .where(sql`${(table as any).id} = ${opts?.where?.id}`)
        .run();
      const updated = await getDb()
        .select()
        .from(table)
        .where(sql`${(table as any).id} = ${opts?.where?.id}`)
        .limit(1)
        .all();
      return fromStorage(updated[0]);
    },
    async updateMany(opts: any) {
      const data = toStorage(opts?.data ?? {});
      const q = getDb().update(table).set(data);
      const res = (await buildWhere(q, table, opts?.where).run()) as any;
      return { count: res?.changes ?? res?.meta?.changes ?? 0 };
    },
    async upsert(opts: any) {
      const existing = await getDb()
        .select()
        .from(table)
        .where(
          sql`${(table as any).id} = ${opts?.where?.id}`,
        )
        .limit(1)
        .all();
      if (existing[0]) {
        return this.update({
          where: opts.where,
          data: opts.update,
        });
      }
      return this.create({ data: opts.create });
    },
    async delete(opts: any) {
      const res = (await getDb()
        .delete(table)
        .where(sql`${(table as any).id} = ${opts?.where?.id}`)
        .run()) as any;
      return { count: res?.changes ?? res?.meta?.changes ?? 0 };
    },
    async deleteMany(opts: any = {}) {
      const q = getDb().delete(table);
      const res = (opts?.where
        ? await buildWhere(q, table, opts.where).run()
        : await q.run()) as any;
      return { count: res?.changes ?? res?.meta?.changes ?? 0 };
    },
    async count(opts: any = {}) {
      const q = getDb().select({ c: sql`COUNT(*)` }).from(table);
      const rows = opts?.where
        ? await buildWhere(q, table, opts.where).all()
        : await q.all();
      return Number(rows[0]?.c ?? 0);
    },
  };
}

// ---- public db object (Prisma-shaped) ------------------------------------
function makeDb() {
  const dbObj: Record<string, any> = {};
  for (const name of Object.keys(tables) as TableName[]) {
    dbObj[name] = makeModel(name);
  }
  return dbObj as any;
}

export const db = makeDb();
export default db;
