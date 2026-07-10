# Deploying Backdoor Sniper on Cloudflare

Backdoor Sniper runs on **Cloudflare Workers + D1** (SQLite on the edge) using
the [OpenNext Cloudflare](https://opennext.js.org/cloudflare) adapter. It uses
**Drizzle ORM** over the D1 binding — the Prisma/SQLite code was swapped for a
drop-in D1 facade (`src/lib/db.ts`) so the route handlers are unchanged.

## Prerequisites

- Node.js **>= 22** (`nvm install 22`)
- A Cloudflare account with **Workers** + **D1** enabled
- `CLOUDFLARE_API_TOKEN` with `Account > Workers Scripts`, `D1 > Edit`, and
  `Account > Account Settings` (for `wrangler`/zone) scopes
- `wrangler` (`npm i -g wrangler`) — log in once with `wrangler login`

## One-time setup

```bash
# 1. Install deps (Bun)
bun install

# 2. Authenticate wrangler (interactive) OR export a token:
export CLOUDFLARE_API_TOKEN="<your token>"

# 3. Create the D1 database (note the returned id)
wrangler d1 create backdoor-sniper
#   -> copy the "database_id" into wrangler.toml (database_id = "...")

# 4. Apply the schema migration
wrangler d1 execute backdoor-sniper --remote --file=./migrations/0001_init.sql
```

> The `database_name` in `wrangler.toml` is `backdoor-sniper`; the binding is `DB`
> (must match `[[d1_databases]] binding = "DB"` and `src/lib/db.ts`).

## Build & deploy

```bash
# Build for the Cloudflare Workers runtime (produces .open-next/worker.js)
bun run cf:build

# Deploy
bun run cf:deploy
```

`wrangler.toml` deploys to a `*.workers.dev` subdomain by default. To serve it on
**scan.insights.autos** (your existing Cloudflare zone):

1. In `wrangler.toml`, uncomment the `[env.production]` block and set
   `zone_name = "insights.autos"`.
2. Ensure `scan.insights.autos` is covered by the `insights.autos` zone in the
   Cloudflare dashboard (it is — the zone is already active).
3. Deploy: `wrangler deploy --env production`.

## Local dev (edge simulator)

```bash
bun run cf:dev          # wrangler dev — runs the Worker + D1 locally
```

The local D1 DB is created on first run under `.wrangler/`. To seed schema
locally: `wrangler d1 execute backdoor-sniper --local --file=./migrations/0001_init.sql`.

## Environment variables / secrets

Non-secret config goes in `[vars]` in `wrangler.toml`. For AI provider keys
(optional — the scanner works without them), use **secrets**, never commit them:

```bash
wrangler secret put OPENAI_API_KEY
wrangler secret put ANTHROPIC_API_KEY
```

Add the same names to `src/env.d.ts` so TypeScript knows about them.

## How the DB layer works (no Prisma on Cloudflare)

- `src/lib/db-schema.ts` — Drizzle tables mirroring `prisma/schema.prisma`.
- `src/lib/db.ts` — a **Prisma-compatible facade** over Drizzle/D1. Route
  handlers still call `db.scanRecord.findMany({ where, orderBy, select })` etc.
  The facade translates those into Drizzle queries, coercing SQLite's lack of
  native booleans (0/1) and JSON (TEXT) back into the shapes the UI expects,
  and exposes `createdAt`/`updatedAt` as `Date` objects.
- `migrations/0001_init.sql` — the authoritative D1 schema (`wrangler d1 execute`).

## Troubleshooting

- **`D1 binding 'DB' is not available`** — the Worker can't see the binding.
  Confirm `wrangler.toml` has `[[d1_databases]] binding = "DB"` and that you ran
  `wrangler d1 execute` against the **same** database name.
- **Build fails on Google Fonts** — `next/font/google` fetches at build time;
  ensure network egress during `bun run cf:build` (retry if it timed out).
- **`nodejs_compat`** is enabled in `wrangler.toml` because some routes use the
  Node.js runtime (e.g. `/api/trends`). Keep `compatibility_flags` as-is.

## Rollback notes

The app still builds as a plain Next.js standalone server (`bun run build` /
`bun run start`) for non-Cloudflare hosts. D1 is only used when the `DB` binding
is present; otherwise `src/lib/db.ts` throws a clear error.
