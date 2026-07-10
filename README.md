# Backdoor Sniper 🎯

Static-analysis security scanner that detects **backdoors, reverse shells,
obfuscated payloads, credential stealers, and persistence mechanisms** in source
code. Scan a snippet, a batch of files, or a whole project — get explained
findings, SARIF/PDF reports, audit trails, and an optional AI analysis layer.

> Defensive tool. Use only on code you own or are authorized to audit.

**Live:** https://scan.insights.autos  ·  **Repo:** https://github.com/Bryn018/backdoor-sniper

## Features

- **Multi-mode scanner** — single, batch, project-wide, streaming
- **Rule engine** — `src/lib/detector` flags known backdoor / miner / reverse-shell patterns
- **AI analysis** — optional LLM explanations of findings
- **Reports** — SARIF (CI-friendly) and PDF export
- **History & audit log** — every scan recorded for compliance
- **Policies & suppressions** — tune signal vs. noise
- **Scheduled scans + webhooks** — recurring scans with notifications
- **Scoped API keys** — programmatic access (`scan:run`, `scan:read`)
- **Trends & stats** — track backdoor exposure over time

## Tech stack

- Next.js 16 (App Router) · React 19 · TypeScript
- Tailwind CSS 4 · shadcn/ui
- **Cloudflare Workers + D1** (SQLite on the edge) via OpenNext, using **Drizzle ORM**
- Bun runtime/package manager

## Quick start (local)

```bash
bun install
cp .env.example .env
bun run dev                              # http://localhost:3000
```

Production build: `bun run build && bun run start`.

> Local development uses an in-memory/SQLite facade; the production deployment
> runs on Cloudflare D1. See [DEPLOY.md](./DEPLOY.md) for the D1 setup.

## Deploy (Cloudflare, automated)

Every push to `main` runs the GitHub Actions workflow
(`.github/workflows/deploy.yml`) which builds with OpenNext and deploys to
Cloudflare Workers + D1 using the `CLOUDFLARE_API_TOKEN` repo secret. Migration
SQL lives in `migrations/0001_init.sql`. Full walkthrough → [DEPLOY.md](./DEPLOY.md).

## API

REST endpoints under `/api/*`: `/api/scan`, `/api/scan/batch`,
`/api/scan/project`, `/api/scan/stream`, plus history, audit, policies,
suppressions, scheduled scans, webhooks, stats, trends, and SARIF/PDF export.
Create a scoped API key from the UI to call them.

## Project layout

```
src/app/            UI + /api/* route handlers
src/lib/detector/   detection engine & rules
src/lib/db.ts       Prisma-compatible D1 facade (Drizzle)
migrations/         D1 schema SQL
scripts/            PDF report generator (Python)
```

## License

Use responsibly and only on code you are authorized to audit.
