#!/bin/bash
# One-shot Codespace/container launcher for Backdoor Sniper.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || cp .env.example .env
bun run db:generate
bun run db:push
exec bun run dev
