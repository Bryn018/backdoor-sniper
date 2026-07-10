#!/bin/bash
# Post-create setup for GitHub Codespaces (and local devcontainer).
# Installs deps, prepares env + DB, and prints how to start the app.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Installing dependencies (bun)"
bun install

echo "==> Writing .env from example (if missing)"
if [ ! -f .env ]; then
  cp .env.example .env
fi

echo "==> Generating Prisma client + pushing schema"
bun run db:generate
bun run db:push

echo "==> Build sanity check (optional, can take a minute)"
# Run build once inside the container so 'bun run start' works immediately.
bun run build || echo "WARN: build failed; run 'bun run dev' instead."

cat <<'EOF'

Backdoor Sniper is ready.
  Start dev server : bun run dev      -> http://localhost:3000
  Or production    : bun run start    -> http://localhost:3000
  Caddy proxy      : caddy run --config Caddyfile  -> http://localhost:81

Open the forwarded port 3000 to use the scanner.
EOF
