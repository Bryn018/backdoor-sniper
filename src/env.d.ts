// Cloudflare runtime environment type declarations.
// `DB` is the D1 binding wired in wrangler.toml / open-next.config.ts.
interface CloudflareEnv {
  DB: D1Database;
  NODE_ENV?: string;
  // Add `wrangler secret put <NAME>` entries here as needed:
  // OPENAI_API_KEY?: string;
  // ANTHROPIC_API_KEY?: string;
}

declare module "cloudflare:workers" {
  export const env: CloudflareEnv;
}

export {};
