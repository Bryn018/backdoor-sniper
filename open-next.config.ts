import { defineCloudflareConfig } from "@opennextjs/cloudflare";

export default defineCloudflareConfig({
  // D1 binding name must match wrangler.toml [[d1_databases]] binding = "DB".
  // All other defaults (assets, routes) are handled automatically.
});
