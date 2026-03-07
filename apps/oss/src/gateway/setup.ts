/**
 * Sovereignly v3  Setup Wizard Route
 *
 * Serves the deployment wizard at /_sovereign/setup
 * Allows bootstrapping directly from the running instance.
 *
 * Usage: import and register with the Hono gateway.
 */

import type { Hono } from "hono";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dir = dirname(fileURLToPath(import.meta.url));

export function registerSetupRoute(app: Hono) {
  // Serve the wizard HTML
  app.get("/_sovereign/setup", async (c) => {
    // Try to serve bundled wizard (production)
    const wizardPath = join(__dir, "../../setup/index.html");
    const fallbackPath = join(__dir, "../../dashboard/index.html");

    let html: string;

    if (existsSync(wizardPath)) {
      html = readFileSync(wizardPath, "utf-8");
    } else if (existsSync(fallbackPath)) {
      html = readFileSync(fallbackPath, "utf-8");
    } else {
      // Minimal redirect page
      html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
        <title>Sovereignly Setup</title>
        <meta http-equiv="refresh" content="0;url=/_sovereign/health">
        </head><body>
        <p>Setup wizard not found. <a href="/_sovereign/health">Health check </a></p>
        </body></html>`;
    }

    return new Response(html, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  });

  // Quick-start API: returns everything needed to get started
  app.get("/_sovereign/setup/info", (c) => {
    return c.json({
      version: "3.0.0",
      runtime: "bun",
      bunVersion: Bun.version,
      endpoints: {
        health:    "/_sovereign/health",
        metrics:   "/_sovereign/metrics",
        functions: "/_sovereign/functions",
        kv:        "/_sovereign/kv/:ns/:key",
        setup:     "/_sovereign/setup",
      },
      quickstart: {
        deployFunction: {
          method: "POST",
          url:    "/_sovereign/functions",
          headers: {
            "content-type":      "application/json",
            "x-sovereign-token": "<ADMIN_TOKEN>",
          },
          body: {
            id:      "my-function",
            name:    "My First Function",
            route:   "/api/hello",
            methods: ["GET"],
            code:    "async function handler(req, env) {\n  return Response.json({ ok: true });\n}",
          },
        },
        testFunction: {
          method: "GET",
          url:    "/api/hello",
        },
      },
    });
  });
}
