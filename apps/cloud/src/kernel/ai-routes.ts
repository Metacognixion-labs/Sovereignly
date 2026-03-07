import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
// Sovereignly AI OS + Cognitive Routes -- BSL License
//
// POST /v1/ai/command            Natural language infrastructure command
// GET  /v1/ai/predictions        Current metric predictions
// GET  /v1/ai/risk/:id           Entity risk score
// GET  /v1/ai/frequency          Event frequency analysis
// GET  /v1/ai/stats              Cognitive model stats

import type { Hono } from "hono";
import type { AIOperatingSystem } from "./ai-os.ts";
import type { CognitiveModel } from "./cognitive-model.ts";

export function registerAIRoutes(
  app:       Hono,
  aiOS:      AIOperatingSystem,
  cognitive: CognitiveModel,
  opts:      { adminToken?: string }
) {

  function requireAdmin(c: any): boolean {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    return !!opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken);
  }

  // Natural language command
  app.post("/v1/ai/command", async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.command) return c.json({ error: "command string required" }, 400);

    const result = await aiOS.run(body.command);
    return c.json(result);
  });

  // Parse only (no execution)
  app.post("/v1/ai/parse", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);

    const body = (c.req as any).json?.() ?? {};
    const command = (body as any).command ?? c.req.query("q") ?? "";
    if (!command) return c.json({ error: "command or q required" }, 400);

    const intent = aiOS.parse(command as string);
    const plan   = aiOS.plan(intent);
    return c.json({ intent, plan });
  });

  // Predictions
  app.get("/v1/ai/predictions", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({ predictions: cognitive.predict() });
  });

  // Risk score
  app.get("/v1/ai/risk/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(cognitive.riskScore(c.req.param("id")));
  });

  // Event frequency
  app.get("/v1/ai/frequency", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({ frequency: cognitive.eventFrequency() });
  });

  // Stats
  app.get("/v1/ai/stats", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(cognitive.stats());
  });
}
