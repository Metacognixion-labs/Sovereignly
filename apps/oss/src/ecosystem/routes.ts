import { timingSafeEqual } from "../security/crypto.ts";
// Sovereignly Ecosystem Routes -- MIT License
//
// GET  /v1/marketplace              List published plugins
// POST /v1/marketplace/publish      Publish a plugin
// POST /v1/marketplace/install      Install a plugin
// GET  /v1/marketplace/stats        Marketplace stats
// GET  /v1/templates                List templates
// GET  /v1/templates/:id            Template detail
// GET  /v1/gamification/leaderboard Developer leaderboard
// GET  /v1/gamification/profile/:id Developer profile
// GET  /v1/gamification/stats       Gamification stats

import type { Hono } from "hono";
import type { PluginRegistry } from "./plugins.ts";
import type { TemplateRegistry } from "./templates.ts";
import type { GamificationEngine } from "./gamification.ts";

export function registerEcosystemRoutes(
  app:           Hono,
  plugins:       PluginRegistry,
  templates:     TemplateRegistry,
  gamification:  GamificationEngine,
  opts:          { adminToken?: string }
) {

  function requireAuth(c: any): { ok: boolean; role: string; userId: string } {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "")
               ?? c.req.header("authorization")?.slice(7);
    if (!token) return { ok: false, role: "", userId: "" };
    if (opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken)) return { ok: true, role: "admin", userId: "admin" };
    return { ok: false, role: "", userId: "" };
  }

  // ── Marketplace ──

  app.get("/v1/marketplace", (c) => {
    const { type, tag } = c.req.query();
    const list = plugins.listPublished({ type: type as any, tag });
    return c.json({ count: list.length, plugins: list });
  });

  app.post("/v1/marketplace/publish", async (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.name || !body.type) return c.json({ error: "name and type required" }, 400);

    const manifest = plugins.publish({
      name:        body.name,
      type:        body.type,
      version:     body.version ?? "1.0.0",
      description: body.description ?? "",
      author:      body.author ?? auth.userId,
      authorId:    auth.userId,
      license:     body.license ?? "MIT",
      homepage:    body.homepage,
      repository:  body.repository,
      tags:        body.tags ?? [],
      permissions: body.permissions ?? [],
      entrypoint:  body.entrypoint ?? "index.ts",
      config:      body.config,
    });

    return c.json({ plugin: manifest }, 201);
  });

  app.post("/v1/marketplace/install", async (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.pluginId) return c.json({ error: "pluginId required" }, 400);

    try {
      const installed = plugins.install(body.pluginId, {
        tenantId:    body.tenantId,
        installedBy: auth.userId,
        config:      body.config,
      });
      return c.json({ installed }, 201);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  app.get("/v1/marketplace/stats", (c) => c.json(plugins.stats()));

  // ── Templates ──

  app.get("/v1/templates", (c) => {
    const { category } = c.req.query();
    return c.json({ templates: templates.list(category), stats: templates.stats() });
  });

  app.get("/v1/templates/:id", (c) => {
    const t = templates.get(c.req.param("id"));
    if (!t) return c.json({ error: "not found" }, 404);
    return c.json(t);
  });

  // ── Gamification ──

  app.get("/v1/gamification/leaderboard", (c) => {
    const { limit } = c.req.query();
    return c.json({ leaderboard: gamification.leaderboard(limit ? parseInt(limit) : 20) });
  });

  app.get("/v1/gamification/profile/:id", (c) => {
    const profile = gamification.profile(c.req.param("id"));
    return c.json(profile);
  });

  app.get("/v1/gamification/stats", (c) => c.json(gamification.stats()));

  // ── Ecosystem overview ──

  app.get("/v1/ecosystem", (c) => {
    return c.json({
      marketplace:   plugins.stats(),
      templates:     templates.stats(),
      gamification:  gamification.stats(),
    });
  });
}
