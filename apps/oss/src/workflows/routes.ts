import { timingSafeEqual } from "../security/crypto.ts";
// Sovereignly Workflow Routes -- MIT License
//
// POST /v1/workflows/trigger         Start a workflow
// GET  /v1/workflows                 List instances
// GET  /v1/workflows/definitions     List registered definitions
// GET  /v1/workflows/:id             Instance detail + step progress
// POST /v1/workflows/:id/cancel      Cancel running workflow
// GET  /v1/workflows/stats           Engine statistics

import type { Hono } from "hono";
import type { WorkflowEngine } from "./engine.ts";
import type { EventBus } from "../events/bus.ts";

export function registerWorkflowRoutes(
  app:    Hono,
  engine: WorkflowEngine,
  bus:    EventBus,
  opts:   { adminToken?: string }
) {

  function requireAuth(c: any): { ok: boolean; role: string } {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "")
               ?? c.req.header("authorization")?.slice(7);
    if (!token) return { ok: false, role: "" };
    if (opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken)) return { ok: true, role: "admin" };
    return { ok: false, role: "" };
  }

  // Trigger workflow
  app.post("/v1/workflows/trigger", async (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.name) return c.json({ error: "workflow name required" }, 400);

    try {
      const instance = await engine.trigger(
        body.name,
        body.params ?? {},
        body.tenantId,
        "api",
      );

      return c.json({
        workflowId: instance.id,
        name:       instance.name,
        status:     instance.status,
        steps:      instance.steps.map(s => ({ id: s.id, name: s.name, status: s.status })),
      }, 202);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  // List instances
  app.get("/v1/workflows", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const { status, tenantId, limit } = c.req.query();
    const list = engine.list({
      status: status as any,
      tenantId,
      limit: limit ? parseInt(limit) : undefined,
    });

    return c.json({
      count: list.length,
      workflows: list.map(w => ({
        id: w.id, name: w.name, status: w.status,
        tenantId: w.tenantId, startedAt: w.startedAt, completedAt: w.completedAt,
        steps: w.steps.map(s => ({ id: s.id, status: s.status })),
      })),
    });
  });

  // List definitions
  app.get("/v1/workflows/definitions", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const defs = engine.listDefinitions();
    return c.json({
      count: defs.length,
      definitions: defs.map(d => ({
        name:        d.name,
        description: d.description,
        version:     d.version,
        steps:       d.steps.map(s => ({
          id: s.id, name: s.name,
          dependsOn: s.dependsOn ?? [],
          retries: s.retries ?? 0,
        })),
      })),
    });
  });

  // Instance detail
  app.get("/v1/workflows/:id", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const instance = engine.get(c.req.param("id"));
    if (!instance) return c.json({ error: "not found" }, 404);

    return c.json({
      ...instance,
      durationMs: instance.completedAt
        ? instance.completedAt - instance.startedAt
        : Date.now() - instance.startedAt,
    });
  });

  // Cancel
  app.post("/v1/workflows/:id/cancel", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const ok = engine.cancel(c.req.param("id"));
    return ok
      ? c.json({ ok: true, status: "cancelled" })
      : c.json({ error: "workflow not found or not running" }, 404);
  });

  // Stats
  app.get("/v1/workflows/stats", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);
    return c.json(engine.stats());
  });
}
