import { timingSafeEqual } from "../security/crypto.ts";
// Sovereignly Agent Routes -- MIT License
//
// POST /v1/agents/execute         Run one observe/plan/execute cycle
// GET  /v1/agents                 List registered agents
// GET  /v1/agents/:id             Agent detail + run history
// POST /v1/agents/:id/start       Start agent (scheduled + event-driven)
// POST /v1/agents/:id/stop        Stop agent
// GET  /v1/agents/stats           Runtime statistics

import type { Hono } from "hono";
import type { AgentRuntime } from "./runtime.ts";
import type { EventBus } from "../events/bus.ts";

export function registerAgentRoutes(
  app:     Hono,
  runtime: AgentRuntime,
  bus:     EventBus,
  opts:    { adminToken?: string }
) {

  function requireAuth(c: any): { ok: boolean; role: string } {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "")
               ?? c.req.header("authorization")?.slice(7);
    if (!token) return { ok: false, role: "" };
    if (opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken)) return { ok: true, role: "admin" };
    return { ok: false, role: "" };
  }

  // Execute one cycle for an agent
  app.post("/v1/agents/execute", async (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.agentId) return c.json({ error: "agentId required" }, 400);

    try {
      const report = await runtime.run(body.agentId);
      return c.json(report);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  // List agents
  app.get("/v1/agents", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const { status, tenantId } = c.req.query();
    const list = runtime.list({ status: status as any, tenantId });
    return c.json({ count: list.length, agents: list });
  });

  // Agent detail
  app.get("/v1/agents/:id", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const agent = runtime.get(c.req.param("id"));
    if (!agent) return c.json({ error: "not found" }, 404);

    return c.json({
      id:          agent.def.id,
      name:        agent.def.name,
      description: agent.def.description,
      version:     agent.def.version,
      scope:       agent.def.scope,
      tenantId:    agent.def.tenantId,
      status:      agent.status,
      schedule:    agent.def.schedule,
      events:      agent.def.events,
      runCount:    agent.runCount,
      errorCount:  agent.errorCount,
      lastRun:     agent.lastRun,
    });
  });

  // Start agent
  app.post("/v1/agents/:id/start", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    try {
      runtime.start(c.req.param("id"));
      return c.json({ ok: true, status: "running" });
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  // Stop agent
  app.post("/v1/agents/:id/stop", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    runtime.stop(c.req.param("id"));
    return c.json({ ok: true, status: "stopped" });
  });

  // Stats
  app.get("/v1/agents/stats", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);
    return c.json(runtime.stats());
  });
}
