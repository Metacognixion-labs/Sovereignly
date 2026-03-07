import { timingSafeEqual } from "../security/crypto.ts";
// Sovereignly Platform Protocol v1 -- MIT License
// Standard REST API surface per PLATFORM_PROTOCOL.md
//
// Primitives: TENANT, MACHINE, WORKFLOW, AGENT, EVENT, POLICY
// All operations require authentication and policy validation.

import type { Hono } from "hono";
import type { EventBus } from "../events/bus.ts";
import type { PolicyEngine } from "../policies/engine.ts";

export function registerProtocolRoutes(
  app:     Hono,
  bus:     EventBus,
  policy:  PolicyEngine,
  opts:    { adminToken?: string }
) {

  // -- Auth helper --
  function requireAuth(c: any): { ok: boolean; role: string } {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "")
               ?? c.req.header("authorization")?.slice(7);
    if (!token) return { ok: false, role: "" };
    if (opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken)) return { ok: true, role: "admin" };
    // TODO: JWT verification when integrated with full auth
    return { ok: false, role: "" };
  }

  // ======================================================================
  // EVENTS -- query the event bus
  // ======================================================================

  app.get("/v1/events", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const { type, tenantId, since, limit } = c.req.query();
    const events = bus.query({
      type,
      tenantId,
      since: since ? parseInt(since) : undefined,
      limit: limit ? Math.min(parseInt(limit), 500) : 100,
    });

    return c.json({ count: events.length, events });
  });

  app.get("/v1/events/stats", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);
    return c.json(bus.stats());
  });

  // ======================================================================
  // POLICIES -- manage declarative policies
  // ======================================================================

  app.get("/v1/policies", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const { scope } = c.req.query();
    const policies = policy.list(scope as any);
    return c.json({ count: policies.length, policies });
  });

  app.post("/v1/policies", async (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);
    if (auth.role !== "admin") return c.json({ error: "admin required" }, 403);

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.name || !body.scope || !body.rules) {
      return c.json({ error: "name, scope, and rules required" }, 400);
    }

    const result = policy.register({
      name:        body.name,
      description: body.description ?? "",
      scope:       body.scope,
      tenantId:    body.tenantId,
      rules:       body.rules,
      effect:      body.effect ?? "deny",
      priority:    body.priority ?? 500,
      active:      body.active ?? true,
    });

    return c.json({ policy: result }, 201);
  });

  app.get("/v1/policies/evaluate", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const { action, tenantId, source } = c.req.query();
    if (!action) return c.json({ error: "action query param required" }, 400);

    const result = policy.evaluate(action, { tenantId, source, role: auth.role });
    return c.json(result);
  });

  app.get("/v1/policies/stats", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);
    return c.json(policy.stats());
  });

  // ======================================================================
  // MACHINES -- register and manage compute nodes
  // ======================================================================

  // In-memory machine registry (Phase 4 moves to state-registry)
  const machines = new Map<string, {
    id: string; name: string; region: string; status: string;
    tenantId?: string; resources: Record<string, unknown>;
    registeredAt: number; lastHeartbeat: number;
  }>();

  app.post("/v1/machines", async (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const eval_ = policy.evaluate("machine.register", { role: auth.role });
    if (!eval_.allowed) return c.json({ error: eval_.reason }, 403);

    const body = await c.req.json().catch(() => ({})) as any;
    const id = `mach_${crypto.randomUUID().slice(0, 12)}`;
    const machine = {
      id,
      name:       body.name ?? id,
      region:     body.region ?? "iad",
      status:     "starting",
      tenantId:   body.tenantId,
      resources:  body.resources ?? {},
      registeredAt: Date.now(),
      lastHeartbeat: Date.now(),
    };
    machines.set(id, machine);

    await bus.emit("MACHINE_STARTED", { machineId: id, region: machine.region }, {
      source: "control-plane", tenantId: body.tenantId,
    });

    return c.json({ machine }, 201);
  });

  app.get("/v1/machines", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const list = Array.from(machines.values());
    return c.json({ count: list.length, machines: list });
  });

  app.get("/v1/machines/:id", (c) => {
    const auth = requireAuth(c);
    if (!auth.ok) return c.json({ error: "authentication required" }, 401);

    const machine = machines.get(c.req.param("id"));
    if (!machine) return c.json({ error: "not found" }, 404);
    return c.json(machine);
  });

  app.post("/v1/machines/:id/heartbeat", (c) => {
    const machine = machines.get(c.req.param("id"));
    if (!machine) return c.json({ error: "not found" }, 404);
    machine.lastHeartbeat = Date.now();
    machine.status = "running";
    return c.json({ ok: true });
  });

  // WORKFLOWS: handled by registerWorkflowRoutes (Phase 2)

  // AGENTS: handled by registerAgentRoutes (Phase 3)

  // ======================================================================
  // PLATFORM INFO
  // ======================================================================

  app.get("/v1/info", (c) => {
    return c.json({
      platform:  "Sovereignly",
      version:   "3.0.1",
      protocol:  "SPP/1.0",
      primitives: ["TENANT", "MACHINE", "WORKFLOW", "AGENT", "EVENT", "POLICY"],
      layers: [
        "Developer Ecosystem",
        "Platform Protocol",
        "Control Plane",
        "Agent Control Layer",
        "Autonomous Infrastructure Kernel",
        "Cognitive Infrastructure Model",
        "Global Edge Infrastructure",
      ],
      endpoints: {
        events:    "/v1/events",
        policies:  "/v1/policies",
        machines:  "/v1/machines",
        workflows: "/v1/workflows/trigger",
        agents:    "/v1/agents/execute",
      },
    });
  });
}
