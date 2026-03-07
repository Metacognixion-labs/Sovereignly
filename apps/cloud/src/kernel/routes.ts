import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
// Sovereignly Kernel Routes -- BSL License
//
// GET  /v1/kernel/state              State registry overview
// GET  /v1/kernel/state/:id          Entity detail
// GET  /v1/kernel/health             Health analyzer signals + score
// GET  /v1/kernel/decisions          Recent decisions
// POST /v1/kernel/decisions/evaluate Force evaluation cycle
// GET  /v1/kernel/placement          Placement suggestion
// POST /v1/kernel/migrate            Trigger tenant migration
// GET  /v1/kernel/migrations         Migration history
// GET  /v1/kernel/topology           Infrastructure graph
// GET  /v1/kernel/topology/:id       Node neighbors
// GET  /v1/kernel/stats              All kernel stats

import type { Hono } from "hono";
import type { StateRegistry } from "./state-registry.ts";
import type { HealthAnalyzer } from "./health-analyzer.ts";
import type { DecisionEngine } from "./decision-engine.ts";
import type { PlacementEngine } from "./placement-engine.ts";
import type { MigrationEngine } from "./migration-engine.ts";
import type { TopologyEngine } from "./topology-engine.ts";

export function registerKernelRoutes(
  app: Hono,
  kernel: {
    state:     StateRegistry;
    health:    HealthAnalyzer;
    decisions: DecisionEngine;
    placement: PlacementEngine;
    migration: MigrationEngine;
    topology:  TopologyEngine;
  },
  opts: { adminToken?: string }
) {

  function requireAdmin(c: any): boolean {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    return !!opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken);
  }

  // -- State Registry --

  app.get("/v1/kernel/state", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { type, status } = c.req.query();
    const entities = kernel.state.list({ type: type as any, status: status as any });
    return c.json({ count: entities.length, entities: entities.slice(0, 100), stats: kernel.state.stats() });
  });

  app.get("/v1/kernel/state/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const entity = kernel.state.get(c.req.param("id"));
    if (!entity) return c.json({ error: "not found" }, 404);
    const neighbors = kernel.topology.neighbors(entity.id);
    return c.json({ entity, neighbors });
  });

  // -- Health Analyzer --

  app.get("/v1/kernel/health", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({
      ...kernel.health.score(),
      signals: kernel.health.getSignals(),
      ...kernel.health.stats(),
    });
  });

  // -- Decision Engine --

  app.get("/v1/kernel/decisions", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { limit } = c.req.query();
    const recent = kernel.decisions.recent(limit ? parseInt(limit) : 20);
    return c.json({ count: recent.length, decisions: recent, stats: kernel.decisions.stats() });
  });

  app.post("/v1/kernel/decisions/evaluate", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const newDecisions = kernel.decisions.evaluate();
    return c.json({ evaluated: newDecisions.length, decisions: newDecisions });
  });

  // -- Placement Engine --

  app.get("/v1/kernel/placement", async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { tenantId, workloadType, region, residency } = c.req.query();
    const result = kernel.placement.place({
      tenantId,
      workloadType: (workloadType ?? "tenant") as any,
      requirements: {
        regions: region ? [region] : undefined,
        dataResidency: residency,
      },
    });
    return c.json(result);
  });

  app.get("/v1/kernel/regions", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({ regions: kernel.placement.regions(), stats: kernel.placement.stats() });
  });

  // -- Migration Engine --

  app.post("/v1/kernel/migrate", async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.tenantId || !body.toRegion) return c.json({ error: "tenantId and toRegion required" }, 400);
    try {
      const migration = await kernel.migration.migrate(body.tenantId, body.toRegion, body.reason ?? "api");
      return c.json(migration, 202);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  app.get("/v1/kernel/migrations", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({ migrations: kernel.migration.list(), stats: kernel.migration.stats() });
  });

  app.get("/v1/kernel/migrations/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const m = kernel.migration.get(c.req.param("id"));
    if (!m) return c.json({ error: "not found" }, 404);
    return c.json(m);
  });

  // -- Topology Engine --

  app.get("/v1/kernel/topology", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(kernel.topology.build());
  });

  app.get("/v1/kernel/topology/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(kernel.topology.neighbors(c.req.param("id")));
  });

  // -- Combined kernel stats --

  app.get("/v1/kernel/stats", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({
      state:     kernel.state.stats(),
      health:    kernel.health.stats(),
      decisions: kernel.decisions.stats(),
      placement: kernel.placement.stats(),
      migration: kernel.migration.stats(),
      topology:  kernel.topology.stats(),
    });
  });
}
