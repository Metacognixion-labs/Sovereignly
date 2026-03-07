// Sovereignly Control Plane — Routes
// BSL License — MetaCognixion
//
// API surface for the control plane:
//   POST /_sovereign/control/heartbeat         Node heartbeat
//   GET  /control/nodes                        List nodes
//   GET  /control/nodes/:id                    Node detail
//   DELETE /control/nodes/:id                  Deregister node
//   GET  /control/clusters                     List clusters
//   GET  /control/clusters/:id                 Cluster detail
//   GET  /control/policies                     List policies
//   POST /control/policies                     Create policy
//   PUT  /control/policies/:id                 Update policy
//   DELETE /control/policies/:id               Delete policy
//   GET  /control/route                        Route a request
//   GET  /control/metrics                      Global metrics
//   GET  /control/metrics/history              Metrics history
//   GET  /control/stats                        Combined stats

import { Hono } from "hono";
import type { ControlPlaneNodeRegistry } from "./node-registry.ts";
import type { ClusterManager } from "./cluster-manager.ts";
import type { PolicyAuthority } from "./policy-authority.ts";
import type { RoutingEngine } from "./routing-engine.ts";
import type { MetricsAggregator } from "./metrics-aggregator.ts";

export function createControlPlaneRoutes(
  nodeRegistry:     ControlPlaneNodeRegistry,
  clusterManager:   ClusterManager,
  policyAuthority:  PolicyAuthority,
  routingEngine:    RoutingEngine,
  metricsAggregator: MetricsAggregator,
  opts: { adminToken?: string },
): Hono {
  const app = new Hono();

  function requireAdmin(c: any): boolean {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    if (!opts.adminToken || !token) return false;
    // Constant-time comparison
    if (token.length !== opts.adminToken.length) return false;
    let mismatch = 0;
    for (let i = 0; i < token.length; i++) {
      mismatch |= token.charCodeAt(i) ^ opts.adminToken.charCodeAt(i);
    }
    return mismatch === 0;
  }

  // ── Heartbeat (public for cluster nodes) ──

  app.post("/_sovereign/control/heartbeat", async (c) => {
    try {
      const payload = await c.req.json();
      if (!payload.nodeId || !payload.region) {
        return c.json({ error: "nodeId and region required" }, 400);
      }
      const node = nodeRegistry.heartbeat(payload);
      return c.json({
        ok: true,
        nodeId: node.nodeId,
        status: node.status,
        totalNodes: nodeRegistry.stats().totalNodes,
        policies: policyAuthority.forCluster(node.clusterId).length,
      });
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  // ── Nodes ──

  app.get("/control/nodes", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { role, region, status, clusterId } = c.req.query();
    const nodes = nodeRegistry.list({
      role: role as any, region: region || undefined,
      status: status as any, clusterId: clusterId || undefined,
    });
    return c.json({ count: nodes.length, nodes });
  });

  app.get("/control/nodes/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const node = nodeRegistry.get(c.req.param("id"));
    if (!node) return c.json({ error: "not found" }, 404);
    return c.json(node);
  });

  app.delete("/control/nodes/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const ok = nodeRegistry.deregister(c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    return c.json({ ok: true });
  });

  // ── Clusters ──

  app.get("/control/clusters", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const clusters = clusterManager.list();
    return c.json({ count: clusters.length, clusters, stats: clusterManager.stats() });
  });

  app.get("/control/clusters/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const cluster = clusterManager.get(c.req.param("id"));
    if (!cluster) return c.json({ error: "not found" }, 404);
    const nodes = nodeRegistry.list({ clusterId: c.req.param("id") });
    return c.json({ cluster, nodes });
  });

  app.get("/control/clusters/region/:region", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const best = clusterManager.bestInRegion(c.req.param("region"));
    if (!best) return c.json({ error: "no clusters in region" }, 404);
    return c.json(best);
  });

  // ── Policies ──

  app.get("/control/policies", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { scope } = c.req.query();
    const policies = policyAuthority.list({ scope: scope as any });
    return c.json({ count: policies.length, policies, stats: policyAuthority.stats() });
  });

  app.post("/control/policies", async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const body = await c.req.json().catch(() => null);
    if (!body?.name || !body?.rules) return c.json({ error: "name and rules required" }, 400);
    const policy = policyAuthority.create({
      name:     body.name,
      scope:    body.scope ?? "global",
      target:   body.target ?? "*",
      rules:    body.rules,
      priority: body.priority ?? 50,
      enabled:  body.enabled ?? true,
    });
    return c.json(policy, 201);
  });

  app.put("/control/policies/:id", async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const body = await c.req.json().catch(() => ({}));
    const updated = policyAuthority.update(c.req.param("id"), body);
    if (!updated) return c.json({ error: "not found" }, 404);
    return c.json(updated);
  });

  app.delete("/control/policies/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const ok = policyAuthority.delete(c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    return c.json({ ok: true });
  });

  // ── Routing ──

  app.get("/control/route", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { tenantId, sourceRegion, residency, workloadType } = c.req.query();
    const result = routingEngine.route({
      tenantId: tenantId || undefined,
      sourceRegion: sourceRegion || undefined,
      residency: residency || undefined,
      workloadType: workloadType || undefined,
    });
    return c.json(result);
  });

  // ── Metrics ──

  app.get("/control/metrics", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(metricsAggregator.latest());
  });

  app.get("/control/metrics/history", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { limit } = c.req.query();
    return c.json(metricsAggregator.getHistory(limit ? parseInt(limit) : 60));
  });

  // ── Combined stats ──

  app.get("/control/stats", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({
      nodes:    nodeRegistry.stats(),
      clusters: clusterManager.stats(),
      policies: policyAuthority.stats(),
      routing:  routingEngine.stats(),
      metrics:  metricsAggregator.stats(),
    });
  });

  // ── Health check (public) ──

  app.get("/health", (c) => {
    const stats = nodeRegistry.stats();
    return c.json({
      status: "ok",
      role:   "control-plane",
      nodes:  stats.totalNodes,
      healthy: stats.byStatus?.healthy ?? 0,
    });
  });

  return app;
}
