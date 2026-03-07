// Sovereignly Cluster Routes -- BSL License
//
// POST /_sovereign/control/heartbeat     Node heartbeat (public for cluster nodes)
// GET  /v1/cluster/nodes                 List all nodes
// GET  /v1/cluster/nodes/:id             Node detail
// DELETE /v1/cluster/nodes/:id           Deregister node
// GET  /v1/cluster/topology              Cluster network graph
// GET  /v1/cluster/topology/region/:r    Nodes in region
// GET  /v1/cluster/best-node             Best node for placement
// GET  /v1/cluster/stats                 Cluster stats

import type { Hono } from "hono";
import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
import type { NodeRegistry } from "./node-registry.ts";
import type { ClusterTopology } from "./cluster-topology.ts";

export function registerClusterRoutes(
  app: Hono,
  nodeRegistry: NodeRegistry,
  clusterTopology: ClusterTopology,
  opts: { adminToken?: string }
) {
  function requireAdmin(c: any): boolean {
    const token = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    return !!opts.adminToken && timingSafeEqual(token ?? "", opts.adminToken);
  }

  // -- Heartbeat endpoint (accepts heartbeats from any cluster node) --

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
        registeredNodes: nodeRegistry.stats().totalNodes,
      });
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  // -- Node listing (admin only) --

  app.get("/v1/cluster/nodes", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { role, region, status } = c.req.query();
    const nodes = nodeRegistry.list({
      role: role as any,
      region: region || undefined,
      status: status as any,
    });
    return c.json({ count: nodes.length, nodes, stats: nodeRegistry.stats() });
  });

  app.get("/v1/cluster/nodes/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const node = nodeRegistry.get(c.req.param("id"));
    if (!node) return c.json({ error: "node not found" }, 404);
    return c.json(node);
  });

  app.delete("/v1/cluster/nodes/:id", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const removed = nodeRegistry.deregister(c.req.param("id"), "admin_removal");
    if (!removed) return c.json({ error: "node not found" }, 404);
    return c.json({ ok: true });
  });

  // -- Cluster topology --

  app.get("/v1/cluster/topology", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(clusterTopology.build());
  });

  app.get("/v1/cluster/topology/region/:region", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const nodes = clusterTopology.region(c.req.param("region"));
    return c.json({ region: c.req.param("region"), count: nodes.length, nodes });
  });

  app.get("/v1/cluster/best-node", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { region } = c.req.query();
    const best = clusterTopology.bestNode(region || undefined);
    if (!best) return c.json({ error: "no healthy cluster nodes available" }, 404);
    return c.json(best);
  });

  // -- Cluster stats --

  app.get("/v1/cluster/stats", (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json({
      nodes:    nodeRegistry.stats(),
      topology: clusterTopology.stats(),
    });
  });
}
