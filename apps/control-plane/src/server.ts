/**
 * Sovereignly Control Plane Server
 * Business Source License 1.1 — MetaCognixion
 *
 * The Global Control Plane manages the entire Sovereignly network.
 * It does NOT execute tenant workloads.
 *
 * Responsibilities:
 *   - Cluster discovery and node health monitoring
 *   - Policy distribution
 *   - Global ledger anchoring
 *   - Request routing
 *   - Metrics aggregation
 *   - Compliance coordination
 *
 * This is a standalone server, separate from the cluster nodes.
 * Cluster nodes send heartbeats to this server.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { mkdir } from "node:fs/promises";

import { ControlPlaneNodeRegistry } from "./node-registry.ts";
import { ClusterManager }           from "./cluster-manager.ts";
import { PolicyAuthority }           from "./policy-authority.ts";
import { RoutingEngine }             from "./routing-engine.ts";
import { MetricsAggregator }         from "./metrics-aggregator.ts";
import { createControlPlaneRoutes }  from "./routes.ts";

// ── Config ──

const PORT        = parseInt(process.env.PORT         ?? "9090");
const HOST        = process.env.HOST                   ?? "0.0.0.0";
const DATA_DIR    = process.env.DATA_DIR               ?? "./data/control-plane";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

console.log(`

       SOVEREIGNLY CONTROL PLANE v4.0

  Port:   ${PORT}
  Data:   ${DATA_DIR}
  Admin:  ${ADMIN_TOKEN ? "configured" : "WARNING: no ADMIN_TOKEN set"}
`);

await mkdir(DATA_DIR, { recursive: true });

// ── Initialize components ──

const nodeRegistry     = new ControlPlaneNodeRegistry(DATA_DIR);
const clusterManager   = new ClusterManager(nodeRegistry);
const policyAuthority  = new PolicyAuthority();
const routingEngine    = new RoutingEngine(nodeRegistry, clusterManager, policyAuthority);
const metricsAggregator = new MetricsAggregator(nodeRegistry, clusterManager);

// ── Create Hono app ──

const app = new Hono();

app.use("*", cors({ origin: "*" }));

// Mount control plane routes
const controlRoutes = createControlPlaneRoutes(
  nodeRegistry, clusterManager, policyAuthority,
  routingEngine, metricsAggregator,
  { adminToken: ADMIN_TOKEN },
);
app.route("/", controlRoutes);

// Root info
app.get("/", (c) => c.json({
  name: "Sovereignly Control Plane",
  version: "4.0.0",
  role: "control-plane",
  endpoints: {
    heartbeat:  "POST /_sovereign/control/heartbeat",
    nodes:      "GET /control/nodes",
    clusters:   "GET /control/clusters",
    policies:   "GET /control/policies",
    route:      "GET /control/route",
    metrics:    "GET /control/metrics",
    stats:      "GET /control/stats",
    health:     "GET /health",
  },
}));

// ── Start ──

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  fetch: app.fetch,
});

console.log(`[Control Plane] Ready on http://${HOST}:${PORT}
  Nodes:     http://${HOST}:${PORT}/control/nodes
  Clusters:  http://${HOST}:${PORT}/control/clusters
  Policies:  http://${HOST}:${PORT}/control/policies
  Health:    http://${HOST}:${PORT}/health
`);

// ── Shutdown ──

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\n[Control Plane] Shutting down...");
  metricsAggregator.close();
  clusterManager.close();
  nodeRegistry.close();
  server.stop(true);
  process.exit(0);
}

export { app, nodeRegistry, clusterManager, policyAuthority, routingEngine, metricsAggregator };
