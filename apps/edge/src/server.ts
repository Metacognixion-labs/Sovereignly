/**
 * Sovereignly Edge Node Server
 * Business Source License 1.1 — MetaCognixion
 *
 * Lightweight edge execution node. Runs close to users for low-latency compute.
 *
 * Edge nodes:
 *   - Execute edge functions (stateless, short-lived)
 *   - Cache responses from upstream clusters
 *   - Forward events to regional cluster gateways
 *   - Send heartbeats to the control plane
 *
 * Edge nodes do NOT:
 *   - Store tenant chains
 *   - Run workflows or agents
 *   - Manage tenants
 */

import { Hono } from "hono";
import { cors } from "hono/cors";

import { EdgeRuntime }     from "./edge-runtime.ts";
import { EdgeCache }       from "./edge-cache.ts";
import { EventForwarder }  from "./event-forwarder.ts";
import { EdgeGateway }     from "./edge-gateway.ts";

// ── Config ──

const PORT              = parseInt(process.env.PORT ?? "8788");
const HOST              = process.env.HOST ?? "0.0.0.0";
const EDGE_NODE_ID      = process.env.EDGE_NODE_ID ?? `edge-${crypto.randomUUID().slice(0, 6)}`;
const EDGE_REGION       = process.env.EDGE_REGION ?? "us-east";
const CLUSTER_URL       = process.env.CLUSTER_URL ?? "http://localhost:8787";
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://localhost:9090";
const CACHE_TTL         = parseInt(process.env.EDGE_CACHE_TTL ?? "60000");
const CACHE_MAX         = parseInt(process.env.EDGE_CACHE_MAX ?? "10000");

console.log(`

       SOVEREIGNLY EDGE NODE v4.0

  Node:     ${EDGE_NODE_ID}
  Region:   ${EDGE_REGION}
  Port:     ${PORT}
  Cluster:  ${CLUSTER_URL}
  Control:  ${CONTROL_PLANE_URL}
`);

// ── Initialize components ──

const edgeRuntime = new EdgeRuntime();
const edgeCache   = new EdgeCache({ maxEntries: CACHE_MAX, defaultTTLMs: CACHE_TTL });
const forwarder   = new EventForwarder({
  clusterUrl: CLUSTER_URL,
  edgeNodeId: EDGE_NODE_ID,
  batchSize:  50,
  flushIntervalMs: 5000,
});
const gateway = new EdgeGateway(edgeRuntime, edgeCache, forwarder, {
  edgeNodeId: EDGE_NODE_ID,
  clusterUrl: CLUSTER_URL,
  cacheTTLMs: CACHE_TTL,
});

// ── Heartbeat to control plane ──

let heartbeatInterval: ReturnType<typeof setInterval>;
const startTime = Date.now();

async function sendHeartbeat() {
  try {
    const mem = process.memoryUsage();
    await fetch(`${CONTROL_PLANE_URL}/_sovereign/control/heartbeat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nodeId:       EDGE_NODE_ID,
        region:       EDGE_REGION,
        role:         "edge",
        load:         Number((mem.heapUsed / mem.heapTotal).toFixed(3)),
        uptime:       Math.round((Date.now() - startTime) / 1000),
        version:      "4.0.0",
        capabilities: ["cache", "functions", "forwarding"],
      }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err: any) {
    console.warn(`[Edge] Heartbeat failed: ${err.message}`);
  }
}

sendHeartbeat();
heartbeatInterval = setInterval(sendHeartbeat, 30_000);

// ── Hono app ──

const app = new Hono();
app.use("*", cors({ origin: "*" }));

// Health check
app.get("/health", (c) => c.json({
  status: "ok",
  role:   "edge",
  nodeId: EDGE_NODE_ID,
  region: EDGE_REGION,
  uptime: Math.round((Date.now() - startTime) / 1000),
}));

// Edge stats
app.get("/_sovereign/edge/stats", (c) => c.json({
  node:      { id: EDGE_NODE_ID, region: EDGE_REGION, uptime: Math.round((Date.now() - startTime) / 1000) },
  gateway:   gateway.stats(),
  runtime:   edgeRuntime.stats(),
  cache:     edgeCache.stats(),
  forwarder: forwarder.stats(),
}));

// Edge function management
app.get("/_sovereign/edge/functions", (c) => {
  return c.json({ functions: edgeRuntime.listFunctions() });
});

app.post("/_sovereign/edge/functions", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body?.name || !body?.code || !body?.routes) {
    return c.json({ error: "name, code, and routes required" }, 400);
  }
  const fn = edgeRuntime.register({
    name:    body.name,
    code:    body.code,
    routes:  body.routes,
    timeout: body.timeout ?? 5000,
    enabled: body.enabled ?? true,
  });
  return c.json(fn, 201);
});

app.delete("/_sovereign/edge/functions/:id", (c) => {
  const ok = edgeRuntime.deregister(c.req.param("id"));
  if (!ok) return c.json({ error: "not found" }, 404);
  return c.json({ ok: true });
});

// Cache management
app.delete("/_sovereign/edge/cache", (c) => {
  edgeCache.clear();
  return c.json({ ok: true, message: "Cache cleared" });
});

app.delete("/_sovereign/edge/cache/:prefix", (c) => {
  const count = edgeCache.invalidatePrefix(c.req.param("prefix"));
  return c.json({ ok: true, invalidated: count });
});

// Recent invocations
app.get("/_sovereign/edge/invocations", (c) => {
  const { limit } = c.req.query();
  return c.json({ invocations: edgeRuntime.recent(limit ? parseInt(limit) : 50) });
});

// ── Catch-all: edge gateway handles everything else ──

app.all("*", async (c) => {
  const headers: Record<string, string> = {};
  c.req.raw.headers.forEach((v, k) => { headers[k] = v; });
  headers["x-edge-region"] = EDGE_REGION;

  let body: unknown;
  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    body = await c.req.json().catch(() => undefined);
  }

  const result = await gateway.handle({
    path:    c.req.path,
    method:  c.req.method,
    headers,
    body,
  });

  // Set response headers
  for (const [k, v] of Object.entries(result.headers)) {
    c.header(k, v);
  }
  c.header("x-edge-source", result.source);
  c.header("x-edge-node", EDGE_NODE_ID);

  return c.json(result.body, result.status as any);
});

// ── Start ──

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  fetch: app.fetch,
});

console.log(`[Edge Node] Ready on http://${HOST}:${PORT}
  Health:    http://${HOST}:${PORT}/health
  Stats:     http://${HOST}:${PORT}/_sovereign/edge/stats
  Functions: http://${HOST}:${PORT}/_sovereign/edge/functions
`);

// ── Shutdown ──

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\n[Edge Node] Shutting down...");
  clearInterval(heartbeatInterval);
  await forwarder.drain();
  forwarder.close();
  edgeCache.close();
  server.stop(true);
  process.exit(0);
}

export { app, edgeRuntime, edgeCache, forwarder, gateway };
