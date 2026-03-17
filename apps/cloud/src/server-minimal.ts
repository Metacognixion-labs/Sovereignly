// Bisect test — Layer 3a: L2 + cluster CORE only (NodeRegistry + Heartbeat + Topology + GlobalAnchor)
// NO AI components (ClusterBalancer, NetworkAnomalyDetector, CostOptimizer, WorkloadPlanner)
import { SovereignKV }        from "@sovereignly/oss/kv";
import { SovereignStorage }   from "@sovereignly/oss/storage";
import { startServer }        from "@sovereignly/oss/gateway";
import { SovereignRuntime }   from "@sovereignly/oss/runtime";
import { SovereignScheduler } from "@sovereignly/oss/scheduler";
import { mkdir }               from "node:fs/promises";
import { config }              from "./bootstrap/config.ts";
import { createOmniAnchor, createChain } from "./bootstrap/chain.ts";
import { createAuth }          from "./bootstrap/auth.ts";
import { createTenantLayer, wireChainHooks } from "./bootstrap/tenants.ts";
import { createKernel }        from "./bootstrap/kernel.ts";
import { createEcosystem }     from "./bootstrap/ecosystem.ts";
import { createPlatformGateway } from "./bootstrap/gateway.ts";

// Cluster core imports (no AI)
import { NodeRegistry }       from "./cluster/node-registry.ts";
import { NodeHeartbeat }      from "./cluster/node-heartbeat.ts";
import { ClusterTopology }    from "./cluster/cluster-topology.ts";
import { GlobalAnchor }       from "./global/global-anchor.ts";
import { ClusterRootComputer } from "./global/cluster-root.ts";

process.on("uncaughtException", (err) => {
  console.error("[FATAL] Uncaught exception:", err);
});
process.on("unhandledRejection", (reason) => {
  console.error("[FATAL] Unhandled rejection:", reason);
});
process.on("exit", (code) => {
  console.error(`[EXIT] Process exiting with code ${code}`);
});

console.log(`[Bisect-L3a] L2 + cluster core (NO AI components)`);
console.log(`  Node: ${config.nodeId} | Port: ${config.port} | Workers: ${config.poolSize}`);

await mkdir(config.dataDir, { recursive: true });
await mkdir(`${config.dataDir}/global`, { recursive: true });
await mkdir(`${config.dataDir}/platform`, { recursive: true });

const omniAnchor = createOmniAnchor(config);
const chain      = await createChain(config, omniAnchor);

const { oauthBroker, passkeys } = createAuth(config);

const { tenantManager, billing, tenantLimiter, webhookManager } = createTenantLayer(config, chain, omniAnchor);
wireChainHooks(chain, tenantManager, webhookManager, config);

const kv      = new SovereignKV({ dataDir: `${config.dataDir}/platform` });
await kv.init();
const storage = new SovereignStorage({ dataDir: `${config.dataDir}/platform` });
const runtime = new SovereignRuntime(kv, { poolSize: config.poolSize });
const scheduler = new SovereignScheduler(runtime);

const kernel = createKernel(config, chain);
kernel.sovereignKernel.services.register("tenantManager", tenantManager);

const ecosystem = createEcosystem(kernel.eventBus, kernel.policyEngine);

// Cluster CORE only (no AI)
const nodeRegistry    = new NodeRegistry(kernel.eventBus);
const clusterTopology = new ClusterTopology(nodeRegistry);
const nodeHeartbeat   = new NodeHeartbeat({
  nodeId: config.nodeId, region: config.nodeRegion, role: config.nodeRole,
  version: "4.0.0", capabilities: ["chain", "tenants", "workflows", "agents", "ai-kernel"],
  controlPlaneUrl: config.controlPlaneUrl,
}, nodeRegistry);
nodeHeartbeat.start();

const globalAnchor        = new GlobalAnchor(kernel.eventBus);
const clusterRootComputer = new ClusterRootComputer(config.clusterId, kernel.eventBus, tenantManager);

chain.onBlock(async (block) => {
  if (block.index > 0 && block.index % config.globalAnchorInterval === 0) {
    try {
      await clusterRootComputer.compute();
      if (!config.controlPlaneUrl) await globalAnchor.computeGlobalRoot();
    } catch (e: any) { console.warn("[GlobalAnchor] Root computation failed:", e.message); }
  }
});

kernel.sovereignKernel.services.register("nodeRegistry", nodeRegistry);
kernel.sovereignKernel.services.register("clusterTopology", clusterTopology);

const { app, metrics } = createPlatformGateway(config, {
  chain, runtime, kv, storage,
  passkeys, oauthBroker,
  tenantManager, billing, tenantLimiter, webhookManager,
  ...kernel,
  ...ecosystem,
  nodeRegistry, clusterTopology, nodeHeartbeat,
  globalAnchor,
  // Stub AI components
  clusterBalancer: { stats: () => ({}), close: () => {}, recent: () => [], evaluate: () => [] } as any,
  networkAnomalyDetector: { stats: () => ({}), close: () => {}, recent: () => [] } as any,
  costOptimizer: { stats: () => ({}), close: () => {}, recent: () => [] } as any,
});

const server = startServer(app, { port: config.port, host: config.host });

// Memory + lag tracking
let lastTick = Date.now();
setInterval(() => {
  const now = Date.now();
  const mem = process.memoryUsage();
  const lag = now - lastTick - 30000;
  console.log(`[Bisect-L3a] rss=${Math.round(mem.rss / 1024 / 1024)}MB heap=${Math.round(mem.heapUsed / 1024 / 1024)}/${Math.round(mem.heapTotal / 1024 / 1024)}MB lag=${lag}ms`);
  lastTick = now;
}, 30000);

let fastLast = Date.now();
setInterval(() => {
  const now = Date.now();
  const delay = now - fastLast - 1000;
  if (delay > 5000) console.error(`[BLOCK] Event loop blocked for ${delay}ms!`);
  fastLast = now;
}, 1000);

let _wdFails = 0;
setInterval(async () => {
  try {
    const res = await fetch(`http://localhost:${config.port}/_sovereign/health`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) { _wdFails = 0; return; }
  } catch {}
  _wdFails++;
  console.error(`[WATCHDOG] Self-health check failed (${_wdFails}/3)`);
  if (_wdFails >= 3) {
    console.error("[WATCHDOG] HTTP server unresponsive — exiting for restart");
    process.exit(1);
  }
}, 15000);

await chain.emit("NODE_JOIN", {
  nodeId: config.nodeId, version: "4.0.0", edition: "cloud",
}, "LOW");

console.log(`[Bisect-L3a] Ready on port ${config.port}`);

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\n[Bisect-L3a] Shutting down...");
  await chain.flush();
  nodeHeartbeat.stop(); nodeRegistry.close();
  server.stop(true); scheduler.stop(); runtime.shutdown();
  webhookManager.close(); kernel.workflowEngine.close(); kernel.agentRuntime.close();
  kernel.healthAnalyzer.close(); kernel.decisionEngine.close(); kernel.stateRegistry.close();
  kernel.cognitiveModel.close(); ecosystem.gamification.close();
  await tenantManager.closeAll();
  kv.close(); storage.close(); chain.close();
  process.exit(0);
}
