/**
 * Sovereignly Cloud  Multi-Tenant SaaS Server
 * Business Source License 1.1  MetaCognixion
 *
 * Everything in the OSS edition, plus:
 *   Multi-tenancy     Per-tenant isolated chains + encryption
 *   ComplianceEngine  SOC2, ISO27001, HIPAA, GDPR, NIST reports
 *   Stripe Billing    Checkout, portal, webhooks, plan sync
 *   Self-Service      Public signup, upgrade, pricing API
 *   Webhooks          HMAC-signed delivery with retry
 *   Zero-Trust        Anomaly detection, secret scanning, RBAC
 *   Per-tenant rates  Plan-based event/API rate limiting
 *   Admin dashboard   Full ops visibility
 *
 * This file is the production entry point for sovereignly.io.
 * It imports core components from @sovereignly/oss and adds premium layers.
 *
 * License: Business Source License 1.1
 *    You may view, fork, and modify this code.
 *    You may NOT offer it as a hosted service to third parties.
 *    After 4 years from publication, converts to MIT.
 *    For commercial hosting rights: jp@metacognixion.com
 */

import { SovereignKV }        from "@sovereignly/oss/kv";
import { SovereignStorage }   from "@sovereignly/oss/storage";
import { SovereignRuntime }   from "@sovereignly/oss/runtime";
import { SovereignScheduler } from "@sovereignly/oss/scheduler";
import { startServer }        from "@sovereignly/oss/gateway";
import { mkdir }               from "node:fs/promises";

// Bootstrap modules
import { config }              from "./bootstrap/config.ts";
import { createOmniAnchor, createChain } from "./bootstrap/chain.ts";
import { createAuth }          from "./bootstrap/auth.ts";
import { createTenantLayer, wireChainHooks } from "./bootstrap/tenants.ts";
import { createKernel }        from "./bootstrap/kernel.ts";
import { createEcosystem }     from "./bootstrap/ecosystem.ts";
import { createCluster }       from "./bootstrap/cluster.ts";
import { createPlatformGateway } from "./bootstrap/gateway.ts";

//  Banner

console.log(`

       SOVEREIGNLY CLOUD v4.0  Global Sovereign Network

  Node: ${config.nodeId} | Port: ${config.port} | Workers: ${config.poolSize}
  Role:     ${config.nodeRole} | Cluster: ${config.clusterId} | Region: ${config.nodeRegion}
  Auth:     Passkeys + OAuth + SIWE + Solana
  Chain:    SovereignChain PoA (per-tenant isolated)
  Anchor:   ${process.env.EAS_BASE_RPC ? "EAS/Base " : "config EAS_BASE_RPC"}
  Billing:  ${config.stripeKey ? "Stripe " : "disabled"}
  Cluster:  ${config.controlPlaneUrl ? `-> ${config.controlPlaneUrl}` : "self (control plane)"}
  License:  Business Source License 1.1
`);

//  Bootstrap

await mkdir(config.dataDir, { recursive: true });
await mkdir(`${config.dataDir}/global`, { recursive: true });
await mkdir(`${config.dataDir}/platform`, { recursive: true });

// 1. Chain + anchor
const omniAnchor = createOmniAnchor(config);
const chain      = await createChain(config, omniAnchor);

// 2. Auth
const { oauthBroker, passkeys } = createAuth(config);

// 3. Tenants + billing + webhooks
const { tenantManager, billing, tenantLimiter, webhookManager } = createTenantLayer(config, chain, omniAnchor);
wireChainHooks(chain, tenantManager, webhookManager, config);

// 4. Platform services
const kv      = new SovereignKV({ dataDir: `${config.dataDir}/platform` });
await kv.init();
const storage = new SovereignStorage({ dataDir: `${config.dataDir}/platform` });
const runtime = new SovereignRuntime(kv, config.poolSize);
const scheduler = new SovereignScheduler(chain);

// 5. Kernel + workflows + agents + AI
const kernel = createKernel(config, chain);
kernel.sovereignKernel.services.register("tenantManager", tenantManager);

// 6. Ecosystem
const ecosystem = createEcosystem(kernel.eventBus, kernel.policyEngine);

// 7. Cluster + global anchoring + AI orchestration
const cluster = createCluster(
  config, kernel.eventBus, chain, tenantManager,
  kernel.sovereignKernel, kernel.placementEngine, kernel.stateRegistry,
);

// 8. Gateway + all routes
const { app, metrics } = createPlatformGateway(config, {
  chain, runtime, kv, storage,
  passkeys, oauthBroker,
  tenantManager, billing, tenantLimiter, webhookManager,
  ...kernel,
  ...ecosystem,
  ...cluster,
});

//  Start

const server = startServer(app, { port: config.port, host: config.host });

await chain.emit("NODE_JOIN", {
  nodeId: config.nodeId, version: "4.0.0", edition: "cloud",
  role: config.nodeRole, region: config.nodeRegion, cluster: config.clusterId,
  port: config.port, peers: config.clusterPeers.length,
  features: {
    passkeys: true, oauth: oauthBroker.getSupportedProviders(), omnichain: true,
    billing: !!billing, tenants: true, webhooks: true,
    cluster: true, globalAnchor: true, aiOrchestration: true,
  },
}, "LOW");

console.log(`[Sovereignly Cloud]  Ready  ${config.appUrl}
  Dashboard:  ${config.appUrl}/_sovereign/dashboard
  Signup:     ${config.appUrl}/_sovereign/signup
  Ops:        ${config.appUrl}/_sovereign/ops
  Cluster:    ${config.appUrl}/v1/cluster/stats
  Kernel:     ${config.appUrl}/v1/kernel/stats
`);

//  Shutdown

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\n[Sovereignly Cloud] Shutting down...");
  await chain.emit("NODE_LEAVE", { nodeId: config.nodeId, reason: "graceful" }, "LOW");
  await chain.flush();
  // Cluster components
  cluster.nodeHeartbeat.stop(); cluster.nodeRegistry.close();
  cluster.clusterBalancer.close(); cluster.networkAnomalyDetector.close(); cluster.costOptimizer.close();
  // Core components
  server.stop(true); scheduler.stop(); runtime.shutdown();
  webhookManager.close(); kernel.workflowEngine.close(); kernel.agentRuntime.close();
  kernel.healthAnalyzer.close(); kernel.decisionEngine.close(); kernel.stateRegistry.close();
  kernel.cognitiveModel.close(); ecosystem.gamification.close();
  await tenantManager.closeAll();
  kv.close(); storage.close(); chain.close();
  process.exit(0);
}

export {
  app, chain, kv, storage, runtime, scheduler, metrics,
  tenantManager, billing,
};
export const sovereignKernel = kernel.sovereignKernel;
export const nodeRegistry = cluster.nodeRegistry;
export const clusterTopology = cluster.clusterTopology;
export const globalAnchor = cluster.globalAnchor;
export const clusterBalancer = cluster.clusterBalancer;
export const workloadPlanner = cluster.workloadPlanner;
export const networkAnomalyDetector = cluster.networkAnomalyDetector;
export const costOptimizer = cluster.costOptimizer;
