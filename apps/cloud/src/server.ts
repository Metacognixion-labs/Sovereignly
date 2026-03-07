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

//  OSS core (MIT) 
// These are imported from the OSS app  same code, MIT licensed.
// The Cloud server instantiates them the same way, then adds premium layers.

import { SovereignKV }        from "@sovereignly/oss/kv";
import { SovereignStorage }   from "@sovereignly/oss/storage";
import { SovereignRuntime }   from "@sovereignly/oss/runtime";
import { SovereignScheduler } from "@sovereignly/oss/scheduler";
import { createGateway, startServer, registerFunctionDispatcher } from "@sovereignly/oss/gateway";
import { SovereignChain }     from "@sovereignly/oss/security/chain";
import { OmnichainAnchor }    from "@sovereignly/oss/security/omnichain-anchor";
import type { AnchorTier }     from "@sovereignly/oss/security/omnichain-anchor";
import { registerChainRoutes } from "@sovereignly/oss/gateway/chain-routes";
import { registerAuthRoutes }  from "@sovereignly/oss/gateway/auth-routes";
import { OAuthBroker }         from "@sovereignly/oss/auth/oauth";
import { PasskeyEngine }       from "@sovereignly/oss/auth/passkeys";
import { mkdir }               from "node:fs/promises";
import { platformBus }             from "@sovereignly/oss/events/bus";
import { PolicyEngine }            from "@sovereignly/oss/policies/engine";
import { registerProtocolRoutes }  from "@sovereignly/oss/protocol/routes";
import { WorkflowEngine }          from "@sovereignly/oss/workflows/engine";
import { registerBuiltinWorkflows } from "@sovereignly/oss/workflows/builtins";
import { registerWorkflowRoutes }   from "@sovereignly/oss/workflows/routes";
import { AgentRuntime }             from "@sovereignly/oss/agents/runtime";
import { registerBuiltinAgents }    from "@sovereignly/oss/agents/builtins";
import { registerAgentRoutes }      from "@sovereignly/oss/agents/routes";
import { timingSafeEqual }      from "@sovereignly/oss/security/crypto";

//  Premium layers (BSL) 

import { ComplianceEngine }         from "./compliance.ts";
import { AnomalyDetector, createZeroTrustMiddleware } from "./zero-trust.ts";
import { TenantManager }            from "./tenants/manager.ts";
import { registerTenantRoutes }     from "./tenants/routes.ts";
import { BillingService, registerBillingRoutes } from "./billing/stripe.ts";
import { registerPublicRoutes }     from "./gateway/public-routes.ts";
import { TenantRateLimiter }        from "./gateway/tenant-limiter.ts";
import { WebhookManager }           from "./webhooks/index.ts";
import { registerWebhookRoutes }    from "./webhooks/routes.ts";

// Kernel (Phase 4)
import { StateRegistry }    from "./kernel/state-registry.ts";
import { HealthAnalyzer }   from "./kernel/health-analyzer.ts";
import { DecisionEngine }   from "./kernel/decision-engine.ts";
import { PlacementEngine }  from "./kernel/placement-engine.ts";
import { MigrationEngine }  from "./kernel/migration-engine.ts";
import { TopologyEngine }   from "./kernel/topology-engine.ts";
import { registerKernelRoutes } from "./kernel/routes.ts";
import { CognitiveModel }      from "./kernel/cognitive-model.ts";
import { AIOperatingSystem }    from "./kernel/ai-os.ts";
import { registerAIRoutes }     from "./kernel/ai-routes.ts";

// Phase 5: Developer Ecosystem
import { PluginRegistry }          from "@sovereignly/oss/ecosystem/plugins";
import { TemplateRegistry }        from "@sovereignly/oss/ecosystem/templates";
import { GamificationEngine }      from "@sovereignly/oss/ecosystem/gamification";
import { registerEcosystemRoutes } from "@sovereignly/oss/ecosystem/routes";

//  Config 

const NODE_ID      = process.env.SOVEREIGN_NODE_ID   ?? "primary";
const PORT         = parseInt(process.env.PORT        ?? "8787");
const HOST         = process.env.HOST                 ?? "0.0.0.0";
const DATA_DIR     = process.env.DATA_DIR             ?? "./data";
const POOL_SIZE    = parseInt(process.env.WORKER_POOL_SIZE ?? "4");
const ADMIN_TOKEN  = process.env.ADMIN_TOKEN;
const JWT_SECRET   = process.env.JWT_SECRET ?? crypto.randomUUID() + crypto.randomUUID();
const SERVER_KEY   = process.env.SOVEREIGN_SERVER_KEY ?? crypto.randomUUID();
const ANCHOR_INTERVAL = parseInt(process.env.CHAIN_ANCHOR_INTERVAL ?? "100");
const GLOBAL_ANCHOR_INTERVAL = parseInt(process.env.GLOBAL_ANCHOR_INTERVAL ?? "100");

const STRIPE_KEY     = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_GROWTH  = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_ENT     = process.env.STRIPE_PRICE_ENTERPRISE;

const APP_URL = process.env.SOVEREIGN_DOMAIN
  ? `https://${process.env.SOVEREIGN_DOMAIN}`
  : `http://localhost:${PORT}`;

console.log(`

       SOVEREIGNLY CLOUD v3.0.1  Multi-Tenant SaaS         

  Node: ${NODE_ID} | Port: ${PORT} | Workers: ${POOL_SIZE}
  Auth:     Passkeys + OAuth + SIWE + Solana
  Chain:    SovereignChain PoA (per-tenant isolated)
  Anchor:   ${process.env.EAS_BASE_RPC ? "EAS/Base " : "config EAS_BASE_RPC"}
  Billing:  ${STRIPE_KEY ? "Stripe " : "disabled"}
  License:  Business Source License 1.1
`);

await mkdir(DATA_DIR, { recursive: true });
await mkdir(`${DATA_DIR}/global`, { recursive: true });
await mkdir(`${DATA_DIR}/platform`, { recursive: true });

//  1. Omnichain anchor 

const ANCHOR_TIER = (process.env.ANCHOR_TIER ?? "starter") as AnchorTier;
const omniAnchor  = OmnichainAnchor.fromEnv(ANCHOR_TIER);
omniAnchor.verifySchemaConfig();

//  2. Platform chain 

const chain = new SovereignChain({
  dataDir:        `${DATA_DIR}/platform`,
  nodeId:         NODE_ID,
  anchorInterval: GLOBAL_ANCHOR_INTERVAL,
  omniAnchor,
  anchorOrgId:    "platform",
  peers:          (process.env.CLUSTER_PEERS ?? "").split(",").filter(Boolean),
});
await chain.init();

//  3. Multi-tenant manager (PREMIUM) 

const tenantManager = new TenantManager({ dataDir: DATA_DIR, nodeId: NODE_ID, serverKey: SERVER_KEY, omniAnchor });

// Global root anchor: Merkle root of all tenant tips
chain.onBlock(async (block) => {
  if (block.index > 0 && block.index % GLOBAL_ANCHOR_INTERVAL === 0) {
    try {
      const { root, tenantTips } = await tenantManager.buildGlobalRoot();
      await chain.emit("CONFIG_CHANGE", {
        event: "global_root_computed", root: "0x" + root,
        blockIdx: block.index, tenants: tenantTips.length,
      }, "LOW");
    } catch (e: any) { console.warn("[Chain] Global root failed:", e.message); }
  }
});

//  4. Auth engines 

const oauthBroker = new OAuthBroker({
  google:  process.env.GOOGLE_CLIENT_ID  ? { clientId: process.env.GOOGLE_CLIENT_ID!,  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,  redirectUri: `${APP_URL}/_sovereign/auth/oauth/google/callback`  } : undefined,
  github:  process.env.GITHUB_CLIENT_ID  ? { clientId: process.env.GITHUB_CLIENT_ID!,  clientSecret: process.env.GITHUB_CLIENT_SECRET!,  redirectUri: `${APP_URL}/_sovereign/auth/oauth/github/callback`  } : undefined,
  discord: process.env.DISCORD_CLIENT_ID ? { clientId: process.env.DISCORD_CLIENT_ID!, clientSecret: process.env.DISCORD_CLIENT_SECRET!, redirectUri: `${APP_URL}/_sovereign/auth/oauth/discord/callback` } : undefined,
  meta:    process.env.META_CLIENT_ID    ? { clientId: process.env.META_CLIENT_ID!,    clientSecret: process.env.META_CLIENT_SECRET!,    redirectUri: `${APP_URL}/_sovereign/auth/oauth/meta/callback`    } : undefined,
});

const passkeys = new PasskeyEngine({ dataDir: `${DATA_DIR}/platform`, rpId: process.env.SOVEREIGN_DOMAIN ?? "localhost", rpName: "Sovereignly", origin: APP_URL });

//  5. Platform services 

const compliance = new ComplianceEngine(chain);
const anomaly    = new AnomalyDetector(chain);
const kv         = new SovereignKV({ dataDir: `${DATA_DIR}/platform` });
await kv.init();
const storage    = new SovereignStorage({ dataDir: `${DATA_DIR}/platform` });
const runtime    = new SovereignRuntime(kv, POOL_SIZE);
const scheduler  = new SovereignScheduler(chain);

//  6. Billing (PREMIUM) 

let billing: BillingService | null = null;
if (STRIPE_KEY && STRIPE_WEBHOOK && STRIPE_STARTER && STRIPE_GROWTH) {
  billing = new BillingService(
    { stripeSecretKey: STRIPE_KEY, stripeWebhookSecret: STRIPE_WEBHOOK, prices: { starter: STRIPE_STARTER, growth: STRIPE_GROWTH, enterprise: STRIPE_ENT ?? "" }, successUrl: `${APP_URL}/dashboard`, cancelUrl: `${APP_URL}/pricing` },
    tenantManager, chain
  );
}

//  6b. Tenant rate limiter + webhooks (PREMIUM) 

const tenantLimiter = new TenantRateLimiter();
setInterval(() => tenantLimiter.gc(), 300_000);
const webhookManager = new WebhookManager(chain);

// Dispatch anchor events to tenant webhooks
chain.onBlock(async (block) => {
  if (block.index > 0 && block.index % ANCHOR_INTERVAL === 0) {
    for (const t of tenantManager.listTenants({ status: "active" })) {
      const ctx = await tenantManager.get(t.id).catch(() => null);
      if (ctx) {
        webhookManager.dispatch(ctx.kv, t.id, "anchor_completed", {
          merkleRoot: block.merkleRoot, blockIndex: block.index,
          eventCount: block.eventCount, nodeId: block.nodeId,
        }).catch(() => {});
      }
    }
  }
});

//  7. Gateway + all routes 

const zeroTrust = createZeroTrustMiddleware({ adminToken: ADMIN_TOKEN, jwtSecret: JWT_SECRET, chain, anomaly, enableHeaders: true });
const { app, metrics, cache, limiter } = createGateway(runtime, kv, storage, {
  port: PORT, host: HOST,
  corsOrigins: (process.env.CORS_ORIGINS ?? "*").split(","),
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT ?? "600"),
  adminToken: ADMIN_TOKEN, enableCompression: process.env.NODE_ENV === "production",
  logLevel: (process.env.LOG_LEVEL ?? "minimal") as any, zeroTrustMiddleware: zeroTrust,
});

// OSS routes (MIT)
registerChainRoutes(app, chain, compliance, { adminToken: ADMIN_TOKEN, jwtSecret: JWT_SECRET });
registerAuthRoutes(app, passkeys, oauthBroker, chain, { jwtSecret: JWT_SECRET, adminToken: ADMIN_TOKEN, appUrl: APP_URL });

// Premium routes (BSL)
registerTenantRoutes(app, tenantManager, billing, chain, { jwtSecret: JWT_SECRET, adminToken: ADMIN_TOKEN });
if (billing) registerBillingRoutes(app, billing, { jwtSecret: JWT_SECRET });
registerPublicRoutes(app, tenantManager, billing, chain, { jwtSecret: JWT_SECRET, adminToken: ADMIN_TOKEN });
registerWebhookRoutes(app, tenantManager, webhookManager, chain, { jwtSecret: JWT_SECRET, adminToken: ADMIN_TOKEN });

// Ecosystem routes (Phase 5)
registerEcosystemRoutes(app, pluginRegistry, templateRegistry, gamification, { adminToken: ADMIN_TOKEN });

// AI + Cognitive routes (Phase 6-7)
registerAIRoutes(app, aiOS, cognitiveModel, { adminToken: ADMIN_TOKEN });

// Kernel routes (Phase 4)
registerKernelRoutes(app, {
  state: stateRegistry, health: healthAnalyzer, decisions: decisionEngine,
  placement: placementEngine, migration: migrationEngine, topology: topologyEngine,
}, { adminToken: ADMIN_TOKEN });

// Agent routes (Phase 3)
registerAgentRoutes(app, agentRuntime, eventBus, { adminToken: ADMIN_TOKEN });

// Workflow routes (Phase 2)
registerWorkflowRoutes(app, workflowEngine, eventBus, { adminToken: ADMIN_TOKEN });

// Platform Protocol v1 routes (Phase 1)
registerProtocolRoutes(app, eventBus, policyEngine, { adminToken: ADMIN_TOKEN });

// SDK ingest with per-tenant rate limiting (PREMIUM)
app.post("/_sovereign/sdk/events", async (c) => {
  const orgId  = c.req.header("x-org-id");
  const apiKey = c.req.header("authorization")?.slice(7);
  if (!orgId || !apiKey) return c.json({ error: "x-org-id and Bearer API key required" }, 401);
  const ctx = await tenantManager.get(orgId);
  if (!ctx) return c.json({ error: "org not found" }, 404);
  const { events } = await c.req.json().catch(() => ({ events: [] }));
  if (!Array.isArray(events)) return c.json({ error: "events array required" }, 400);

  // Per-minute rate limit
  const rl = tenantLimiter.check(orgId, "events", ctx.tenant.plan, events.length);
  if (!rl.ok) {
    c.header("x-ratelimit-limit", String(rl.limit));
    c.header("retry-after", String(Math.ceil((rl.resetMs - Date.now()) / 1000)));
    return c.json({ error: `Rate limit exceeded (${rl.limit}/min on ${ctx.tenant.plan})`, upgradeUrl: "/_sovereign/signup/upgrade" }, 429);
  }
  c.header("x-ratelimit-limit", String(rl.limit));
  c.header("x-ratelimit-remaining", String(rl.remaining));

  // Monthly event limit enforcement
  const chainStats = ctx.chain.getStats();
  const monthlyLimit = ctx.tenant.limits.eventsPerMonth;
  if (monthlyLimit !== Infinity && chainStats.events + events.length > monthlyLimit) {
    return c.json({
      error: `Monthly event limit reached (${chainStats.events}/${monthlyLimit} on ${ctx.tenant.plan} plan)`,
      usage: { current: chainStats.events, limit: monthlyLimit, plan: ctx.tenant.plan },
      upgradeUrl: "/_sovereign/signup/upgrade",
    }, 429);
  }

  const results: Array<{ eventId: string; timestamp: number }> = [];
  for (const ev of events.slice(0, 100)) {
    await ctx.chain.emit(ev.type, ev.payload ?? {}, ev.severity ?? "LOW");
    results.push({ eventId: crypto.randomUUID(), timestamp: Date.now() });
  }
  return c.json({ results });
});

// Admin ops (PREMIUM)
app.get("/_sovereign/ops", (c) => {
  const xtoken = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
  if (!ADMIN_TOKEN || !timingSafeEqual(xtoken ?? '', ADMIN_TOKEN)) return c.json({ error: "admin required" }, 403);
  return c.json({
    version: "3.0.1", edition: "cloud", license: "BSL-1.1",
    uptime: process.uptime(),
    tenants: { active: tenantManager.getActiveCount(), byPlan: tenantManager.getPlanBreakdown(), mrr: tenantManager.getMRR(), arr: tenantManager.getMRR() * 12 },
    chain: chain.getStats(), rateLimiter: { activeTenants: tenantLimiter.activeTenants },
    webhooks: webhookManager.stats(),
    http: { requests: metrics.requests, errors: metrics.errors, rps: Number(metrics.rps.toFixed(4)) },
  });
});

//  Function dispatcher LAST
registerFunctionDispatcher(app, runtime, { metrics, cache, limiter, rateLimitPerMin: parseInt(process.env.RATE_LIMIT ?? "600") });

//  8. Start 

const server = startServer(app, { port: PORT, host: HOST });

await chain.emit("NODE_JOIN", {
  nodeId: NODE_ID, version: "3.0.1", edition: "cloud",
  port: PORT, peers: (process.env.CLUSTER_PEERS ?? "").split(",").filter(Boolean).length,
  features: { passkeys: true, oauth: oauthBroker.getSupportedProviders(), omnichain: true, billing: !!billing, tenants: true, webhooks: true },
}, "LOW");

console.log(`[Sovereignly Cloud]  Ready  ${APP_URL}
  Dashboard: ${APP_URL}/_sovereign/dashboard
  Signup:    ${APP_URL}/_sovereign/signup
  Ops:       ${APP_URL}/_sovereign/ops
`);

//  Shutdown 

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\n[Sovereignly Cloud] Shutting down...");
  await chain.emit("NODE_LEAVE", { nodeId: NODE_ID, reason: "graceful" }, "LOW");
  await chain.flush();
  server.stop(true); scheduler.stop(); runtime.shutdown(); webhookManager.close(); workflowEngine.close(); agentRuntime.close(); healthAnalyzer.close(); decisionEngine.close(); stateRegistry.close(); cognitiveModel.close(); gamification.close();
  await tenantManager.closeAll();
  kv.close(); storage.close(); chain.close();
  process.exit(0);
}

export { app, chain, kv, storage, runtime, scheduler, metrics, tenantManager, billing };
