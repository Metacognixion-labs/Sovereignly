/**
 * Bootstrap: Gateway + Route Registration
 */

import { createGateway, startServer, registerFunctionDispatcher } from "@sovereignly/oss/gateway";
import { registerChainRoutes }    from "@sovereignly/oss/gateway/chain-routes";
import { registerAuthRoutes }     from "@sovereignly/oss/gateway/auth-routes";
import { registerProtocolRoutes } from "@sovereignly/oss/protocol/routes";
import { registerWorkflowRoutes } from "@sovereignly/oss/workflows/routes";
import { registerAgentRoutes }    from "@sovereignly/oss/agents/routes";
import { registerEcosystemRoutes } from "@sovereignly/oss/ecosystem/routes";
import { timingSafeEqual }        from "@sovereignly/oss/security/crypto";

import { registerTenantRoutes }   from "../tenants/routes.ts";
import { registerBillingRoutes }  from "../billing/stripe.ts";
import { registerPublicRoutes }   from "../gateway/public-routes.ts";
import { registerWebhookRoutes }  from "../webhooks/routes.ts";
import { registerKernelRoutes }   from "../kernel/routes.ts";
import { registerAIRoutes }       from "../kernel/ai-routes.ts";
import { registerClusterRoutes }  from "../cluster/routes.ts";
import { createZeroTrustMiddleware, AnomalyDetector } from "../zero-trust.ts";
import { ComplianceEngine }       from "../compliance.ts";

import type { SovereignChain } from "@sovereignly/oss/security/chain";
import type { Config } from "./config.ts";

export function createPlatformGateway(cfg: Config, deps: {
  chain: SovereignChain;
  runtime: any;
  kv: any;
  storage: any;
  // Auth
  passkeys: any;
  oauthBroker: any;
  // Tenants
  tenantManager: any;
  billing: any;
  tenantLimiter: any;
  webhookManager: any;
  // Kernel
  eventBus: any;
  policyEngine: any;
  workflowEngine: any;
  agentRuntime: any;
  stateRegistry: any;
  healthAnalyzer: any;
  decisionEngine: any;
  placementEngine: any;
  migrationEngine: any;
  topologyEngine: any;
  aiOS: any;
  cognitiveModel: any;
  // Ecosystem
  pluginRegistry: any;
  templateRegistry: any;
  gamification: any;
  // Cluster
  nodeRegistry: any;
  clusterTopology: any;
  globalAnchor: any;
  clusterBalancer: any;
  networkAnomalyDetector: any;
  costOptimizer: any;
  // Kernel orchestrator
  sovereignKernel: any;
}) {
  const compliance = new ComplianceEngine(deps.chain);
  const anomaly    = new AnomalyDetector(deps.chain);
  const zeroTrust  = createZeroTrustMiddleware({
    adminToken: cfg.adminToken,
    jwtSecret:  cfg.jwtSecret,
    chain:      deps.chain,
    anomaly,
    enableHeaders: true,
  });

  const { app, metrics, cache, limiter } = createGateway(deps.runtime, deps.kv, deps.storage, {
    port: cfg.port, host: cfg.host,
    corsOrigins: cfg.corsOrigins,
    rateLimitPerMin: cfg.rateLimitPerMin,
    adminToken: cfg.adminToken,
    enableCompression: cfg.isProduction,
    logLevel: cfg.logLevel,
    zeroTrustMiddleware: zeroTrust,
  });

  // OSS routes (MIT)
  registerChainRoutes(app, deps.chain, compliance, { adminToken: cfg.adminToken, jwtSecret: cfg.jwtSecret });
  registerAuthRoutes(app, deps.passkeys, deps.oauthBroker, deps.chain, { jwtSecret: cfg.jwtSecret, adminToken: cfg.adminToken, appUrl: cfg.appUrl, dataDir: `${cfg.dataDir}/platform` });

  // Premium routes (BSL)
  registerTenantRoutes(app, deps.tenantManager, deps.billing, deps.chain, { jwtSecret: cfg.jwtSecret, adminToken: cfg.adminToken });
  if (deps.billing) registerBillingRoutes(app, deps.billing, { jwtSecret: cfg.jwtSecret });
  registerPublicRoutes(app, deps.tenantManager, deps.billing, deps.chain, { jwtSecret: cfg.jwtSecret, adminToken: cfg.adminToken });
  registerWebhookRoutes(app, deps.tenantManager, deps.webhookManager, deps.chain, { jwtSecret: cfg.jwtSecret, adminToken: cfg.adminToken });

  // Ecosystem routes
  registerEcosystemRoutes(app, deps.pluginRegistry, deps.templateRegistry, deps.gamification, { adminToken: cfg.adminToken });

  // AI + Cognitive routes
  registerAIRoutes(app, deps.aiOS, deps.cognitiveModel, { adminToken: cfg.adminToken });

  // Kernel routes
  registerKernelRoutes(app, {
    state: deps.stateRegistry, health: deps.healthAnalyzer, decisions: deps.decisionEngine,
    placement: deps.placementEngine, migration: deps.migrationEngine, topology: deps.topologyEngine,
  }, { adminToken: cfg.adminToken });

  // Agent + Workflow + Protocol routes
  registerAgentRoutes(app, deps.agentRuntime, deps.eventBus, { adminToken: cfg.adminToken });
  registerWorkflowRoutes(app, deps.workflowEngine, deps.eventBus, { adminToken: cfg.adminToken });
  registerProtocolRoutes(app, deps.eventBus, deps.policyEngine, { adminToken: cfg.adminToken });

  // Cluster routes
  registerClusterRoutes(app, deps.nodeRegistry, deps.clusterTopology, { adminToken: cfg.adminToken });

  // Edge event ingestion
  app.post("/_sovereign/edge/events", async (c) => {
    const edgeNode = c.req.header("x-edge-node");
    if (!edgeNode) return c.json({ error: "x-edge-node header required" }, 400);
    const body = await c.req.json().catch(() => ({ events: [] }));
    if (!Array.isArray(body.events)) return c.json({ error: "events array required" }, 400);

    let processed = 0;
    for (const ev of body.events.slice(0, 200)) {
      await deps.eventBus.emit(ev.type ?? "CONFIG_CHANGE", {
        ...ev.payload,
        _sourceEdge: ev.sourceEdge,
        _forwardedAt: ev.timestamp,
      }, { source: `edge:${edgeNode}`, tenantId: ev.tenantId, severity: ev.severity as any });
      processed++;
    }
    return c.json({ ok: true, processed, edgeNode });
  });

  // SDK ingest with per-tenant rate limiting
  app.post("/_sovereign/sdk/events", async (c) => {
    const orgId  = c.req.header("x-org-id");
    const apiKey = c.req.header("authorization")?.slice(7);
    if (!orgId || !apiKey) return c.json({ error: "x-org-id and Bearer API key required" }, 401);
    const ctx = await deps.tenantManager.get(orgId);
    if (!ctx) return c.json({ error: "org not found" }, 404);
    const { events } = await c.req.json().catch(() => ({ events: [] }));
    if (!Array.isArray(events)) return c.json({ error: "events array required" }, 400);

    const rl = deps.tenantLimiter.check(orgId, "events", ctx.tenant.plan, events.length);
    if (!rl.ok) {
      c.header("x-ratelimit-limit", String(rl.limit));
      c.header("retry-after", String(Math.ceil((rl.resetMs - Date.now()) / 1000)));
      return c.json({ error: `Rate limit exceeded (${rl.limit}/min on ${ctx.tenant.plan})`, upgradeUrl: "/_sovereign/signup/upgrade" }, 429);
    }
    c.header("x-ratelimit-limit", String(rl.limit));
    c.header("x-ratelimit-remaining", String(rl.remaining));

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

  // Admin ops
  app.get("/_sovereign/ops", (c) => {
    const xtoken = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    if (!cfg.adminToken || !timingSafeEqual(xtoken ?? '', cfg.adminToken)) return c.json({ error: "admin required" }, 403);
    return c.json({
      version: "4.0.0", edition: "cloud", license: "BSL-1.1",
      node: { id: cfg.nodeId, role: cfg.nodeRole, region: cfg.nodeRegion, cluster: cfg.clusterId },
      uptime: process.uptime(),
      tenants: { active: deps.tenantManager.getActiveCount(), byPlan: deps.tenantManager.getPlanBreakdown(), mrr: deps.tenantManager.getMRR(), arr: deps.tenantManager.getMRR() * 12 },
      chain: deps.chain.getStats(), rateLimiter: { activeTenants: deps.tenantLimiter.activeTenants },
      webhooks: deps.webhookManager.stats(),
      http: { requests: metrics.requests, errors: metrics.errors, rps: Number(metrics.rps.toFixed(4)) },
      cluster: deps.nodeRegistry.stats(),
      globalAnchor: deps.globalAnchor.stats(),
      kernel: deps.sovereignKernel.stats(),
      ai: {
        balancer: deps.clusterBalancer.stats(),
        anomalies: deps.networkAnomalyDetector.stats(),
        costs: deps.costOptimizer.stats(),
      },
    });
  });

  // Function dispatcher LAST
  registerFunctionDispatcher(app, deps.runtime, { metrics, cache, limiter, rateLimitPerMin: cfg.rateLimitPerMin });

  return { app, metrics, cache, limiter, compliance, anomaly };
}
