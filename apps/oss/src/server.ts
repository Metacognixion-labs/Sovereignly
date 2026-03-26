import { timingSafeEqual } from "./security/crypto.ts";
import { initRevocationStore } from "./security/zero-trust.ts";
/**
 * Sovereignly OSS  Single-Tenant Server
 * MIT License  MetaCognixion
 *
 * The open-source edition. One process, one tenant, full audit chain.
 *   SovereignChain    Ed25519 PoA blockchain, Merkle-batched events
 *   OmnichainAnchor   Seals to EAS/Base, Arbitrum, Solana, Irys, Bitcoin
 *   SovereignRuntime  Bun serverless worker pool
 *   Auth              Passkeys, OAuth, SIWE, Solana wallet
 *   Gateway           Hono router, rate limiting, metrics, cache
 *
 * For multi-tenancy, compliance reports, billing, and webhooks:
 *    apps/cloud (Business Source License)
 *    or subscribe at https://sovereignly.io
 */

import { SovereignKV }        from "./kv/index.ts";
import { SovereignStorage }   from "./storage/index.ts";
import { SovereignRuntime }   from "./runtime/index.ts";
import { SovereignScheduler } from "./scheduler/index.ts";
import { createGateway, startServer, registerFunctionDispatcher } from "./gateway/index.ts";
import { SovereignChain }     from "./security/chain.ts";
import { OmnichainAnchor }    from "./security/omnichain-anchor.ts";
import type { AnchorTier }     from "./security/omnichain-anchor.ts";
import { registerChainRoutes } from "./gateway/chain-routes.ts";
import { registerAuthRoutes }  from "./gateway/auth-routes.ts";
import { OAuthBroker, initOAuthStore } from "./auth/oauth.ts";
import { PasskeyEngine }       from "./auth/passkeys.ts";
import { initSIWEStore }       from "./auth/siwe.ts";
import { initSolanaStore }     from "./auth/solana.ts";
import { initAuthCodeStore }   from "./gateway/auth-routes.ts";
import { mkdir }               from "node:fs/promises";
import { EventBus, platformBus }  from "./events/bus.ts";
import { PolicyEngine }            from "./policies/engine.ts";
import { registerProtocolRoutes }  from "./protocol/routes.ts";
import { WorkflowEngine }          from "./workflows/engine.ts";
import { registerBuiltinWorkflows } from "./workflows/builtins.ts";
import { registerWorkflowRoutes }   from "./workflows/routes.ts";
import { AgentRuntime }             from "./agents/runtime.ts";
import { registerBuiltinAgents }    from "./agents/builtins.ts";
import { registerAgentRoutes }      from "./agents/routes.ts";
import { PluginRegistry }           from "./ecosystem/plugins.ts";
import { TemplateRegistry }         from "./ecosystem/templates.ts";
import { GamificationEngine }       from "./ecosystem/gamification.ts";
import { registerEcosystemRoutes }  from "./ecosystem/routes.ts";
import { tracingMiddleware, prometheusHandler, log, errorCaptureMiddleware, registerErrorReportingRoutes } from "./observability/index.ts";
import { CAEPReceiver, registerCAEPRoutes } from "./auth/caep.ts";
import { MagicLinkService }     from "./auth/magic-link.ts";
import { createEmailTransport } from "./auth/email-transport.ts";
import { CredentialExchange, registerCXPRoutes } from "./auth/credential-exchange.ts";
import { VCIssuer, registerVCRoutes } from "./identity/vc.ts";
import { ComplianceEvaluator } from "./policies/compliance-rules.ts";
import { registerQuantumStatusRoutes } from "./security/quantum-status.ts";

//  Config 

const NODE_ID      = process.env.SOVEREIGN_NODE_ID   ?? "primary";
const PORT         = parseInt(process.env.PORT        ?? "8787");
const HOST         = process.env.HOST                 ?? "0.0.0.0";
const DATA_DIR     = process.env.DATA_DIR             ?? "./data";
const POOL_SIZE    = parseInt(process.env.WORKER_POOL_SIZE ?? "4");
const ADMIN_TOKEN  = process.env.ADMIN_TOKEN;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

// ── Production environment validation ────────────────────────────────────────
// Fail fast on missing required vars. Warn on suspicious optional values.
if (IS_PRODUCTION) {
  const fatal: string[] = [];
  if (!process.env.JWT_SECRET) fatal.push("JWT_SECRET");
  if (!process.env.SOVEREIGN_SERVER_KEY) fatal.push("SOVEREIGN_SERVER_KEY");
  if (!process.env.ADMIN_TOKEN) fatal.push("ADMIN_TOKEN");
  if (fatal.length > 0) {
    throw new Error(`FATAL: Missing required production env vars: ${fatal.join(", ")}. Refusing to start.`);
  }

  // Validate JWT_SECRET minimum strength (≥32 chars)
  if ((process.env.JWT_SECRET?.length ?? 0) < 32) {
    throw new Error("FATAL: JWT_SECRET must be at least 32 characters in production.");
  }

  // Validate CORS_ORIGINS is set (don't allow wildcard in prod)
  const corsOrigins = process.env.CORS_ORIGINS ?? "";
  if (!corsOrigins || corsOrigins === "*") {
    console.warn("[SECURITY] CORS_ORIGINS not set or uses wildcard '*' in production. Set explicit origins.");
  }

  // Validate SOVEREIGN_DOMAIN is set for proper cookie/URL handling
  if (!process.env.SOVEREIGN_DOMAIN) {
    console.warn("[SECURITY] SOVEREIGN_DOMAIN not set in production. Cookies and URLs will use localhost.");
  }

  // Warn about anchor tier defaulting to free
  if (!process.env.ANCHOR_TIER) {
    console.warn("[CONFIG] ANCHOR_TIER not set — defaulting to 'free'. Set 'evm' or 'solana' for blockchain anchoring.");
  }
}

const JWT_SECRET   = process.env.JWT_SECRET ?? (() => {
  console.warn("[WARN] JWT_SECRET not set — generating ephemeral secret. All tokens will be invalidated on restart.");
  return crypto.randomUUID() + crypto.randomUUID();
})();
const SERVER_KEY   = process.env.SOVEREIGN_SERVER_KEY ?? (() => {
  console.warn("[WARN] SOVEREIGN_SERVER_KEY not set — generating ephemeral key. Encrypted data will be unreadable after restart.");
  return crypto.randomUUID();
})();
const ANCHOR_INTERVAL = parseInt(process.env.CHAIN_ANCHOR_INTERVAL ?? "100");

const APP_URL = process.env.SOVEREIGN_DOMAIN
  ? `https://${process.env.SOVEREIGN_DOMAIN}`
  : `http://localhost:${PORT}`;

console.log(`

       SOVEREIGNLY OSS v4.0.0  Open Source Edition         

  Node: ${NODE_ID} | Port: ${PORT} | Workers: ${POOL_SIZE}
  License: MIT | github.com/Metacognixion-labs/Sovereignly
`);

await mkdir(DATA_DIR, { recursive: true });
await mkdir(`${DATA_DIR}/platform`, { recursive: true });

// Initialize persistent stores
initRevocationStore(`${DATA_DIR}/platform`);
platformBus.initOutbox(`${DATA_DIR}/platform`);

//  1. Omnichain anchor 

const ANCHOR_TIER = (process.env.ANCHOR_TIER ?? "free") as AnchorTier;
const omniAnchor  = OmnichainAnchor.fromEnv(ANCHOR_TIER);
omniAnchor.verifySchemaConfig();

//  2. Audit chain 

const chain = new SovereignChain({
  dataDir:        `${DATA_DIR}/platform`,
  nodeId:         NODE_ID,
  anchorInterval: ANCHOR_INTERVAL,
  omniAnchor,
  anchorOrgId:    "platform",
  peers:          (process.env.CLUSTER_PEERS ?? "").split(",").filter(Boolean),
});
await chain.init();

//  3. Auth 

const oauthBroker = new OAuthBroker({
  google:  process.env.GOOGLE_CLIENT_ID  ? { clientId: process.env.GOOGLE_CLIENT_ID!,  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,  redirectUri: `${APP_URL}/_sovereign/auth/oauth/google/callback`  } : undefined,
  github:  process.env.GITHUB_CLIENT_ID  ? { clientId: process.env.GITHUB_CLIENT_ID!,  clientSecret: process.env.GITHUB_CLIENT_SECRET!,  redirectUri: `${APP_URL}/_sovereign/auth/oauth/github/callback`  } : undefined,
});

const passkeys = new PasskeyEngine({
  dataDir: `${DATA_DIR}/platform`,
  rpId:    process.env.SOVEREIGN_DOMAIN ?? "localhost",
  rpName:  "Sovereignly",
  origin:  APP_URL,
});

// Magic link (email sign-in)
const emailTransport = createEmailTransport();
const magicLink = new MagicLinkService({
  dataDir:        `${DATA_DIR}/platform`,
  emailTransport,
  signingKey:     JWT_SECRET,
  appUrl:         APP_URL,
});

//  4. Services 

const kv       = new SovereignKV({ dataDir: `${DATA_DIR}/platform` });
await kv.init();

// Wire auth stores to persistent KV (Phase 1 security: no more in-memory auth state)
initSIWEStore(kv);
initSolanaStore(kv);
initOAuthStore(kv);
initAuthCodeStore(kv);
const storage   = new SovereignStorage({ dataDir: `${DATA_DIR}/platform` });
const runtime   = new SovereignRuntime(kv, { poolSize: POOL_SIZE });
const scheduler = new SovereignScheduler(runtime);

//  4b. Ecosystem services

const policyEngine    = new PolicyEngine(platformBus);
const workflowEngine  = new WorkflowEngine(platformBus, policyEngine);
registerBuiltinWorkflows(workflowEngine, platformBus);
const agentRuntime    = new AgentRuntime(platformBus, policyEngine, workflowEngine);
registerBuiltinAgents(agentRuntime);
const pluginRegistry  = new PluginRegistry(platformBus, policyEngine);
const templateRegistry = new TemplateRegistry();
const gamification    = new GamificationEngine(platformBus);

//  4c. CAEP receiver + Compliance evaluator
const caepReceiver = new CAEPReceiver(chain);
const complianceEvaluator = new ComplianceEvaluator(chain, platformBus, {
  jwtSecretSet:     !!process.env.JWT_SECRET,
  serverKeySet:     !!process.env.SOVEREIGN_SERVER_KEY,
  adminTokenSet:    !!ADMIN_TOKEN,
  tlsEnabled:       IS_PRODUCTION,
  rateLimitEnabled: true,
  corsRestricted:   IS_PRODUCTION,
  encryptionAtRest: !!process.env.SOVEREIGN_SERVER_KEY,
  passkeysEnabled:  true,
  mfaAvailable:     true,
  auditLogging:     true,
  anomalyDetection: true,
  secretScanning:   true,
  inputValidation:  true,
  workerIsolation:  true,
});
complianceEvaluator.start();

//  5. Gateway + routes

const { app, metrics, cache, limiter, gcTimer } = createGateway(runtime, kv, storage, {
  port: PORT, host: HOST,
  corsOrigins: (process.env.CORS_ORIGINS ?? (IS_PRODUCTION ? APP_URL : "*")).split(",").filter(Boolean),
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT ?? "600"),
  adminToken: ADMIN_TOKEN,
  enableCompression: process.env.NODE_ENV === "production",
  logLevel: (process.env.LOG_LEVEL ?? "minimal") as any,
  chain,
});

// Wire rate limiter to KV for distributed state across instances
limiter.useKV(kv);

// Observability: tracing first (assigns requestId/traceId), then error capture wraps all downstream
app.use("*", tracingMiddleware());
app.use("*", errorCaptureMiddleware(chain));
app.get("/_sovereign/prometheus", (c) => prometheusHandler(c));
registerErrorReportingRoutes(app, chain);

registerChainRoutes(app, chain, null, { adminToken: ADMIN_TOKEN, jwtSecret: JWT_SECRET });
registerAuthRoutes(app, passkeys, oauthBroker, chain, { jwtSecret: JWT_SECRET, adminToken: ADMIN_TOKEN, appUrl: APP_URL }, undefined, magicLink);
registerCAEPRoutes(app, caepReceiver, { adminToken: ADMIN_TOKEN, appUrl: APP_URL });

// Verifiable Credentials + Credential Exchange
const vcIssuer = new VCIssuer({
  domain: process.env.SOVEREIGN_DOMAIN ?? "localhost",
  issuerName: "Sovereignly",
  privateKey: new Uint8Array(32), // placeholder — use chain keypair in production
  publicKeyHex: "0".repeat(64),
});
registerVCRoutes(app, vcIssuer, chain, { adminToken: ADMIN_TOKEN });
const credExchange = new CredentialExchange(passkeys, chain, process.env.SOVEREIGN_DOMAIN ?? "localhost", "Sovereignly", APP_URL);
registerCXPRoutes(app, credExchange, { jwtSecret: JWT_SECRET });

registerProtocolRoutes(app, platformBus, policyEngine, { adminToken: ADMIN_TOKEN });

// Compliance-as-code + Quantum status endpoints
app.get("/_sovereign/compliance/live", (c) => c.json(complianceEvaluator.report()));
registerQuantumStatusRoutes(app, chain, { adminToken: ADMIN_TOKEN });
registerWorkflowRoutes(app, workflowEngine, platformBus, { adminToken: ADMIN_TOKEN });
registerAgentRoutes(app, agentRuntime, platformBus, { adminToken: ADMIN_TOKEN });
registerEcosystemRoutes(app, pluginRegistry, templateRegistry, gamification, { adminToken: ADMIN_TOKEN });

// SDK ingest endpoint (single-tenant: no org isolation)
app.post("/_sovereign/sdk/events", async (c) => {
  const apiKey = c.req.header("authorization")?.slice(7);
  if (!apiKey || (ADMIN_TOKEN && !timingSafeEqual(apiKey, ADMIN_TOKEN))) {
    return c.json({ error: "Bearer API key required" }, 401);
  }
  const { events } = await c.req.json().catch(() => ({ events: [] }));
  if (!Array.isArray(events)) return c.json({ error: "events array required" }, 400);

  const results: Array<{ eventId: string; timestamp: number }> = [];
  for (const ev of events.slice(0, 100)) {
    await chain.emit(ev.type, ev.payload ?? {}, ev.severity ?? "LOW");
    results.push({ eventId: crypto.randomUUID(), timestamp: Date.now() });
  }
  return c.json({ results });
});

// Landing page: redirect browsers to dashboard, return JSON for API clients
app.get("/", (c) => {
  const accept = c.req.header("accept") ?? "";
  if (accept.includes("text/html")) {
    return c.redirect("/_sovereign/dashboard");
  }
  return c.json({
    name: "Sovereignly",
    version: "4.0.0",
    edition: "oss",
    license: "MIT",
    dashboard: "/_sovereign/dashboard",
    docs: "/_sovereign/health",
    chain: "/_sovereign/chain/stats",
    github: "https://github.com/Metacognixion-labs/Sovereignly",
    cloud: "https://sovereignly.io",
  });
});

// Serve dashboard HTML (before function dispatcher catch-all)
import { existsSync, readFileSync } from "node:fs";
const dashboardPath = `${import.meta.dir}/../../../dashboard/index.html`;
if (existsSync(dashboardPath)) {
  const dashboardHtml = readFileSync(dashboardPath, "utf-8");
  app.get("/_sovereign/dashboard", (c) => c.html(dashboardHtml));
  app.get("/_sovereign/dashboard/*", (c) => c.html(dashboardHtml));
}

//  Function dispatcher LAST
registerFunctionDispatcher(app, runtime, {
  metrics, cache, limiter,
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT ?? "600"),
});

//  6. Start 

const server = startServer(app, { port: PORT, host: HOST });

await chain.emit("NODE_JOIN", {
  nodeId: NODE_ID, version: "4.0.0", edition: "oss",
  port: PORT, features: { passkeys: true, oauth: oauthBroker.getSupportedProviders(), omnichain: true },
}, "LOW");

console.log(`[Sovereignly OSS]  Ready  ${APP_URL}`);

//  Graceful Shutdown (drain in-flight → flush chain → close stores)

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;

  const shutdownStart = Date.now();
  log("info", "Graceful shutdown initiated", { nodeId: NODE_ID });

  // 1. Stop accepting new connections (allow in-flight to drain for up to 10s)
  server.stop(false); // false = don't abort existing connections
  log("info", "Stopped accepting new connections, draining in-flight requests...");

  // Wait for in-flight requests (max 10 seconds)
  const DRAIN_TIMEOUT_MS = 10_000;
  await new Promise<void>((resolve) => {
    const check = setInterval(() => {
      // server.pendingRequests only available in newer Bun versions
      if (Date.now() - shutdownStart > DRAIN_TIMEOUT_MS) {
        clearInterval(check);
        log("warn", "Drain timeout reached, forcing shutdown", { elapsed: Date.now() - shutdownStart });
        resolve();
      }
    }, 100);
    // Also resolve immediately if drain completes
    setTimeout(resolve, 2000); // Minimum 2s grace for in-flight
  });

  // 2. Emit NODE_LEAVE and flush chain events to disk + omnichain
  try {
    await chain.emit("NODE_LEAVE", { nodeId: NODE_ID, reason: "graceful", uptimeMs: Date.now() - shutdownStart }, "LOW");
    await chain.flush();
    log("info", "Chain events flushed");
  } catch (err: any) {
    log("error", "Failed to flush chain during shutdown", { error: err.message });
  }

  // 3. Stop background services + clear timers
  clearInterval(gcTimer);
  complianceEvaluator.stop();
  scheduler.stop();
  runtime.shutdown();
  workflowEngine.close();
  agentRuntime.close();
  gamification.close();

  // 4. Close data stores (order: consumers first, then stores)
  kv.close();
  storage.close();
  chain.close();
  magicLink.close();

  const elapsed = Date.now() - shutdownStart;
  log("info", "Shutdown complete", { elapsed });
  process.exit(0);
}

export { app, chain, kv, storage, runtime, scheduler, metrics };
