import { timingSafeEqual } from "./security/crypto.ts";
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
import { OAuthBroker }         from "./auth/oauth.ts";
import { PasskeyEngine }       from "./auth/passkeys.ts";
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

//  4. Services 

const kv       = new SovereignKV({ dataDir: `${DATA_DIR}/platform` });
await kv.init();
const storage   = new SovereignStorage({ dataDir: `${DATA_DIR}/platform` });
const runtime   = new SovereignRuntime(kv, POOL_SIZE);
const scheduler = new SovereignScheduler(chain);

//  5. Gateway + routes 

const { app, metrics, cache, limiter } = createGateway(runtime, kv, storage, {
  port: PORT, host: HOST,
  corsOrigins: (process.env.CORS_ORIGINS ?? "*").split(","),
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT ?? "600"),
  adminToken: ADMIN_TOKEN,
  enableCompression: process.env.NODE_ENV === "production",
  logLevel: (process.env.LOG_LEVEL ?? "minimal") as any,
});

registerChainRoutes(app, chain, null, { adminToken: ADMIN_TOKEN, jwtSecret: JWT_SECRET });
registerAuthRoutes(app, passkeys, oauthBroker, chain, { jwtSecret: JWT_SECRET, adminToken: ADMIN_TOKEN, appUrl: APP_URL });

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

// Landing page: point to OSS docs
app.get("/", (c) => c.json({
  name: "Sovereignly",
  version: "4.0.0",
  edition: "oss",
  license: "MIT",
  docs: "/_sovereign/health",
  chain: "/_sovereign/chain/stats",
  github: "https://github.com/Metacognixion-labs/Sovereignly",
  cloud: "https://sovereignly.io",
}));

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

//  Shutdown 

let shuttingDown = false;
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\n[Sovereignly] Shutting down...");
  await chain.emit("NODE_LEAVE", { nodeId: NODE_ID, reason: "graceful" }, "LOW");
  await chain.flush();
  server.stop(true); scheduler.stop(); runtime.shutdown(); workflowEngine.close(); agentRuntime.close(); gamification.close();
  kv.close(); storage.close(); chain.close();
  process.exit(0);
}

export { app, chain, kv, storage, runtime, scheduler, metrics };
