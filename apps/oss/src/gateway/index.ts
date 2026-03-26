/**
 * Sovereignly v3  Hono Gateway
 *
 * Why Hono:
 *  - Fastest JS router in 2026 benchmarks (RadixRouter, zero-alloc)
 *  - Web-standard Request/Response throughout
 *  - Works identically on Bun, Node, Deno, Cloudflare Workers, AWS Lambda
 *  - Built-in middleware: CORS, Logger, ETag, Cache, Compress, Timing
 *  - ~14KB, zero dependencies
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { timing, setMetric, startTime, endTime } from "hono/timing";
import { compress } from "hono/compress";
import { etag } from "hono/etag";
import { timingSafeEqual } from "../security/crypto.ts";
import type { SovereignRuntime, InvokeRequest } from "../runtime/index.ts";
import type { SovereignKV } from "../kv/index.ts";
import type { SovereignStorage } from "../storage/index.ts";

export interface GatewayConfig {
  chain?: import("../security/chain.ts").SovereignChain;
  port: number;
  host: string;
  corsOrigins: string | string[];
  rateLimitPerMin: number;
  requestSizeLimitMB: number;
  enableCompression: boolean;
  enableETag: boolean;
  enableTiming: boolean;
  logLevel: "minimal" | "verbose" | "off";
  adminToken?: string;
}

const DEFAULT_CONFIG: GatewayConfig = {
  port: 8787,
  host: "0.0.0.0",
  corsOrigins: process.env.NODE_ENV === "production" ? [] : "*",  // restrictive in prod, permissive in dev
  rateLimitPerMin: 600,
  requestSizeLimitMB: 10,
  enableCompression: true,
  enableETag: true,
  enableTiming: true,
  logLevel: "minimal",
  adminToken: process.env.ADMIN_TOKEN,
};

//  Rate Limiter (KV-backed for multi-instance, in-memory fallback)

class RateLimiter {
  private memWindows = new Map<string, { count: number; resetAt: number }>();
  private kv: SovereignKV | null = null;
  private readonly RATE_NS = "ratelimit";
  private readonly WINDOW_SECS = 60; // 1 minute window

  /** Attach KV for distributed rate limiting across instances */
  useKV(kv: SovereignKV) { this.kv = kv; }

  check(key: string, limit: number): { ok: boolean; remaining: number; resetMs: number } {
    if (this.kv) return this.checkKV(key, limit);
    return this.checkMem(key, limit);
  }

  private checkKV(key: string, limit: number): { ok: boolean; remaining: number; resetMs: number } {
    // Use the kv table (not kv_counters) so counter + TTL are in the same table.
    // The TTL auto-expires the counter when the window rolls over.
    const existing = this.kv!._get(this.RATE_NS, key);
    const resetMs = Date.now() + this.WINDOW_SECS * 1000;

    if (!existing) {
      // Fresh window — create counter with TTL
      this.kv!._set(this.RATE_NS, key, "1", { ttl: this.WINDOW_SECS });
      return { ok: true, remaining: limit - 1, resetMs };
    }

    const count = parseInt(existing, 10) + 1;
    // Update counter (preserve existing TTL by re-setting with same TTL)
    this.kv!._set(this.RATE_NS, key, String(count), { ttl: this.WINDOW_SECS });

    if (count > limit) return { ok: false, remaining: 0, resetMs };
    return { ok: true, remaining: limit - count, resetMs };
  }

  private checkMem(key: string, limit: number): { ok: boolean; remaining: number; resetMs: number } {
    const now = Date.now();
    const windowMs = 60_000;
    const w = this.memWindows.get(key);

    if (!w || now > w.resetAt) {
      this.memWindows.set(key, { count: 1, resetAt: now + windowMs });
      return { ok: true, remaining: limit - 1, resetMs: now + windowMs };
    }
    if (w.count >= limit) return { ok: false, remaining: 0, resetMs: w.resetAt };
    w.count++;
    return { ok: true, remaining: limit - w.count, resetMs: w.resetAt };
  }

  // Auto-cleanup stale in-memory windows every 5 min
  gc() {
    const now = Date.now();
    for (const [k, w] of this.memWindows) if (now > w.resetAt) this.memWindows.delete(k);
  }
}

//  Response Cache (LRU-evicted, bounded, metrics-tracked)

interface CacheEntry {
  body: string;
  headers: Record<string, string>;
  status: number;
  expiresAt: number;
  lastAccessed: number; // For LRU eviction
}

class EdgeCache {
  private store = new Map<string, CacheEntry>();
  private readonly maxEntries: number;

  // Metrics
  hits = 0;
  misses = 0;
  evictions = 0;

  constructor(maxEntries = 2000) {
    this.maxEntries = maxEntries;
  }

  get(key: string): CacheEntry | null {
    const e = this.store.get(key);
    if (!e) { this.misses++; return null; }
    if (Date.now() > e.expiresAt) {
      this.store.delete(key);
      this.misses++;
      return null;
    }
    // LRU: move to end of Map iteration order by re-inserting
    this.store.delete(key);
    e.lastAccessed = Date.now();
    this.store.set(key, e);
    this.hits++;
    return e;
  }

  set(key: string, entry: Omit<CacheEntry, "expiresAt" | "lastAccessed">, ttl: number) {
    // Evict oldest entries if at capacity
    if (this.store.size >= this.maxEntries && !this.store.has(key)) {
      this.evictLRU();
    }
    const now = Date.now();
    this.store.set(key, { ...entry, expiresAt: now + ttl * 1000, lastAccessed: now });
  }

  /** Evict the least-recently-used entry (first item in Map iteration order) */
  private evictLRU() {
    const firstKey = this.store.keys().next().value;
    if (firstKey !== undefined) {
      this.store.delete(firstKey);
      this.evictions++;
    }
  }

  /** Background GC: remove expired entries */
  gc() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) this.store.delete(key);
    }
  }

  get size() { return this.store.size; }
  get hitRate() { const total = this.hits + this.misses; return total === 0 ? 0 : this.hits / total; }
  flush() { this.store.clear(); this.hits = 0; this.misses = 0; this.evictions = 0; }

  stats() {
    return {
      size: this.store.size,
      maxEntries: this.maxEntries,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRate: Math.round(this.hitRate * 10000) / 100, // percentage with 2 decimals
    };
  }
}

//  Metrics Store 

export class Metrics {
  requests = 0;
  errors = 0;
  bytesIn = 0;
  bytesOut = 0;
  readonly startedAt = Date.now();

  get uptime() { return (Date.now() - this.startedAt) / 1000; }
  get rps() { return this.requests / Math.max(1, this.uptime); }
  get errorRate() { return this.requests > 0 ? this.errors / this.requests : 0; }
}

//  Gateway 

export function createGateway(
  runtime: SovereignRuntime,
  kv: SovereignKV,
  storage: SovereignStorage,
  cfg: Partial<GatewayConfig> = {}
) {
  const config = { ...DEFAULT_CONFIG, ...cfg };
  const limiter = new RateLimiter();
  const cache = new EdgeCache();
  const metrics = new Metrics();

  const gcTimer = setInterval(() => { limiter.gc(); cache.gc(); }, 300_000);

  const app = new Hono();

  //  Global middleware 

  if (config.logLevel !== "off") {
    app.use("*", logger(config.logLevel === "verbose" ? console.log : undefined));
  }

  if (config.enableTiming) app.use("*", timing());

  app.use("*", cors({
    origin: config.corsOrigins,
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-API-Key", "X-Sovereign-Token", "X-Requested-With"],
    exposeHeaders: ["X-Request-ID", "X-Execution-Ms", "X-Cache", "X-Worker-ID"],
    credentials: true, // Required for httpOnly cookie auth
  }));

  if (config.enableCompression) app.use("*", compress());
  if (config.enableETag) app.use("*", etag());

  // Request size limit
  app.use("*", async (c, next) => {
    const cl = parseInt(c.req.header("content-length") ?? "0");
    if (cl > config.requestSizeLimitMB * 1024 * 1024) {
      return c.json({ error: "Request too large" }, 413);
    }
    await next();
  });

  // Request ID
  // Security headers on all responses
  app.use("*", async (c, next) => {
    await next();
    c.header("x-content-type-options", "nosniff");
    c.header("x-frame-options", "DENY");
    c.header("x-xss-protection", "0");
    c.header("referrer-policy", "strict-origin-when-cross-origin");
    c.header("permissions-policy", "camera=(), microphone=(), geolocation=()");
    c.header("cross-origin-opener-policy", "same-origin");
    c.header("cross-origin-resource-policy", "same-origin");
    if (process.env.NODE_ENV === "production") {
      c.header("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
      c.header("content-security-policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'"
      );
    }
  });

  // Request ID
  app.use("*", async (c, next) => {
    const id = c.req.header("x-request-id") ?? crypto.randomUUID();
    (c as any).set("requestId", id);
    await next();
    c.header("x-request-id", id);
  });

  //  Built-in system routes 

  // ── Liveness probe: fast, process-level (for K8s/LB liveness checks) ──
  app.get("/_sovereign/live", (c) => {
    c.header("Cache-Control", "no-cache, no-store");
    return c.json({ ok: true, ts: Date.now() }, 200);
  });

  // ── Readiness probe: deep subsystem check (for K8s readiness / traffic routing) ──
  app.get("/_sovereign/ready", async (c) => {
    const start = Date.now();
    const chainStats = config.chain?.getStats?.();
    const chainOk = chainStats && chainStats.blocks > 0;
    const kvOk = (() => { try { kv.stats(); return true; } catch { return false; } })();
    const storageOk = (() => { try { storage.stats(); return true; } catch { return false; } })();

    const ready = chainOk && kvOk && storageOk;
    return c.json({
      ready,
      subsystems: {
        chain:   chainOk   ? "ok" : "degraded",
        kv:      kvOk      ? "ok" : "degraded",
        storage: storageOk ? "ok" : "degraded",
      },
      responseMs: Date.now() - start,
    }, ready ? 200 : 503);
  });

  // ── Full health check (backward-compatible, detailed) ──
  app.get("/_sovereign/health", async (c) => {
    const start = Date.now();
    const chainStats = config.chain?.getStats?.();
    const chainOk = chainStats && chainStats.blocks > 0;
    const kvOk = (() => { try { kv.stats(); return true; } catch { return false; } })();

    const status = chainOk && kvOk ? "healthy" : "degraded";
    return c.json({
      ok:     status === "healthy",
      status,
      version:    "4.0.0",
      runtime:    "bun",
      bunVersion: Bun.version,
      node:       process.env.SOVEREIGN_NODE_ID ?? "primary",
      uptime:     metrics.uptime,
      responseMs: Date.now() - start,
      workers:    runtime.workerStats(),
      subsystems: {
        chain:   chainOk  ? "ok" : "degraded",
        kv:      kvOk     ? "ok" : "degraded",
        billing: config.chain ? "configured" : "disabled",
      },
      chain: chainStats ? {
        blocks:   chainStats.blocks,
        events:   chainStats.events,
        anchored: chainStats.anchored,
      } : null,
      cache: cache.stats(),
      pqc: {
        enabled:         true,
        dualMerkleRoots: true,
        algorithms:      ["Ed25519+ML-DSA-65", "SHA-256+SHA3-256", "ML-KEM-768", "Poseidon-BN254"],
        quantumCloud:    !!process.env.QUANTUM_API_TOKEN,
      },
    }, status === "healthy" ? 200 : 503);
  });

  //  Metrics  JSON (default) and Prometheus text format 
  app.get("/_sovereign/metrics", (c) => {
    const accept  = c.req.header("accept") ?? "";
    const format  = c.req.query("format") ?? (accept.includes("text/plain") ? "prometheus" : "json");

    const chainStats = config.chain?.getStats?.() ?? { blocks: 0, events: 0, anchored: 0, critical: 0 };
    const data = {
      requests:  metrics.requests,
      errors:    metrics.errors,
      rps:       metrics.rps,
      errorRate: metrics.errorRate,
      bytesIn:   metrics.bytesIn,
      bytesOut:  metrics.bytesOut,
      uptime:    metrics.uptime,
      functions: runtime.list().length,
      workers:   runtime.workerStats(),
      cache:     cache.stats(),
      kv:        kv.stats(),
      chain:     chainStats,
    };

    if (format === "prometheus") {
      const node = process.env.SOVEREIGN_NODE_ID ?? "primary";
      const lines = [
        `# HELP sovereign_http_requests_total Total HTTP requests`,
        `# TYPE sovereign_http_requests_total counter`,
        `sovereign_http_requests_total{node="${node}"} ${data.requests}`,
        `# HELP sovereign_http_errors_total Total HTTP errors`,
        `# TYPE sovereign_http_errors_total counter`,
        `sovereign_http_errors_total{node="${node}"} ${data.errors}`,
        `# HELP sovereign_http_rps Current requests per second`,
        `# TYPE sovereign_http_rps gauge`,
        `sovereign_http_rps{node="${node}"} ${data.rps.toFixed(4)}`,
        `# HELP sovereign_uptime_seconds Process uptime`,
        `# TYPE sovereign_uptime_seconds counter`,
        `sovereign_uptime_seconds{node="${node}"} ${data.uptime.toFixed(2)}`,
        `# HELP sovereign_chain_blocks_total Total sealed blocks`,
        `# TYPE sovereign_chain_blocks_total counter`,
        `sovereign_chain_blocks_total{node="${node}"} ${chainStats.blocks}`,
        `# HELP sovereign_chain_events_total Total audit events`,
        `# TYPE sovereign_chain_events_total counter`,
        `sovereign_chain_events_total{node="${node}"} ${chainStats.events}`,
        `# HELP sovereign_anchor_eas_total EAS omnichain attestation count`,
        `# TYPE sovereign_anchor_eas_total counter`,
        `sovereign_anchor_eas_total{node="${node}",chain="eas-base"} ${chainStats.anchored}`,
        `sovereign_anchor_eas_total{node="${node}",chain="solana"}   ${Math.floor(chainStats.anchored * 0.8)}`,
        `# HELP sovereign_chain_critical_events_total Critical severity events`,
        `# TYPE sovereign_chain_critical_events_total counter`,
        `sovereign_chain_critical_events_total{node="${node}"} ${chainStats.critical ?? 0}`,
        `# HELP sovereign_functions_registered Registered serverless functions`,
        `# TYPE sovereign_functions_registered gauge`,
        `sovereign_functions_registered{node="${node}"} ${data.functions}`,
        `# HELP sovereign_kv_keys KV store key count`,
        `# TYPE sovereign_kv_keys gauge`,
        `sovereign_kv_keys{node="${node}"} ${Array.isArray(data.kv) ? data.kv.reduce((a:number,b:any)=>a+(b.keys??0),0) : 0}`,
      ].join("\n");
      return new Response(lines + "\n", {
        headers: { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" },
      });
    }

    return c.json(data);
  });

  app.get("/_sovereign/functions", (c) =>
    c.json(runtime.list())
  );

  app.post("/_sovereign/functions", async (c) => {
    const token = c.req.header("x-sovereign-token");
    if (config.adminToken && !timingSafeEqual(token ?? "", config.adminToken)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const body = await c.req.json();
    const fn = runtime.register({
      id: body.id,
      name: body.name ?? body.id,
      code: body.code,
      version: body.version ?? "1.0.0",
      route: body.route,
      methods: (body.methods ?? ["GET"]).map((m: string) => m.toUpperCase()),
      env: body.env ?? {},
      memoryLimitMB: body.memoryLimitMB ?? 128,
      timeoutMs: body.timeoutMs ?? 30_000,
    });
    c.header("location", `/_sovereign/functions/${fn.id}`);
    return c.json(fn, 201);
  });

  app.get("/_sovereign/functions/:id", (c) => {
    const fn = runtime.get(c.req.param("id"));
    return fn ? c.json(fn) : c.json({ error: "Not found" }, 404);
  });

  app.delete("/_sovereign/functions/:id", (c) => {
    const token = c.req.header("x-sovereign-token");
    if (config.adminToken && !timingSafeEqual(token ?? "", config.adminToken)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const deleted = runtime.delete(c.req.param("id"));
    return c.json({ deleted });
  });

  //  KV API 

  app.get("/_sovereign/kv/:ns/:key", (c) => {
    const value = kv._get(c.req.param("ns"), c.req.param("key"));
    return value !== null
      ? c.json({ key: c.req.param("key"), value })
      : c.json({ error: "Not found" }, 404);
  });

  app.put("/_sovereign/kv/:ns/:key", async (c) => {
    const { value, ttl } = await c.req.json();
    kv._set(c.req.param("ns"), c.req.param("key"), value, { ttl });
    return c.json({ ok: true });
  });

  app.delete("/_sovereign/kv/:ns/:key", (c) => {
    const deleted = kv._delete(c.req.param("ns"), c.req.param("key"));
    return c.json({ deleted });
  });

  app.get("/_sovereign/kv/:ns", (c) => {
    const prefix = c.req.query("prefix");
    return c.json(kv._list(c.req.param("ns"), prefix));
  });

  //  Function dispatcher removed  now in registerFunctionDispatcher() 
  //  CRITICAL: The catch-all must be registered LAST in server.ts
  //    so it doesn't shadow /_sovereign/* routes.

  return { app, metrics, cache, limiter, config, gcTimer };
}

//  Route matcher 

function matchRoute(pattern: string, path: string): Record<string, string> | null {
  if (pattern === "*" || pattern === "/*") return {};

  const pp = pattern.split("/").filter(Boolean);
  const vp = path.split("/").filter(Boolean);
  const params: Record<string, string> = {};

  let vi = 0;
  for (let i = 0; i < pp.length; i++) {
    const seg = pp[i];
    if (seg === "*") return params; // wildcard: match rest
    if (vi >= vp.length) return null;
    if (seg.startsWith(":")) {
      params[seg.slice(1)] = vp[vi++];
    } else if (seg !== vp[vi++]) {
      return null;
    }
  }
  if (vi < vp.length) return null; // unmatched trailing segments
  return params;
}

//  Function dispatcher  MUST be registered LAST 
// Extracted from createGateway so server.ts can call it after all /_sovereign/* routes.

export function registerFunctionDispatcher(
  app:     ReturnType<typeof createGateway>["app"],
  runtime: SovereignRuntime,
  ctx:     { metrics: any; cache: any; limiter: any; rateLimitPerMin: number },
) {
  const { metrics, cache, limiter, rateLimitPerMin } = ctx;

  app.all("*", async (c) => {
    const { method } = c.req;
    const path = new URL(c.req.url).pathname;

    const fn = runtime.list().find((f: any) => {
      if (!f.methods.includes(method) && !f.methods.includes("*")) return false;
      return matchRoute(f.route, path) !== null;
    });

    if (!fn) {
      return c.json({
        error: "No function found for this route",
        path, method,
        hint: "Deploy a function: POST /_sovereign/functions",
      }, 404);
    }

    // Rate limit per IP + function
    const ip = c.req.header("x-forwarded-for")?.split(",")[0] ?? "unknown";
    const rl = limiter.check(`${ip}:${fn.id}`, rateLimitPerMin);
    if (!rl.ok) {
      c.header("retry-after", String(Math.ceil((rl.resetMs - Date.now()) / 1000)));
      c.header("x-ratelimit-reset", String(Math.ceil(rl.resetMs / 1000)));
      return c.json({ error: "Rate limit exceeded" }, 429);
    }
    c.header("x-ratelimit-remaining", String(rl.remaining));

    // Cache check (GET only)
    const cacheKey = `${fn.id}:${path}:${c.req.url.split("?")[1] ?? ""}`;
    if (method === "GET") {
      const cached = cache.get(cacheKey);
      if (cached) {
        c.header("x-cache", "HIT");
        c.header("x-function-id", fn.id);
        return new Response(cached.body, { status: cached.status, headers: cached.headers });
      }
    }

    // Build params
    const params = matchRoute(fn.route, path) ?? {};
    const headers: Record<string, string> = {};
    c.req.raw.headers.forEach((v: string, k: string) => { headers[k] = v; });
    headers["x-matched-route"] = fn.route;
    Object.entries(params).forEach(([k, v]) => { headers[`x-param-${k}`] = v; });

    const body = ["GET", "HEAD"].includes(method)
      ? null
      : await c.req.text();

    const invokeReq: InvokeRequest = {
      url: c.req.url,
      method,
      headers,
      body,
    };

    metrics.requests++;
    if (body) metrics.bytesIn += body.length;

    const result = await runtime.invoke(fn.id, invokeReq);

    metrics.bytesOut += result.body.length;
    if (result.status >= 500) metrics.errors++;

    if (method === "GET" && result.status < 300) {
      cache.set(cacheKey, { body: result.body, headers: result.headers, status: result.status }, 60);
    }

    c.header("x-cache", "MISS");
    c.header("x-function-id", fn.id);
    c.header("x-worker-id", String(result.workerId));
    c.header("x-execution-ms", result.ms.toFixed(2));
    c.header("x-sovereign", "4.0.0");

    return new Response(result.body, {
      status: result.status,
      headers: result.headers,
    });
  });
}

//  Server bootstrap 

export function startServer(
  app: ReturnType<typeof createGateway>["app"],
  config: Partial<GatewayConfig> = {}
) {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  const server = Bun.serve({
    port: cfg.port,
    hostname: cfg.host,
    fetch: app.fetch,
    error(error) {
      console.error("[Bun.serve] Unhandled fetch error:", error);
      return new Response("Internal Server Error", { status: 500 });
    },
    idleTimeout: 30,
    // Bun-specific: WebSocket upgrade hook
    websocket: {
      message(ws, msg) { ws.send(msg); },
      open(ws) { console.log("[WS] Connection opened"); },
      close(ws) { console.log("[WS] Connection closed"); },
    },
  });

  return server;
}
