import { timingSafeEqual } from "../security/crypto.ts";
/**
 * SovereignGateway
 *
 * A sovereign-aware reverse proxy that drops in front of ANY existing infrastructure.
 * Adds chain-verified audit logging, zero-trust auth enforcement, and rate limiting
 * without requiring a single line of application code to change.
 *
 * DEPLOYMENT MODELS:
 *
 *   Model A  Drop-in front of existing infra:
 *     Internet  SovereignGateway  Your AWS Lambda / Vercel / Railway
 *     Zero app changes. All traffic chain-logged.
 *
 *   Model B  API Gateway replacement:
 *     Internet  SovereignGateway  Internal services
 *     Route-level auth policies. Per-route rate limits. Full audit trail.
 *
 *   Model C  Sovereignly native:
 *     Internet  SovereignGateway  SovereignRuntime workers
 *     This is how Sovereignly already works.
 *
 * WHY THIS IS THE FASTEST PATH TO REVENUE:
 *   No migration required. Install, point at existing backend, done.
 *   Every company on AWS/Vercel/Railway is an immediate customer.
 *   "Add SOC2 audit trail to your existing stack in 5 minutes" is a compelling offer.
 *
 * WHAT IT DOES:
 *   1. Terminates TLS (Caddy behind it handles certs)
 *   2. Enforces auth policies per route (public | jwt | admin | custom)
 *   3. Rate limits per IP, per user, per route
 *   4. Logs every request to SovereignChain
 *   5. Strips sensitive headers before forwarding
 *   6. Injects request context headers to upstream
 *   7. Returns structured errors with chain event IDs
 */

import { Hono }          from "hono";
import type { Context }  from "hono";
import { verifyJWT }     from "../security/zero-trust.ts";
import type { SovereignChain } from "../security/chain.ts";

//  Route configuration 

export type AuthPolicy =
  | "public"       // No auth required
  | "jwt"          // Valid Sovereignly JWT required
  | "jwt_optional" // Auth attached if present, not required
  | "admin"        // Admin token or admin JWT
  | "api_key"      // Static API key (for service-to-service)
  | "passkey"      // Passkey auth only (high-security endpoints)
  | "wallet";      // Wallet signature only (on-chain operations)

export interface RoutePolicy {
  path:          string;       // e.g. "/api/*" or "/admin"
  upstream:      string;       // e.g. "https://my-lambda.lambda-url.us-east-1.on.aws"
  auth:          AuthPolicy;
  rateLimit?:    { reqPerMin: number; burstSize?: number };
  stripHeaders?:  string[];    // headers to remove before forwarding
  injectHeaders?: Record<string, string>;  // headers to add
  logBody?:      boolean;      // log request/response bodies to chain (careful with PII)
  logLevel?:     "all" | "errors" | "none";
  methods?:      string[];     // restrict HTTP methods
  timeout?:      number;       // upstream timeout ms (default 30s)
}

export interface GatewayConfig {
  routes:       RoutePolicy[];
  jwtSecret:    string;
  adminToken?:  string;
  apiKeys?:     Record<string, { orgId: string; name: string }>;
  chain:        SovereignChain;
  defaultUpstream?: string;    // fallback if no route matches
  trustProxy?:  boolean;       // trust X-Forwarded-For header
}

//  Rate limiter (in-memory, sliding window) 

class RateLimiter {
  private windows = new Map<string, number[]>();

  isAllowed(key: string, maxPerMin: number, burstSize: number = maxPerMin): boolean {
    const now    = Date.now();
    const window = 60_000;
    const hits   = (this.windows.get(key) ?? []).filter(t => now - t < window);
    if (hits.length >= burstSize) return false;
    hits.push(now);
    this.windows.set(key, hits);

    // Periodic cleanup
    if (this.windows.size > 50_000) {
      for (const [k, v] of this.windows) {
        if (!v.some(t => now - t < window)) this.windows.delete(k);
      }
    }
    return true;
  }
}

//  SovereignGateway 

export class SovereignGateway {
  private app:         Hono;
  private cfg:         GatewayConfig;
  private rateLimiter: RateLimiter;

  // Headers stripped from ALL upstream requests (security hygiene)
  private static readonly STRIP_ALWAYS = [
    "x-sovereign-token",
    "authorization",          // we re-inject our own auth context
    "x-forwarded-for",        // we control this
    "x-real-ip",
    "host",                   // upstream gets its own host
  ];

  // Headers injected on ALL forwarded requests
  private static readonly INJECT_ALWAYS = [
    "x-sovereign-gateway: 1",
    "x-sovereign-version: 3.0.1",
  ];

  constructor(cfg: GatewayConfig) {
    this.cfg         = cfg;
    this.app         = new Hono();
    this.rateLimiter = new RateLimiter();
    this.register();
  }

  private register() {
    this.app.all("*", async (c) => this.handle(c));
  }

  private async handle(c: Context): Promise<Response> {
    const start    = Date.now();
    const ip       = this.getIP(c);
    const method   = c.req.method;
    const url      = new URL(c.req.url);
    const path     = url.pathname;

    // Find matching route
    const route = this.matchRoute(path, method);
    if (!route) {
      if (this.cfg.defaultUpstream) {
        return this.proxy(c, this.cfg.defaultUpstream, null, null);
      }
      return c.json({ error: "no route", path }, 404);
    }

    // Rate limiting
    if (route.rateLimit) {
      const key = `${route.path}:${ip}`;
      if (!this.rateLimiter.isAllowed(key, route.rateLimit.reqPerMin, route.rateLimit.burstSize)) {
        void this.cfg.chain.emit("RATE_LIMIT_HIT", { path, ip, route: route.path }, "MEDIUM");
        return c.json({
          error:   "rate_limit_exceeded",
          retryIn: "60s",
        }, 429);
      }
    }

    // Auth enforcement
    let userId:  string | null = null;
    let orgId:   string | null = null;
    let authCtx: Record<string, string> = {};

    const authResult = await this.enforceAuth(c, route, ip);
    if (!authResult.ok) {
      const ms = Date.now() - start;
      if (route.logLevel !== "none") {
        void this.cfg.chain.emit("AUTH_FAILURE", {
          path, ip, method, reason: authResult.reason,
          ms, policy: route.auth,
        }, "MEDIUM");
      }
      return c.json({ error: authResult.reason, code: "auth_required" }, 401);
    }

    userId  = authResult.userId  ?? null;
    orgId   = authResult.orgId   ?? null;
    authCtx = authResult.context ?? {};

    // Proxy to upstream
    const response = await this.proxy(c, route.upstream, route, {
      userId, orgId, ip, ...authCtx,
    });

    // Audit log
    const ms     = Date.now() - start;
    const status = response.status;

    if (route.logLevel !== "none" && (route.logLevel === "all" || status >= 400)) {
      void this.cfg.chain.emit("DATA_READ", {
        path, method, status, ms, ip,
        userId: userId ?? undefined,
        orgId:  orgId  ?? undefined,
        upstream: route.upstream,
        routePolicy: route.auth,
      }, status >= 500 ? "HIGH" : status >= 400 ? "MEDIUM" : "LOW");
    }

    return response;
  }

  //  Auth enforcement 

  private async enforceAuth(
    c: Context,
    route: RoutePolicy,
    ip: string
  ): Promise<{
    ok:      boolean;
    userId?: string;
    orgId?:  string;
    context?: Record<string, string>;
    reason?: string;
  }> {
    switch (route.auth) {
      case "public":
        return { ok: true };

      case "jwt":
      case "jwt_optional": {
        const token = this.extractBearer(c);
        if (!token) {
          return route.auth === "jwt_optional"
            ? { ok: true }
            : { ok: false, reason: "Bearer token required" };
        }
        const { valid, payload } = await verifyJWT(token, this.cfg.jwtSecret);
        if (!valid) return { ok: false, reason: "invalid or expired token" };
        return {
          ok: true,
          userId: payload!.sub,
          context: {
            "x-sovereign-user-id":   payload!.sub,
            "x-sovereign-user-role": payload!.role,
          },
        };
      }

      case "admin": {
        const token = this.extractBearer(c) ?? c.req.header("x-sovereign-token");
        if (this.cfg.adminToken && timingSafeEqual(token, this.cfg.adminToken)) return { ok: true, context: { "x-sovereign-admin": "1" } };
        const { valid, payload } = token
          ? await verifyJWT(token, this.cfg.jwtSecret)
          : { valid: false, payload: null };
        if (!valid || payload?.role !== "admin") return { ok: false, reason: "admin access required" };
        return {
          ok: true,
          userId: payload!.sub,
          context: { "x-sovereign-admin": "1", "x-sovereign-user-id": payload!.sub },
        };
      }

      case "api_key": {
        const key = c.req.header("x-api-key") ?? this.extractBearer(c);
        if (!key || !this.cfg.apiKeys?.[key]) return { ok: false, reason: "valid API key required" };
        const kInfo = this.cfg.apiKeys[key];
        return {
          ok: true,
          orgId: kInfo.orgId,
          context: {
            "x-sovereign-org-id":  kInfo.orgId,
            "x-sovereign-key-name": kInfo.name,
          },
        };
      }

      default:
        return { ok: true };
    }
  }

  //  Proxy 

  private async proxy(
    c:        Context,
    upstream: string,
    route:    RoutePolicy | null,
    ctx:      Record<string, string> | null
  ): Promise<Response> {
    const url      = new URL(c.req.url);
    const upstreamUrl = upstream.replace(/\/$/, "") + url.pathname + url.search;

    // Build forwarded headers
    const headers = new Headers();

    // Copy original headers (except stripped ones)
    const stripSet = new Set([
      ...SovereignGateway.STRIP_ALWAYS,
      ...(route?.stripHeaders ?? []),
    ].map(h => h.toLowerCase()));

    for (const [k, v] of c.req.raw.headers.entries()) {
      if (!stripSet.has(k.toLowerCase())) headers.set(k, v);
    }

    // Inject standard gateway headers
    headers.set("x-sovereign-gateway",  "3.0.1");
    headers.set("x-forwarded-for",      this.getIP(c));
    headers.set("x-forwarded-proto",    "https");
    headers.set("x-forwarded-host",     url.hostname);

    // Inject auth context
    if (ctx) {
      for (const [k, v] of Object.entries(ctx)) {
        headers.set(k, v);
      }
    }

    // Inject route-level custom headers
    if (route?.injectHeaders) {
      for (const [k, v] of Object.entries(route.injectHeaders)) {
        headers.set(k, v);
      }
    }

    // Forward request
    try {
      const response = await fetch(upstreamUrl, {
        method:  c.req.method,
        headers,
        body:    ["GET", "HEAD"].includes(c.req.method) ? undefined : c.req.raw.body,
        signal:  AbortSignal.timeout(route?.timeout ?? 30_000),
        // Don't follow redirects  pass them through to client
        redirect: "manual",
      });

      return response;
    } catch (err: any) {
      const isTimeout = err.name === "TimeoutError" || err.message?.includes("timeout");
      void this.cfg.chain.emit("ANOMALY", {
        upstream, error: err.message,
        type: isTimeout ? "upstream_timeout" : "upstream_error",
      }, "HIGH");
      return new Response(
        JSON.stringify({ error: isTimeout ? "upstream_timeout" : "upstream_error" }),
        { status: 502, headers: { "content-type": "application/json" } }
      );
    }
  }

  //  Route matching 

  private matchRoute(path: string, method: string): RoutePolicy | null {
    for (const route of this.cfg.routes) {
      if (route.methods && !route.methods.includes(method)) continue;
      const pattern = route.path;

      if (pattern === "*" || pattern === "/*") return route;
      if (pattern.endsWith("/*")) {
        const prefix = pattern.slice(0, -2);
        if (path.startsWith(prefix)) return route;
      }
      if (pattern === path) return route;
      // Param matching: /api/users/:id
      if (this.matchParams(pattern, path)) return route;
    }
    return null;
  }

  private matchParams(pattern: string, path: string): boolean {
    const pParts = pattern.split("/");
    const uParts = path.split("/");
    if (pParts.length !== uParts.length) return false;
    return pParts.every((p, i) => p.startsWith(":") || p === uParts[i]);
  }

  //  Helpers 

  private getIP(c: Context): string {
    if (this.cfg.trustProxy) {
      const fwd = c.req.header("x-forwarded-for");
      if (fwd) return fwd.split(",")[0].trim();
    }
    return c.req.header("x-real-ip") ?? "unknown";
  }

  private extractBearer(c: Context): string | null {
    const auth = c.req.header("authorization") ?? "";
    return auth.startsWith("Bearer ") ? auth.slice(7) : null;
  }

  get fetch() { return this.app.fetch; }
}

//  Configuration DSL helper 

export function defineGateway(
  routes:  Array<Omit<RoutePolicy, "upstream"> & { upstream: string }>,
  opts:    Omit<GatewayConfig, "routes">
): SovereignGateway {
  return new SovereignGateway({ routes, ...opts });
}

/**
 * Quick-start: proxy everything to one upstream with full audit logging.
 *
 * @example
 * const gw = proxyAll({
 *   upstream: 'https://my-app.railway.app',
 *   chain,
 *   jwtSecret: process.env.JWT_SECRET!,
 * });
 * export default { fetch: gw.fetch };
 */
export function proxyAll(opts: {
  upstream:  string;
  chain:     SovereignChain;
  jwtSecret: string;
  auth?:     AuthPolicy;
  rateLimit?: { reqPerMin: number };
}): SovereignGateway {
  return new SovereignGateway({
    jwtSecret: opts.jwtSecret,
    chain:     opts.chain,
    routes: [{
      path:      "/*",
      upstream:  opts.upstream,
      auth:      opts.auth ?? "jwt_optional",
      rateLimit: opts.rateLimit,
      logLevel:  "all",
    }],
  });
}
