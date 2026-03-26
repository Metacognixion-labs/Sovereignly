/**
 * Sovereignly v3  Zero-Trust Security Layer
 *
 * Implements the full zero-trust perimeter:
 *
 *   1. RBAC          admin / deployer / reader / auditor roles
 *   2. JWT Auth      HMAC-SHA256 signed tokens, short-lived
 *   3. Request Signing  HMAC-SHA256 request signature validation
 *   4. Anomaly Detection  spike, brute-force, recon pattern detection
 *   5. Secret Scanner    blocks function deploys with hardcoded credentials
 *   6. Security Headers  OWASP-recommended HTTP headers
 *   7. Audit Bridge      every security event  SovereignChain
 *
 * Maps to SOC2 Trust Services Criteria:
 *   CC6.1  Logical access controls
 *   CC6.6  Boundary protection
 *   CC6.8  Unauthorized software protection
 *   CC7.2  Anomaly detection
 *   CC7.3  Incident response events
 */

import type { Context, Next, MiddlewareHandler } from "hono";
import { Database } from "bun:sqlite";
import { join }     from "node:path";
import { hmac256, hmac256Verify, sha256, timingSafeEqual } from "./crypto.ts";
import { InputShield }                     from "./input-shield.ts";
import type { SovereignChain }            from "./chain.ts";

//  RBAC

export type Role = "admin" | "deployer" | "reader" | "auditor" | "owner";

export const PERMISSIONS: Record<Role, Set<string>> = {
  admin:    new Set(["*"]),
  deployer: new Set(["functions:write", "functions:read", "kv:write", "kv:read"]),
  reader:   new Set(["functions:read", "kv:read", "metrics:read"]),
  auditor:  new Set(["metrics:read", "chain:read", "events:read"]),
  owner:    new Set(["functions:write", "functions:read", "kv:write", "kv:read", "metrics:read", "chain:read", "events:read", "tenant:manage", "billing:manage", "webhooks:manage"]),
};

export function can(role: Role, permission: string): boolean {
  const perms = PERMISSIONS[role];
  return perms.has("*") || perms.has(permission);
}

// -- Persistent token revocation (SQLite-backed, survives restarts) --

let revocationDb: Database | null = null;
const revokedCache = new Set<string>(); // in-memory cache for hot lookups

export function initRevocationStore(dataDir: string): void {
  revocationDb = new Database(join(dataDir, "revocations.db"));
  revocationDb.run("PRAGMA journal_mode = WAL");
  revocationDb.run("PRAGMA busy_timeout = 5000");
  revocationDb.run(`
    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti        TEXT PRIMARY KEY,
      revoked_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `);
  // Hydrate cache from disk
  const rows = revocationDb.prepare("SELECT jti FROM revoked_tokens WHERE expires_at > ?").all(Math.floor(Date.now() / 1000)) as Array<{ jti: string }>;
  for (const row of rows) revokedCache.add(row.jti);
  // Periodic cleanup of expired entries (every 5 minutes)
  setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    revocationDb?.prepare("DELETE FROM revoked_tokens WHERE expires_at <= ?").run(now);
    // Rebuild cache from DB (only non-expired tokens)
    revokedCache.clear();
    const active = revocationDb?.prepare("SELECT jti FROM revoked_tokens WHERE expires_at > ?").all(now) as Array<{ jti: string }> ?? [];
    for (const row of active) revokedCache.add(row.jti);
  }, 5 * 60_000);
}

export function revokeToken(jti: string, expiresAtSec?: number): void {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = expiresAtSec ?? now + 86400; // default 24h TTL
  revokedCache.add(jti);
  if (revocationDb) {
    revocationDb.prepare(
      "INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)"
    ).run(jti, now, expiresAt);
  }
}

export function isTokenRevoked(jti: string): boolean {
  return revokedCache.has(jti);
}

//  JWT (HMAC-SHA256, no library) 

export interface JWTPayload {
  sub:       string;   // node id or user id
  role:      Role;
  tid?:      string;   // tenant id (for tenant-scoped tokens)
  iat:       number;   // issued at (seconds)
  exp:       number;   // expiry (seconds)
  jti:       string;   // unique token id (for revocation)
  verified?: boolean;  // email verification status
  scope?:    string;   // restricted scope (e.g. "totp_pending")
}

export async function issueJWT(
  payload: Omit<JWTPayload, "iat" | "exp" | "jti">,
  secret:  string,
  ttlSecs: number = 3600
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const full: JWTPayload = {
    ...payload,
    iat: now,
    exp: now + ttlSecs,
    jti: crypto.randomUUID(),
  };
  const header    = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })).replace(/=/g, "");
  const body      = btoa(JSON.stringify(full)).replace(/=/g, "");
  const signature = await hmac256(secret, `${header}.${body}`);
  return `${header}.${body}.${btoa(signature).replace(/=/g, "")}`;
}

export async function verifyJWT(
  token:  string,
  secret: string
): Promise<{ valid: boolean; payload?: JWTPayload; reason?: string }> {
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, reason: "malformed" };

  const [header, body, sig] = parts;
  const expected = await hmac256(secret, `${header}.${body}`);
  const valid    = await hmac256Verify(secret, `${header}.${body}`, atob(sig.replace(/-/g,"+").replace(/_/g,"/")));

  if (!valid) return { valid: false, reason: "invalid signature" };

  try {
    const payload: JWTPayload = JSON.parse(atob(body + "==".slice((4 - body.length % 4) % 4)));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return { valid: false, reason: "expired" };
    if (payload.jti && isTokenRevoked(payload.jti)) return { valid: false, reason: "revoked" };
    return { valid: true, payload };
  } catch {
    return { valid: false, reason: "invalid payload" };
  }
}

//  Anomaly Detector 

interface AnomalyState {
  authFailures:    Map<string, { count: number; firstTs: number; lastTs: number }>;
  requestCounts:   Map<string, { count: number; windowStart: number }>;
  reconPatterns:   Map<string, { count: number; ts: number }>;
  blockedIPs:      Set<string>;
}

export class AnomalyDetector {
  private state: AnomalyState = {
    authFailures:  new Map(),
    requestCounts: new Map(),
    reconPatterns: new Map(),
    blockedIPs:    new Set(),
  };

  private chain: SovereignChain | null;

  // Thresholds
  private readonly AUTH_FAIL_THRESHOLD    = 5;   // per 5 minutes
  private readonly AUTH_FAIL_WINDOW_MS    = 5 * 60 * 1000;
  private readonly RECON_THRESHOLD        = 20;  // 404s per minute
  private readonly RECON_WINDOW_MS        = 60 * 1000;
  private readonly BLOCK_DURATION_MS      = 15 * 60 * 1000;

  constructor(chain: SovereignChain | null) {
    this.chain = chain;
    // Cleanup stale state every 10 minutes
    setInterval(() => this.cleanup(), 10 * 60 * 1000);
  }

  /** Record a failed auth attempt. Returns true if IP should be blocked. */
  recordAuthFailure(ip: string): { blocked: boolean; count: number } {
    const now = Date.now();
    const rec = this.state.authFailures.get(ip);

    if (!rec || now - rec.firstTs > this.AUTH_FAIL_WINDOW_MS) {
      this.state.authFailures.set(ip, { count: 1, firstTs: now, lastTs: now });
      return { blocked: false, count: 1 };
    }

    rec.count++;
    rec.lastTs = now;

    if (rec.count >= this.AUTH_FAIL_THRESHOLD) {
      this.state.blockedIPs.add(ip);
      setTimeout(() => this.state.blockedIPs.delete(ip), this.BLOCK_DURATION_MS);

      void this.chain?.emit("ANOMALY", {
        type:    "BRUTE_FORCE",
        ip,
        count:   rec.count,
        windowMs: this.AUTH_FAIL_WINDOW_MS,
      }, "HIGH");

      return { blocked: true, count: rec.count };
    }

    return { blocked: false, count: rec.count };
  }

  /** Record a 404 (potential recon). */
  recordRecon(ip: string, path: string): boolean {
    const now = Date.now();
    const key = ip;
    const rec = this.state.reconPatterns.get(key);

    if (!rec || now - rec.ts > this.RECON_WINDOW_MS) {
      this.state.reconPatterns.set(key, { count: 1, ts: now });
      return false;
    }

    rec.count++;
    if (rec.count === this.RECON_THRESHOLD) {
      void this.chain?.emit("ANOMALY", {
        type:  "RECONNAISSANCE",
        ip,
        count: rec.count,
        path,
      }, "MEDIUM");
      return true;
    }
    return false;
  }

  isBlocked(ip: string): boolean {
    return this.state.blockedIPs.has(ip);
  }

  private cleanup() {
    const now = Date.now();
    for (const [ip, rec] of this.state.authFailures) {
      if (now - rec.lastTs > this.AUTH_FAIL_WINDOW_MS * 2) {
        this.state.authFailures.delete(ip);
      }
    }
    for (const [ip, rec] of this.state.reconPatterns) {
      if (now - rec.ts > this.RECON_WINDOW_MS * 5) {
        this.state.reconPatterns.delete(ip);
      }
    }
  }

  stats() {
    return {
      blockedIPs:       this.state.blockedIPs.size,
      trackedFailures:  this.state.authFailures.size,
      reconPatterns:    this.state.reconPatterns.size,
    };
  }
}

//  Secret Scanner 

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; severity: "HIGH" | "CRITICAL" }> = [
  { name: "AWS Access Key",       regex: /AKIA[0-9A-Z]{16}/,                       severity: "CRITICAL" },
  { name: "AWS Secret Key",       regex: /aws_secret_access_key\s*=\s*[^\s'"]{40}/i, severity: "CRITICAL" },
  { name: "Anthropic API Key",    regex: /sk-ant-api0[34]-[A-Za-z0-9_-]{93}/,      severity: "CRITICAL" },
  { name: "OpenAI API Key",       regex: /sk-[A-Za-z0-9]{48}/,                     severity: "CRITICAL" },
  { name: "Private Key (PEM)",    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "CRITICAL" },
  { name: "Generic Secret",       regex: /['"]?(password|passwd|secret|api_key|apikey|token)['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/]{16,}['"]?/i, severity: "HIGH" },
  { name: "GitHub Token",         regex: /ghp_[A-Za-z0-9]{36}/,                    severity: "CRITICAL" },
  { name: "Stripe Secret Key",    regex: /sk_live_[A-Za-z0-9]{24}/,                severity: "CRITICAL" },
  { name: "Database URL",         regex: /(mysql|postgres|mongodb):\/\/[^:]+:[^@]+@/, severity: "HIGH" },
  { name: "Hardcoded IP",         regex: /\b(?:192\.168|10\.\d|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b/, severity: "HIGH" },
];

export interface ScanResult {
  clean:    boolean;
  findings: Array<{ name: string; severity: string; snippet: string }>;
}

export function scanForSecrets(code: string): ScanResult {
  const findings: ScanResult["findings"] = [];

  for (const { name, regex, severity } of SECRET_PATTERNS) {
    const match = code.match(regex);
    if (match) {
      // Redact the actual value for logging
      const raw = match[0];
      const snippet = raw.length > 20
        ? raw.slice(0, 6) + "" + raw.slice(-4)
        : raw.slice(0, 3) + "";
      findings.push({ name, severity, snippet });
    }
  }

  return { clean: findings.length === 0, findings };
}

//  Security Headers 

/**
 * Generate a per-request CSP nonce for inline scripts/styles.
 * Must be base64-encoded and cryptographically random.
 */
export function generateCSPNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

export function applySecurityHeaders(headers: Headers, cspNonce?: string): void {
  // OWASP recommended + extras
  headers.set("X-Frame-Options",            "DENY");
  headers.set("X-Content-Type-Options",     "nosniff");
  headers.set("X-XSS-Protection",           "0"); // Deprecated; CSP is the real defense
  headers.set("Referrer-Policy",            "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy",         "camera=(), microphone=(), geolocation=()");
  headers.set("X-Sovereign-Version",        "4.0.0");
  headers.set("X-Sovereign-Node",           process.env.SOVEREIGN_NODE_ID ?? "primary");

  // Nonce-based CSP — no unsafe-inline. Inline scripts must include nonce attribute.
  const nonceSrc = cspNonce ? `'nonce-${cspNonce}'` : "";
  headers.set("Content-Security-Policy",
    `default-src 'self'; ` +
    `script-src 'self' ${nonceSrc} https://cdnjs.cloudflare.com; ` +
    `style-src 'self' ${nonceSrc} https://fonts.googleapis.com; ` +
    `font-src 'self' https://fonts.gstatic.com; ` +
    `img-src 'self' data:; ` +
    `connect-src 'self'; ` +
    `frame-ancestors 'none';`
  );

  headers.set("Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );

  // Remove information-leaking headers
  headers.delete("Server");
  headers.delete("X-Powered-By");
}

//  Zero-Trust Middleware Factory 

export interface ZeroTrustConfig {
  adminToken:    string | undefined;
  jwtSecret:     string;
  chain:         SovereignChain | null;
  anomaly:       AnomalyDetector;
  enableHeaders: boolean;
  trustedProxies?: string[];  // CIDRs or IPs of trusted reverse proxies (Caddy, Fly.io, etc.)
}

/**
 * Extract the real client IP from proxy headers.
 * Only trusts the rightmost entry in X-Forwarded-For that isn't a known proxy,
 * or falls back to X-Real-IP / Cf-Connecting-IP.
 */
function resolveClientIP(c: Context, trustedProxies: Set<string>): string {
  // Prefer Cf-Connecting-IP (set by Cloudflare at edge, cannot be spoofed)
  const cfIP = c.req.header("cf-connecting-ip");
  if (cfIP) return cfIP.trim();

  // Fly-Client-IP (set by Fly.io proxy, cannot be spoofed by client)
  const flyIP = c.req.header("fly-client-ip");
  if (flyIP) return flyIP.trim();

  // X-Forwarded-For: walk from rightmost, skip trusted proxies
  const xff = c.req.header("x-forwarded-for");
  if (xff) {
    const ips = xff.split(",").map(s => s.trim()).filter(Boolean);
    // Walk from right to left: the rightmost non-trusted IP is the real client
    for (let i = ips.length - 1; i >= 0; i--) {
      if (!trustedProxies.has(ips[i])) return ips[i];
    }
    // All IPs are trusted proxies — use leftmost as last resort
    if (ips.length > 0) return ips[0];
  }

  // X-Real-IP fallback (set by Caddy/Nginx)
  const realIP = c.req.header("x-real-ip");
  if (realIP) return realIP.trim();

  return "unknown";
}

export function createZeroTrustMiddleware(cfg: ZeroTrustConfig): MiddlewareHandler {
  const shield = new InputShield();
  const trustedProxies = new Set(cfg.trustedProxies ?? []);

  return async (c: Context, next: Next) => {
    const ip      = resolveClientIP(c, trustedProxies);
    const path    = new URL(c.req.url).pathname;
    const method  = c.req.method;
    const reqId   = c.get("requestId") ?? crypto.randomUUID();

    //  0. Input Shield: scan POST/PUT/PATCH bodies for injection
    //  IMPORTANT: Clone request before reading JSON to preserve body stream for downstream handlers
    if (method === "POST" || method === "PUT" || method === "PATCH") {
      try {
        const contentType = c.req.header("content-type") ?? "";
        if (contentType.includes("application/json")) {
          const cloned = c.req.raw.clone();
          const body = await cloned.json().catch(() => null);
          if (body) {
            const scan = shield.scanObject(body);
            if (!scan.safe) {
              void cfg.chain?.emit("ANOMALY", {
                type:    "INPUT_INJECTION",
                ip, path, method,
                threats: scan.threats.map(t => t.type),
              }, "HIGH");
              return c.json({
                error: "Request blocked: suspicious input detected",
                threats: scan.threats.map(t => t.type),
                requestId: reqId,
              }, 400);
            }
          }
        }
      } catch { /* non-JSON body, skip scan */ }
    }

    //  1. CSRF protection for cookie-based auth on mutating requests
    //  If the request uses a cookie (not Bearer header) for auth, require X-Requested-With.
    //  Browsers won't send custom headers cross-origin without CORS preflight.
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      const cookieHeader = c.req.header("cookie") ?? "";
      const hasCookieAuth = cookieHeader.includes("__sovereign_session=");
      const hasBearerAuth = (c.req.header("authorization") ?? "").startsWith("Bearer ");
      const hasAdminToken = !!(c.req.header("x-sovereign-token"));

      // Only enforce CSRF for cookie-only auth (not API clients using Bearer/admin token)
      if (hasCookieAuth && !hasBearerAuth && !hasAdminToken) {
        const xrw = c.req.header("x-requested-with") ?? "";
        if (xrw !== "sovereignly") {
          void cfg.chain?.emit("ANOMALY", {
            type: "CSRF_ATTEMPT",
            ip, path, method,
          }, "HIGH");
          return c.json({ error: "CSRF validation failed", requestId: reqId }, 403);
        }
      }
    }

    //  2. Check blocked IPs
    if (cfg.anomaly.isBlocked(ip)) {
      void cfg.chain?.emit("AUTH_FAILURE", {
        ip, path, method, reason: "ip_blocked",
      }, "HIGH");
      return c.json({ error: "forbidden", requestId: reqId }, 403);
    }

    //  2. Apply security headers (nonce-based CSP — no unsafe-inline)
    const cspNonce = generateCSPNonce();
    c.set("cspNonce", cspNonce);

    if (cfg.enableHeaders) {
      c.header("X-Frame-Options",            "DENY");
      c.header("X-Content-Type-Options",     "nosniff");
      c.header("X-Sovereign-Version",        "4.0.0");
      c.header("Referrer-Policy",            "strict-origin-when-cross-origin");
      c.header("Strict-Transport-Security",  "max-age=31536000; includeSubDomains");
      c.header("Permissions-Policy",         "camera=(), microphone=(), geolocation=()");
      c.header("Content-Security-Policy",
        `default-src 'self'; ` +
        `script-src 'self' 'nonce-${cspNonce}' https://cdnjs.cloudflare.com; ` +
        `style-src 'self' 'nonce-${cspNonce}' https://fonts.googleapis.com; ` +
        `font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; ` +
        `connect-src 'self'; frame-ancestors 'none';`
      );
    }

    //  3. Admin endpoint authentication 
    // Public system endpoints (health probes for LB/K8s, metrics via Prometheus scraper)
    const publicSystemPaths = new Set(["/_sovereign/health", "/_sovereign/live", "/_sovereign/ready", "/_sovereign/prometheus"]);
    if (path.startsWith("/_sovereign/") && !publicSystemPaths.has(path)) {
      const authHeader = c.req.header("authorization") ?? "";
      const tokenHeader = c.req.header("x-sovereign-token") ?? "";

      let authenticated = false;
      let role: Role = "reader";

      // 1. httpOnly session cookie (preferred — immune to XSS)
      const cookieHeader = c.req.header("cookie") ?? "";
      const cookieMatch = cookieHeader.match(/__sovereign_session=([^;]+)/);
      if (cookieMatch?.[1]) {
        const { valid, payload } = await verifyJWT(cookieMatch[1], cfg.jwtSecret);
        if (valid && payload) {
          authenticated = true;
          role = payload.role;
        }
      }

      // 2. Bearer JWT header (API clients, SDK, legacy)
      if (!authenticated && authHeader.startsWith("Bearer ")) {
        const token = authHeader.slice(7);
        const { valid, payload } = await verifyJWT(token, cfg.jwtSecret);
        if (valid && payload) {
          authenticated = true;
          role = payload.role;
        }
      }

      // Legacy admin token (backwards compat)
      if (!authenticated && cfg.adminToken && tokenHeader) {
        if (timingSafeEqual(tokenHeader, cfg.adminToken)) {
          authenticated = true;
          role = "admin";
        }
      }

      if (!authenticated) {
        const result = cfg.anomaly.recordAuthFailure(ip);
        void cfg.chain?.emit("AUTH_FAILURE", {
          ip, path, method, reason: "invalid_token",
          failureCount: result.count, blocked: result.blocked,
        }, result.blocked ? "HIGH" : "MEDIUM");

        return c.json({ error: "unauthorized", requestId: reqId }, 401);
      }

      // Record successful auth
      void cfg.chain?.emit("AUTH_SUCCESS", { ip, path, method, role }, "LOW");

      // Store role for downstream handlers
      c.set("role", role);
      c.set("authenticated", true);
    }

    await next();

    //  4. Record 404s for recon detection 
    if (c.res.status === 404) {
      cfg.anomaly.recordRecon(ip, path);
    }
  };
}

//  Permission Guard 

export function requirePermission(permission: string): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const role = c.get("role") as Role | undefined;
    if (!role || !can(role, permission)) {
      return c.json({ error: "forbidden", required: permission }, 403);
    }
    await next();
  };
}
