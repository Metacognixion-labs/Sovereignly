import { timingSafeEqual } from "../security/crypto.ts";
/**
 * Sovereignly v3  Auth Routes
 *
 * Full auth surface  zero external identity providers:
 *
 * PASSKEYS (primary  WebAuthn / FIDO2)
 *   GET  /_sovereign/auth/passkeys/register/begin    Start passkey registration
 *   POST /_sovereign/auth/passkeys/register/complete Finish registration  store credential
 *   GET  /_sovereign/auth/passkeys/login/begin       Start passkey login
 *   POST /_sovereign/auth/passkeys/login/complete    Finish login  issue Sovereign JWT
 *
 * OAUTH (Google / GitHub / Discord / Meta)
 *   GET  /_sovereign/auth/oauth/:provider/start      Redirect to provider
 *   GET  /_sovereign/auth/oauth/:provider/callback   Handle code  issue JWT
 *
 * WALLETS
 *   GET  /_sovereign/auth/siwe/nonce                 EVM wallet nonce
 *   POST /_sovereign/auth/siwe/verify                EIP-4361 signature  issue JWT
 *   GET  /_sovereign/auth/solana/nonce               Solana wallet nonce
 *   POST /_sovereign/auth/solana/verify              Ed25519 signature  issue JWT
 *
 * SESSION
 *   GET  /_sovereign/auth/me                         Current user profile
 *   POST /_sovereign/auth/refresh                    Extend session
 *   POST /_sovereign/auth/logout                     Invalidate + chain event
 *
 * USERS (admin)
 *   GET  /_sovereign/auth/users                      List all users
 *   PATCH /_sovereign/auth/users/:id                 Update role / plan
 *   GET  /_sovereign/auth/stats                      Auth statistics
 */

import type { Hono }            from "hono";
import { Database }             from "bun:sqlite";
import { join }                 from "node:path";
import { PasskeyEngine }        from "../auth/passkeys.ts";
import { OAuthBroker }          from "../auth/oauth.ts";
import type { OAuthProvider }   from "../auth/oauth.ts";
import { generateNonce, verifySIWE } from "../auth/siwe.ts";
import { generateSolanaNonce, verifySolanaSignature } from "../auth/solana.ts";
import { issueJWT, verifyJWT, revokeToken }  from "../security/zero-trust.ts";
import type { SovereignChain }  from "../security/chain.ts";

//  User store 


function escapeHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}

export type UserRole = "reader" | "deployer" | "admin";
export type UserPlan = "free" | "starter" | "growth" | "enterprise";

export interface SovereignUser {
  id:            string;
  email?:        string;
  displayName:   string;
  role:          UserRole;
  plan:          UserPlan;
  authMethods:   string[];
  evmAddress?:   string;
  solanaAddress?:string;
  avatarUrl?:    string;
  createdAt:     number;
  lastSeenAt:    number;
}

class UserStore {
  private db: Database;

  constructor(dataDir: string) {
    this.db = new Database(join(dataDir, "users.db"));
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id              TEXT PRIMARY KEY,
        email           TEXT,
        display_name    TEXT NOT NULL,
        role            TEXT NOT NULL DEFAULT 'deployer',
        plan            TEXT NOT NULL DEFAULT 'free',
        auth_methods    TEXT NOT NULL DEFAULT '[]',
        evm_address     TEXT,
        solana_address  TEXT,
        avatar_url      TEXT,
        created_at      INTEGER NOT NULL,
        last_seen_at    INTEGER NOT NULL
      )
    `);
    this.db.run("CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_users_evm    ON users(evm_address)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_users_solana ON users(solana_address)");
  }

  upsertFromOAuth(profile: {
    sub: string; provider: string; email?: string;
    name?: string; username?: string; avatarUrl?: string;
  }): SovereignUser {
    const id  = `usr_${profile.provider}_${profile.sub.replace(/\W/g,"").slice(0,20)}`;
    const now = Date.now();
    const existing = this.get(id);
    if (existing) {
      this.db.prepare(
        "UPDATE users SET last_seen_at=?, email=COALESCE(?,email), avatar_url=COALESCE(?,avatar_url) WHERE id=?"
      ).run(now, profile.email ?? null, profile.avatarUrl ?? null, id);
      return { ...existing, lastSeenAt: now };
    }
    const user: SovereignUser = {
      id, email: profile.email,
      displayName: profile.name ?? profile.username ?? profile.email ?? id,
      role: "deployer", plan: "free",
      authMethods: [profile.provider],
      avatarUrl: profile.avatarUrl,
      createdAt: now, lastSeenAt: now,
    };
    this.db.prepare(`
      INSERT INTO users (id,email,display_name,role,plan,auth_methods,avatar_url,created_at,last_seen_at)
      VALUES (?,?,?,?,?,?,?,?,?)
    `).run(id, user.email??null, user.displayName, user.role, user.plan,
           JSON.stringify(user.authMethods), user.avatarUrl??null, now, now);
    return user;
  }

  upsertFromPasskey(credentialId: string, userId?: string): SovereignUser {
    const id  = userId ?? `usr_pk_${credentialId.replace(/[^a-zA-Z0-9]/g,"").slice(0,16)}`;
    const now = Date.now();
    const existing = this.get(id);
    if (existing) {
      this.db.prepare("UPDATE users SET last_seen_at=? WHERE id=?").run(now, id);
      return { ...existing, lastSeenAt: now };
    }
    const user: SovereignUser = {
      id, displayName: "Passkey User",
      role: "deployer", plan: "free", authMethods: ["passkey"],
      createdAt: now, lastSeenAt: now,
    };
    this.db.prepare(`
      INSERT INTO users (id,display_name,role,plan,auth_methods,created_at,last_seen_at)
      VALUES (?,?,?,?,?,?,?)
    `).run(id, user.displayName, user.role, user.plan,
           JSON.stringify(user.authMethods), now, now);
    return user;
  }

  upsertFromWallet(address: string, chain: "evm" | "solana"): SovereignUser {
    const col     = chain === "evm" ? "evm_address" : "solana_address";
    const id      = `usr_${chain}_${address.slice(2,10).toLowerCase()}`;
    const now     = Date.now();
    const existing = this.db.prepare(`SELECT * FROM users WHERE ${col}=?`).get(address) as any;
    if (existing) {
      this.db.prepare("UPDATE users SET last_seen_at=? WHERE id=?").run(now, existing.id);
      return this.row(existing);
    }
    const label   = chain === "evm"
      ? address.slice(0,6) + "" + address.slice(-4)
      : address.slice(0,8) + "";
    const user: SovereignUser = {
      id, displayName: label, role: "deployer", plan: "free",
      authMethods: [chain === "evm" ? "siwe" : "solana"],
      evmAddress:    chain === "evm"    ? address : undefined,
      solanaAddress: chain === "solana" ? address : undefined,
      createdAt: now, lastSeenAt: now,
    };
    this.db.prepare(`
      INSERT INTO users (id,display_name,role,plan,auth_methods,${col},created_at,last_seen_at)
      VALUES (?,?,?,?,?,?,?,?)
    `).run(id, user.displayName, user.role, user.plan,
           JSON.stringify(user.authMethods), address, now, now);
    return user;
  }

  get(id: string): SovereignUser | null {
    const r = this.db.prepare("SELECT * FROM users WHERE id=?").get(id) as any;
    return r ? this.row(r) : null;
  }

  list(opts: { limit?: number; offset?: number } = {}): SovereignUser[] {
    return (this.db.prepare(
      "SELECT * FROM users ORDER BY last_seen_at DESC LIMIT ? OFFSET ?"
    ).all(opts.limit ?? 100, opts.offset ?? 0) as any[]).map(r => this.row(r));
  }

  updateRole(id: string, role: UserRole) { this.db.prepare("UPDATE users SET role=? WHERE id=?").run(role,id); }
  updatePlan(id: string, plan: UserPlan) { this.db.prepare("UPDATE users SET plan=? WHERE id=?").run(plan,id); }

  stats() {
    const total = (this.db.prepare("SELECT COUNT(*) AS n FROM users").get() as any).n;
    const byRole = Object.fromEntries(
      (this.db.prepare("SELECT role,COUNT(*) AS n FROM users GROUP BY role").all() as any[])
        .map(r => [r.role, r.n])
    );
    return { total, byRole };
  }

  private row(r: any): SovereignUser {
    return {
      id:r.id, email:r.email, displayName:r.display_name,
      role:r.role, plan:r.plan, authMethods:(() => { try { return JSON.parse(r.auth_methods??"[]"); } catch { return []; } })(),
      evmAddress:r.evm_address, solanaAddress:r.solana_address,
      avatarUrl:r.avatar_url, createdAt:r.created_at, lastSeenAt:r.last_seen_at,
    };
  }

  close() { this.db.close(); }
}

//  Register all auth routes 

export function registerAuthRoutes(
  app:      Hono,
  passkeys: PasskeyEngine,
  oauth:    OAuthBroker,
  chain:    SovereignChain,
  cfg: { jwtSecret: string; adminToken?: string; appUrl: string; dataDir?: string }
) {
  const dataDir = cfg.dataDir ?? "./data/platform";
  const users   = new UserStore(dataDir);
  const rpId    = new URL(cfg.appUrl).hostname;
  const clientIP = (c: any) =>
    c.req.header("x-real-ip") ?? c.req.header("x-forwarded-for")?.split(",")[0] ?? "unknown";

  const checkAdmin = async (c: any): Promise<boolean> => {
    if (cfg.adminToken && timingSafeEqual(c.req.header("x-sovereign-token") ?? "", cfg.adminToken)) return true;
    const b = c.req.header("authorization")?.slice(7);
    if (!b) return false;
    const { valid, payload } = await verifyJWT(b, cfg.jwtSecret);
    return valid && payload?.role === "admin";
  };

  //  PASSKEYS  REGISTER BEGIN 
  app.get("/_sovereign/auth/passkeys/register/begin", async (c) => {
    const { userId, userName, displayName } = c.req.query();
    if (!userName) return c.json({ error: "userName required" }, 400);
    const uid  = userId ?? `usr_pk_${crypto.randomUUID().replace(/-/g,"").slice(0,16)}`;
    const opts = passkeys.beginRegistration({ userId:uid, userName, displayName:displayName??userName });
    return c.json({ ...opts, _userId: uid });
  });

  //  PASSKEYS  REGISTER COMPLETE 
  app.post("/_sovereign/auth/passkeys/register/complete", async (c) => {
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    const r = await passkeys.completeRegistration(body);
    if (!r.ok) return c.json({ error: r.reason }, 400);
    const user  = users.upsertFromPasskey(r.credentialId!, body._userId);
    const token = await issueJWT({ sub: user.id, role: user.role }, cfg.jwtSecret);
    void chain.emit("AUTH_SUCCESS", { userId:user.id, method:"passkey_register", ip:clientIP(c) }, "LOW");
    return c.json({ token, user, credentialId: r.credentialId }, 201);
  });

  //  PASSKEYS  LOGIN BEGIN 
  app.get("/_sovereign/auth/passkeys/login/begin", async (c) => {
    const { userId } = c.req.query();
    let credIds: string[] | undefined;
    if (userId) credIds = passkeys.getCredentialsForUser(userId).map(c => c.id);
    return c.json(passkeys.beginAuthentication({ userId, credentialIds: credIds }));
  });

  //  PASSKEYS  LOGIN COMPLETE 
  app.post("/_sovereign/auth/passkeys/login/complete", async (c) => {
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    const r = await passkeys.completeAuthentication(body);
    if (!r.ok) {
      void chain.emit("AUTH_FAILURE", { method:"passkey", reason:r.reason, ip:clientIP(c) }, "MEDIUM");
      return c.json({ error: r.reason }, 401);
    }
    const user  = users.upsertFromPasskey(r.credentialId!, r.userId);
    const token = await issueJWT({ sub: user.id, role: user.role }, cfg.jwtSecret);
    void chain.emit("AUTH_SUCCESS", { userId:user.id, method:"passkey", ip:clientIP(c) }, "LOW");
    return c.json({ token, user });
  });

  //  OAUTH  START 
  app.get("/_sovereign/auth/oauth/:provider/start", async (c) => {
    const provider = c.req.param("provider") as OAuthProvider;
    try {
      const { url } = await oauth.getAuthorizationUrl(provider, c.req.query("redirect") ?? "/");
      return c.redirect(url);
    } catch (e: any) { return c.json({ error: e.message }, 400); }
  });

  //  OAUTH  CALLBACK 
  app.get("/_sovereign/auth/oauth/:provider/callback", async (c) => {
    const provider = c.req.param("provider") as OAuthProvider;
    const { code, state, error } = c.req.query();
    if (error) {
      void chain.emit("AUTH_FAILURE", { method:`oauth_${provider}`, reason:error, ip:clientIP(c) }, "MEDIUM");
      return c.redirect(`${cfg.appUrl}/_sovereign/auth?error=${encodeURIComponent(error)}`);
    }
    if (!code || !state) return c.json({ error: "code and state required" }, 400);
    try {
      const { profile, redirectTo } = await oauth.handleCallback(provider, code, state);
      const user  = users.upsertFromOAuth(profile);
      const token = await issueJWT({ sub: user.id, role: user.role }, cfg.jwtSecret);
      void chain.emit("AUTH_SUCCESS", { userId:user.id, method:`oauth_${provider}`, ip:clientIP(c) }, "LOW");
      return c.redirect(`${cfg.appUrl}${redirectTo}#sovereign_token=${token}`);
    } catch (e: any) {
      void chain.emit("AUTH_FAILURE", { method:`oauth_${provider}`, reason:e.message, ip:clientIP(c) }, "MEDIUM");
      return c.redirect(`${cfg.appUrl}/_sovereign/auth?error=${encodeURIComponent(e.message)}`);
    }
  });

  //  SIWE  NONCE 
  app.get("/_sovereign/auth/siwe/nonce", (c) => c.json({ nonce: generateNonce() }));

  //  SIWE  VERIFY 
  app.post("/_sovereign/auth/siwe/verify", async (c) => {
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    if (!body.message || !body.signature) return c.json({ error: "message and signature required" }, 400);
    const r = await verifySIWE({ message: body.message, signature: body.signature });
    if (!r.valid) {
      void chain.emit("AUTH_FAILURE", { method:"siwe", reason:r.reason, ip:clientIP(c) }, "MEDIUM");
      return c.json({ error: r.reason }, 401);
    }
    const user  = users.upsertFromWallet(r.address!, "evm");
    const token = await issueJWT({ sub: user.id, role: user.role }, cfg.jwtSecret);
    void chain.emit("AUTH_SUCCESS", { userId:user.id, method:"siwe", evmAddress:r.address, ip:clientIP(c) }, "LOW");
    return c.json({ token, user, address: r.address });
  });

  //  SOLANA  NONCE 
  app.get("/_sovereign/auth/solana/nonce", (c) => c.json({ nonce: generateSolanaNonce() }));

  //  SOLANA  VERIFY 
  app.post("/_sovereign/auth/solana/verify", async (c) => {
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    if (!body.message || !body.signature || !body.publicKey) {
      return c.json({ error: "message, signature, and publicKey required" }, 400);
    }
    const r = await verifySolanaSignature({ message:body.message, signature:body.signature, publicKey:body.publicKey });
    if (!r.valid) {
      void chain.emit("AUTH_FAILURE", { method:"solana", reason:r.reason, ip:clientIP(c) }, "MEDIUM");
      return c.json({ error: r.reason }, 401);
    }
    const user  = users.upsertFromWallet(body.publicKey, "solana");
    const token = await issueJWT({ sub: user.id, role: user.role }, cfg.jwtSecret);
    void chain.emit("AUTH_SUCCESS", { userId:user.id, method:"solana", solanaAddress:body.publicKey, ip:clientIP(c) }, "LOW");
    return c.json({ token, user, address: body.publicKey });
  });

  //  ME 
  app.get("/_sovereign/auth/me", async (c) => {
    const b = c.req.header("authorization")?.slice(7);
    if (!b) return c.json({ error: "Bearer token required" }, 401);
    const { valid, payload } = await verifyJWT(b, cfg.jwtSecret);
    if (!valid || !payload) return c.json({ error: "invalid token" }, 401);
    const user = users.get(payload.sub);
    return user ? c.json({ user, exp: payload.exp }) : c.json({ error: "not found" }, 404);
  });

  //  REFRESH 
  app.post("/_sovereign/auth/refresh", async (c) => {
    const b = c.req.header("authorization")?.slice(7);
    if (!b) return c.json({ error: "Bearer token required" }, 401);
    const { valid, payload } = await verifyJWT(b, cfg.jwtSecret);
    if (!valid || !payload) return c.json({ error: "invalid token" }, 401);
    const user = users.get(payload.sub);
    if (!user) return c.json({ error: "user not found" }, 404);
    const token = await issueJWT({ sub: user.id, role: user.role }, cfg.jwtSecret);
    return c.json({ token, user });
  });

  //  LOGOUT 
  app.post("/_sovereign/auth/logout", async (c) => {
    const b = c.req.header("authorization")?.slice(7);
    if (b) {
      const { valid, payload } = await verifyJWT(b, cfg.jwtSecret);
      if (valid && payload) void chain.emit("SESSION_END", { userId:payload.sub, ip:clientIP(c) }, "LOW");
    }
    return c.json({ ok: true });
  });

  //  USERS  LIST (admin) 
  app.get("/_sovereign/auth/users", async (c) => {
    if (!await checkAdmin(c)) return c.json({ error: "admin required" }, 403);
    const { limit, offset } = c.req.query();
    return c.json(users.list({ limit:parseInt(limit??"100"), offset:parseInt(offset??"0") }));
  });

  //  USERS  UPDATE (admin) 
  app.patch("/_sovereign/auth/users/:id", async (c) => {
    if (!await checkAdmin(c)) return c.json({ error: "admin required" }, 403);
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    const uid = c.req.param("id");
    if (body.role) users.updateRole(uid, body.role);
    if (body.plan) users.updatePlan(uid, body.plan);
    void chain.emit("PERMISSION_CHANGE", { targetUserId:uid, role:body.role, plan:body.plan }, "MEDIUM");
    const user = users.get(uid);
    return user ? c.json({ user }) : c.json({ error: "not found" }, 404);
  });

  //  AUTH STATS (admin) 
  app.get("/_sovereign/auth/stats", async (c) => {
    if (!await checkAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(users.stats());
  });

  //  PORTAL PAGE 
  app.get("/_sovereign/auth", (c) => {
    const providers = oauth.getSupportedProviders();
    return c.html(`<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sovereignly  Sign In</title>
<script>
window.__SOVEREIGN_API__='';window.__PASSKEYS_RPID__='${escapeHtml(rpId)}';
window.__APP_URL__='${escapeHtml(cfg.appUrl)}';
window.__OAUTH_PROVIDERS__=${JSON.stringify(providers)};
</script></head>
<body style="margin:0;background:#000;color:#e8ecf4;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh">
<div style="text-align:center">
  <div style="font-size:40px;margin-bottom:8px"></div>
  <div style="font-size:13px;font-weight:700;letter-spacing:.1em;margin-bottom:4px">SOVEREIGNLY</div>
  <div style="font-size:10px;color:#4a5f78;font-family:monospace;margin-bottom:24px">sovereign auth  no external providers</div>
  <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
    ${providers.map(p=>`<a href="/_sovereign/auth/oauth/${p}/start" style="padding:7px 14px;background:#101215;border:1px solid #1e2330;border-radius:6px;color:#e8ecf4;text-decoration:none;font-size:11px;font-family:monospace">${p}</a>`).join("")}
  </div>
  <div style="margin-top:16px;font-size:10px;color:#2a3648;font-family:monospace">
    or use WebAuthn passkeys at /_sovereign/auth/passkeys/login/begin
  </div>
</div>
</body></html>`);
  });

  return { users };
}
