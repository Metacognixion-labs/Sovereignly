/**
 * Sovereignly Cloud — Token System API Routes
 * Business Source License 1.1 — MetaCognixion
 *
 * Admin endpoints for managing the token system visibility,
 * configuration, and operations. All actions are audit-logged.
 *
 * Routes:
 *   GET    /_sovereign/tokens/config         → Current config + feature gates
 *   PUT    /_sovereign/tokens/config         → Update config parameters
 *   GET    /_sovereign/tokens/status         → Current status
 *   PUT    /_sovereign/tokens/status         → Transition status (CLOSED↔PRE_PUBLIC↔PUBLIC)
 *   POST   /_sovereign/tokens/freeze        → Emergency freeze
 *   POST   /_sovereign/tokens/unfreeze      → Unfreeze
 *   GET    /_sovereign/tokens/supply         → Supply stats
 *   POST   /_sovereign/tokens/award         → Award tokens to user
 *   GET    /_sovereign/tokens/balance/:id    → User balance
 *   GET    /_sovereign/tokens/transactions   → Transaction history
 *   POST   /_sovereign/tokens/transfer      → User-to-user transfer
 *   POST   /_sovereign/tokens/withdraw      → Withdraw to wallet (PUBLIC only)
 *   POST   /_sovereign/tokens/stake         → Stake tokens
 *   POST   /_sovereign/tokens/unstake       → Unstake tokens
 */

import type { Hono }         from "hono";
import type { TokenManager } from "./manager.ts";
import { timingSafeEqual }   from "../../../oss/src/security/crypto.ts";
import { verifyJWT }         from "../../../oss/src/security/zero-trust.ts";
import type { TokenSystemStatus } from "./config.ts";

export function registerTokenRoutes(
  app:          Hono,
  tokenManager: TokenManager,
  cfg:          { adminToken?: string; jwtSecret: string },
) {
  const PREFIX = "/_sovereign/tokens";

  // ── Helper: require admin ────────────────────────────────────────────

  async function requireAdmin(c: any): Promise<{ ok: boolean; adminId: string; error?: Response }> {
    const authHeader  = c.req.header("authorization") ?? "";
    const tokenHeader = c.req.header("x-sovereign-token") ?? "";

    // JWT with admin/owner role
    if (authHeader.startsWith("Bearer ")) {
      const { valid, payload } = await verifyJWT(authHeader.slice(7), cfg.jwtSecret);
      if (valid && payload && (payload.role === "admin" || payload.role === "owner")) {
        return { ok: true, adminId: payload.sub };
      }
    }

    // Static admin token
    if (cfg.adminToken && timingSafeEqual(tokenHeader, cfg.adminToken)) {
      return { ok: true, adminId: "platform-admin" };
    }

    return { ok: false, adminId: "", error: c.json({ error: "Admin access required" }, 403) };
  }

  // ── Config ───────────────────────────────────────────────────────────

  app.get(`${PREFIX}/config`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    return c.json({
      config: tokenManager.getConfig(),
      gates:  tokenManager.getFeatureGates(),
    });
  });

  app.put(`${PREFIX}/config`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const updates = await c.req.json().catch(() => ({}));
    const config  = await tokenManager.updateConfig(updates, auth.adminId);

    return c.json({
      ok:     true,
      config,
      gates:  tokenManager.getFeatureGates(),
    });
  });

  // ── Status ───────────────────────────────────────────────────────────

  app.get(`${PREFIX}/status`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const config = tokenManager.getConfig();
    return c.json({
      status:    config.status,
      isFrozen:  config.isFrozen,
      gates:     tokenManager.getFeatureGates(),
      updatedAt: config.updatedAt,
      updatedBy: config.updatedBy,
    });
  });

  app.put(`${PREFIX}/status`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { status } = await c.req.json().catch(() => ({ status: "" })) as { status: TokenSystemStatus };
    if (!status) return c.json({ error: "status field required" }, 400);

    const result = await tokenManager.setStatus(status, auth.adminId);
    if (!result.ok) return c.json({ error: result.error, ...result }, 400);

    return c.json({
      ok:    true,
      ...result,
      gates: tokenManager.getFeatureGates(),
    });
  });

  // ── Freeze/Unfreeze ──────────────────────────────────────────────────

  app.post(`${PREFIX}/freeze`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { reason = "Emergency freeze" } = await c.req.json().catch(() => ({}));
    await tokenManager.setFrozen(true, auth.adminId, reason);

    return c.json({ ok: true, frozen: true, reason, gates: tokenManager.getFeatureGates() });
  });

  app.post(`${PREFIX}/unfreeze`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { reason = "Unfreezing" } = await c.req.json().catch(() => ({}));
    await tokenManager.setFrozen(false, auth.adminId, reason);

    return c.json({ ok: true, frozen: false, reason, gates: tokenManager.getFeatureGates() });
  });

  // ── Supply Stats ─────────────────────────────────────────────────────

  app.get(`${PREFIX}/supply`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    return c.json(tokenManager.getSupplyStats());
  });

  // ── Award ────────────────────────────────────────────────────────────

  app.post(`${PREFIX}/award`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { userId, amount, memo = "Admin award" } = await c.req.json().catch(() => ({}));
    if (!userId || !amount || amount <= 0) {
      return c.json({ error: "userId and positive amount required" }, 400);
    }

    try {
      const entry = await tokenManager.award(userId, amount, memo, auth.adminId);
      return c.json({ ok: true, entry, balance: tokenManager.getBalance(userId) });
    } catch (e: any) {
      return c.json({ error: e.message }, 400);
    }
  });

  // ── Balance ──────────────────────────────────────────────────────────

  app.get(`${PREFIX}/balance/:userId`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const userId = c.req.param("userId");
    return c.json(tokenManager.getBalance(userId));
  });

  // ── Transactions ─────────────────────────────────────────────────────

  app.get(`${PREFIX}/transactions`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { accountId, limit, offset, type } = c.req.query();
    if (!accountId) return c.json({ error: "accountId query param required" }, 400);

    const transactions = tokenManager.getTransactions(accountId, {
      limit:  limit ? parseInt(limit) : undefined,
      offset: offset ? parseInt(offset) : undefined,
      type:   type as any,
    });

    return c.json({ count: transactions.length, transactions });
  });

  // ── Transfer ─────────────────────────────────────────────────────────

  app.post(`${PREFIX}/transfer`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { fromUser, toUser, amount } = await c.req.json().catch(() => ({}));
    if (!fromUser || !toUser || !amount || amount <= 0) {
      return c.json({ error: "fromUser, toUser, and positive amount required" }, 400);
    }

    try {
      const result = await tokenManager.transfer(fromUser, toUser, amount);
      return c.json({
        ok: true,
        ...result,
        fromBalance: tokenManager.getBalance(fromUser),
        toBalance:   tokenManager.getBalance(toUser),
      });
    } catch (e: any) {
      return c.json({ error: e.message }, 400);
    }
  });

  // ── Withdraw ─────────────────────────────────────────────────────────

  app.post(`${PREFIX}/withdraw`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { userId, amount, walletAddress } = await c.req.json().catch(() => ({}));
    if (!userId || !amount || !walletAddress) {
      return c.json({ error: "userId, amount, and walletAddress required" }, 400);
    }

    try {
      const result = await tokenManager.withdraw(userId, amount, walletAddress);
      return c.json({
        ok: true,
        ...result,
        balance: tokenManager.getBalance(userId),
      });
    } catch (e: any) {
      return c.json({ error: e.message }, 400);
    }
  });

  // ── Stake/Unstake ────────────────────────────────────────────────────

  app.post(`${PREFIX}/stake`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { userId, amount } = await c.req.json().catch(() => ({}));
    if (!userId || !amount || amount <= 0) {
      return c.json({ error: "userId and positive amount required" }, 400);
    }

    try {
      const entry = await tokenManager.stake(userId, amount);
      return c.json({ ok: true, entry, balance: tokenManager.getBalance(userId) });
    } catch (e: any) {
      return c.json({ error: e.message }, 400);
    }
  });

  app.post(`${PREFIX}/unstake`, async (c) => {
    const auth = await requireAdmin(c);
    if (!auth.ok) return auth.error;

    const { userId, amount } = await c.req.json().catch(() => ({}));
    if (!userId || !amount || amount <= 0) {
      return c.json({ error: "userId and positive amount required" }, 400);
    }

    try {
      const entry = await tokenManager.unstake(userId, amount);
      return c.json({ ok: true, entry, balance: tokenManager.getBalance(userId) });
    } catch (e: any) {
      return c.json({ error: e.message }, 400);
    }
  });
}
