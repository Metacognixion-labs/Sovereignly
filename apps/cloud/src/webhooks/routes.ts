import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
/**
 * Sovereignly v4.0.0  Webhook Routes
 *
 * POST   /_sovereign/tenants/:id/webhooks           Register webhook
 * GET    /_sovereign/tenants/:id/webhooks           List webhooks
 * DELETE /_sovereign/tenants/:id/webhooks/:whId     Delete webhook
 * POST   /_sovereign/tenants/:id/webhooks/:whId/test  Test webhook delivery
 */

import type { Hono } from "hono";
import type { TenantManager } from "../tenants/manager.ts";
import type { WebhookManager } from "../webhooks/index.ts";
import type { SovereignChain } from "../../../oss/src/security/chain.ts";
import { verifyJWT } from "../zero-trust.ts";

export function registerWebhookRoutes(
  app:      Hono,
  tenants:  TenantManager,
  webhooks: WebhookManager,
  chain:    SovereignChain,
  opts:     { jwtSecret: string; adminToken?: string }
) {

  async function auth(c: any): Promise<{ userId: string; isAdmin: boolean } | null> {
    const header = c.req.header("authorization") ?? "";
    const xtoken = c.req.header("x-sovereign-token") ?? "";
    if (opts.adminToken && timingSafeEqual(xtoken, opts.adminToken)) return { userId: "admin", isAdmin: true };
    if (!header.startsWith("Bearer ")) return null;
    const { valid, payload } = await verifyJWT(header.slice(7), opts.jwtSecret);
    if (!valid || !payload) return null;
    return { userId: payload.sub, isAdmin: payload.role === "admin" };
  }

  //  Register webhook 
  app.post("/_sovereign/tenants/:id/webhooks", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "tenant not found" }, 404);

    const meta = tenants.getTenantMeta(tenantId);
    if (!a.isAdmin && meta?.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    // Free tier: no webhooks
    if (meta?.plan === "free") {
      return c.json({ error: "Webhooks require Starter plan or higher", upgradeUrl: "/_sovereign/signup/upgrade" }, 402);
    }

    const body = await c.req.json().catch(() => ({})) as any;
    if (!body.url?.startsWith("https://")) {
      return c.json({ error: "url must be HTTPS" }, 400);
    }

    const webhook = await webhooks.register(ctx.kv, {
      url:    body.url,
      events: body.events ?? ["anchor_completed", "anomaly_detected"],
      secret: body.secret ?? crypto.randomUUID(),
      active: true,
    });

    void chain.emit("CONFIG_CHANGE", {
      event: "webhook_registered", tenantId, webhookId: webhook.id, url: webhook.url,
    }, "LOW");

    return c.json({ webhook }, 201);
  });

  //  List webhooks 
  app.get("/_sovereign/tenants/:id/webhooks", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "tenant not found" }, 404);

    const meta = tenants.getTenantMeta(tenantId);
    if (!a.isAdmin && meta?.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    const list = await webhooks.list(ctx.kv);
    // Redact secrets in response
    const safe = list.map(w => ({ ...w, secret: w.secret.slice(0, 8) + "..." }));

    return c.json({ count: safe.length, webhooks: safe });
  });

  //  Delete webhook 
  app.delete("/_sovereign/tenants/:id/webhooks/:whId", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const whId     = c.req.param("whId");
    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "tenant not found" }, 404);

    const meta = tenants.getTenantMeta(tenantId);
    if (!a.isAdmin && meta?.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    await webhooks.delete(ctx.kv, whId);

    void chain.emit("CONFIG_CHANGE", {
      event: "webhook_deleted", tenantId, webhookId: whId,
    }, "LOW");

    return c.json({ ok: true });
  });

  //  Test webhook 
  app.post("/_sovereign/tenants/:id/webhooks/:whId/test", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const whId     = c.req.param("whId");
    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "tenant not found" }, 404);

    const results = await webhooks.dispatch(ctx.kv, tenantId, "anchor_completed", {
      test:       true,
      merkleRoot: "0x" + "a".repeat(64),
      blockIndex: 0,
      chains:     ["eas-base"],
      message:    "This is a test webhook delivery from Sovereignly",
    });

    return c.json({ results });
  });
}
