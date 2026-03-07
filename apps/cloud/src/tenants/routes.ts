import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
/**
 * Sovereignly v3  Tenant API Routes
 *
 * POST   /_sovereign/tenants                    Create tenant (provision)
 * GET    /_sovereign/tenants                    List tenants (admin)
 * GET    /_sovereign/tenants/:id                Get tenant + stats
 * PATCH  /_sovereign/tenants/:id               Update tenant
 * DELETE /_sovereign/tenants/:id               Suspend tenant
 * GET    /_sovereign/tenants/:id/stats          Usage + chain stats
 * GET    /_sovereign/tenants/:id/chain/events   Tenant's audit events
 * GET    /_sovereign/tenants/:id/chain/report   Compliance report
 * POST   /_sovereign/tenants/:id/chain/export   Export chain data
 * GET    /_sovereign/platform/stats             Platform-wide metrics (admin)
 */

import type { Hono }           from "hono";
import type { TenantManager }  from "../tenants/manager.ts";
import type { BillingService } from "../billing/stripe.ts";
import type { SovereignChain } from "../../../oss/src/security/chain.ts";
import { verifyJWT }           from "../zero-trust.ts";

export function registerTenantRoutes(
  app:     Hono,
  tenants: TenantManager,
  billing: BillingService | null,
  chain:   SovereignChain,   // platform-level chain for admin audit
  opts:    { jwtSecret: string; adminToken?: string }
) {

  //  Helper: verify auth, return userId + isAdmin 
  async function auth(c: any): Promise<{ userId: string; isAdmin: boolean } | null> {
    const header = c.req.header("authorization") ?? "";
    const xtoken = c.req.header("x-sovereign-token") ?? "";

    if (opts.adminToken && timingSafeEqual(xtoken, opts.adminToken)) {
      return { userId: "admin", isAdmin: true };
    }

    if (!header.startsWith("Bearer ")) return null;
    const { valid, payload } = await verifyJWT(header.slice(7), opts.jwtSecret);
    if (!valid || !payload) return null;
    return { userId: payload.sub, isAdmin: payload.role === "admin" };
  }

  //  Provision new tenant 
  app.post("/_sovereign/tenants", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const { name, plan, domain } = await c.req.json().catch(() => ({})) as any;
    if (!name?.trim()) return c.json({ error: "name required" }, 400);

    try {
      const tenant = await tenants.provision({
        name:    name.trim(),
        ownerId: a.userId,
        plan:    a.isAdmin ? (plan ?? "free") : "free",
        domain,
      });

      void chain.emit("CONFIG_CHANGE", {
        event: "tenant_created", tenantId: tenant.id,
        name: tenant.name, plan: tenant.plan, createdBy: a.userId,
      }, "LOW");

      return c.json({ tenant }, 201);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  //  List tenants (admin only) 
  app.get("/_sovereign/tenants", async (c) => {
    const a = await auth(c);
    if (!a?.isAdmin) return c.json({ error: "admin required" }, 403);

    const { plan, status, limit } = c.req.query();
    const list = tenants.listTenants({ plan: plan as any, status: status as any });

    return c.json({
      count: list.length,
      tenants: list.slice(0, parseInt(limit ?? "100")),
      mrr: tenants.getMRR(),
      planBreakdown: tenants.getPlanBreakdown(),
    });
  });

  //  Get tenant detail 
  app.get("/_sovereign/tenants/:id", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const meta     = tenants.getTenantMeta(tenantId);
    if (!meta) return c.json({ error: "not found" }, 404);

    // Users can only see their own tenant (unless admin)
    if (!a.isAdmin && meta.ownerId !== a.userId) {
      return c.json({ error: "forbidden" }, 403);
    }

    const ctx = await tenants.get(tenantId);
    const chainStats = ctx?.chain.getStats();

    return c.json({
      ...meta,
      chain: chainStats ? {
        blocks:   chainStats.blocks,
        events:   chainStats.events,
        anchored: chainStats.anchored,
        tip:      chainStats.tip?.blockHash,
      } : null,
    });
  });

  //  Update tenant 
  app.patch("/_sovereign/tenants/:id", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const meta     = tenants.getTenantMeta(tenantId);
    if (!meta) return c.json({ error: "not found" }, 404);
    if (!a.isAdmin && meta.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    const { plan, domain } = await c.req.json().catch(() => ({})) as any;

    // Plan changes require admin or billing
    if (plan && !a.isAdmin) return c.json({ error: "plan changes via billing portal" }, 403);
    if (plan) await tenants.upgrade(tenantId, plan);

    return c.json({ ok: true, tenantId });
  });

  //  Suspend tenant (admin) 
  app.delete("/_sovereign/tenants/:id", async (c) => {
    const a = await auth(c);
    if (!a?.isAdmin) return c.json({ error: "admin required" }, 403);

    const tenantId = c.req.param("id");
    const { reason } = await c.req.json().catch(() => ({ reason: "admin action" })) as any;
    await tenants.suspend(tenantId, reason ?? "admin action");
    return c.json({ ok: true });
  });

  //  Tenant stats + usage 
  app.get("/_sovereign/tenants/:id/stats", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const meta     = tenants.getTenantMeta(tenantId);
    if (!meta) return c.json({ error: "not found" }, 404);
    if (!a.isAdmin && meta.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "tenant context unavailable" }, 503);

    const chainStats  = ctx.chain.getStats();
    const kvStats     = await ctx.kv.stats?.() ?? { keys: 0 };
    const sub         = billing ? await billing.getSubscription(tenantId).catch(() => null) : null;

    // Usage for current month
    const monthStart = new Date();
    monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const recentEvents = ctx.chain.getEvents({
      since: monthStart.getTime(),
      limit: 1,
    });

    const monthlyEvents = chainStats.events; // simplified  real impl counts by month

    return c.json({
      tenant: {
        id:     meta.id,
        name:   meta.name,
        plan:   meta.plan,
        status: meta.status,
      },
      chain: {
        blocks:         chainStats.blocks,
        events:         chainStats.events,
        anchored:       chainStats.anchored,
        criticalEvents: chainStats.critical,
        tip:            chainStats.tip?.blockHash ?? null,
        tipTs:          chainStats.tip?.ts ?? null,
      },
      usage: {
        eventsThisMonth:  monthlyEvents,
        eventsLimit:      meta.limits.eventsPerMonth,
        eventsPercent:    meta.limits.eventsPerMonth === Infinity
          ? 0 : Math.round(monthlyEvents / meta.limits.eventsPerMonth * 100),
        storageGB:        0,   // TODO: sum storage
        storageLimit:     meta.limits.storageGB,
        kvKeys:           kvStats.keys,
        kvLimit:          meta.limits.kvKeysMax,
      },
      billing: sub ?? null,
    });
  });

  //  Tenant chain events 
  app.get("/_sovereign/tenants/:id/chain/events", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const meta     = tenants.getTenantMeta(tenantId);
    if (!meta) return c.json({ error: "not found" }, 404);
    if (!a.isAdmin && meta.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "unavailable" }, 503);

    const { type, severity, since, limit } = c.req.query();
    const events = ctx.chain.getEvents({
      type:     type as any,
      severity: severity as any,
      since:    since ? parseInt(since) : undefined,
      limit:    Math.min(parseInt(limit ?? "50"), 500),
    });

    return c.json({ count: events.length, events });
  });

  //  Compliance report 
  app.get("/_sovereign/tenants/:id/chain/report", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const meta     = tenants.getTenantMeta(tenantId);
    if (!meta) return c.json({ error: "not found" }, 404);
    if (!a.isAdmin && meta.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    // Only Growth+ gets compliance reports
    if (!a.isAdmin && meta.plan === "free") {
      return c.json({
        error: "compliance reports require Starter plan or higher",
        upgradeUrl: "/_sovereign/billing/checkout",
      }, 402);
    }

    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "unavailable" }, 503);

    const { ComplianceEngine } = await import("../security/compliance.ts");
    const compliance = new ComplianceEngine(ctx.chain);

    const { standard } = c.req.query();
    const report = compliance.generateReport(
      (standard ?? "SOC2") as any
    );

    return c.json(report);
  });

  //  Export chain (portable, offline-verifiable) 
  app.post("/_sovereign/tenants/:id/chain/export", async (c) => {
    const a = await auth(c);
    if (!a) return c.json({ error: "auth required" }, 401);

    const tenantId = c.req.param("id");
    const meta     = tenants.getTenantMeta(tenantId);
    if (!meta) return c.json({ error: "not found" }, 404);
    if (!a.isAdmin && meta.ownerId !== a.userId) return c.json({ error: "forbidden" }, 403);

    const ctx = await tenants.get(tenantId);
    if (!ctx) return c.json({ error: "unavailable" }, 503);

    const stats  = ctx.chain.getStats();
    const events = ctx.chain.getEvents({ limit: 10_000 });

    const export_ = {
      exportVersion:  "4.0.0",
      tenantId,
      tenantName:     meta.name,
      exportedAt:     new Date().toISOString(),
      exportedBy:     a.userId,
      chain: {
        blocks:    stats.blocks,
        events:    stats.events,
        tip:       stats.tip?.blockHash,
        anchors: {
          meridian:  stats.anchored,
          ethereum:  null,  // TODO: pull from anchor DB
        },
      },
      events,
      verifyInstructions: [
        "1. Hash each event payload with SHA-256",
        "2. Build Merkle tree of all events in each block",
        "3. Verify each block's merkleRoot matches",
        "4. Verify chain continuity: block[n].prevHash === block[n-1].blockHash",
        "5. Verify Meridian/Ethereum anchor at the recorded tx hash",
      ],
    };

    void chain.emit("DATA_EXPORT", {
      tenantId, exportedBy: a.userId, eventCount: events.length,
    }, "MEDIUM");

    return c.json(export_);
  });

  //  Platform stats (admin) 
  app.get("/_sovereign/platform/stats", async (c) => {
    const a = await auth(c);
    if (!a?.isAdmin) return c.json({ error: "admin required" }, 403);

    const globalRoot = await tenants.buildGlobalRoot();

    return c.json({
      tenants: {
        total:     tenants.getActiveCount(),
        byPlan:    tenants.getPlanBreakdown(),
        mrr:       tenants.getMRR(),
        arr:       tenants.getMRR() * 12,
      },
      chain: {
        tenantCount:    globalRoot.tenantTips.length,
        globalRoot:     globalRoot.root,
        rootBuiltAt:    new Date(globalRoot.timestamp).toISOString(),
        tenantTips:     globalRoot.tenantTips.slice(0, 10), // preview
      },
      platform: {
        version:     "4.0.0",
        uptime:      Math.floor(process.uptime()),
        bunVersion:  typeof Bun !== "undefined" ? Bun.version : "node",
      },
    });
  });
}
