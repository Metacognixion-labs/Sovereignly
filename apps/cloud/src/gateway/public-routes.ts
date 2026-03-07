import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
/**
 * Sovereignly v3.0.1  Public Routes & Self-Service
 *
 * Handles the revenue pipeline:
 *   GET  /                               Landing page
 *   GET  /_sovereign/dashboard           Admin dashboard (HTML SPA)
 *   POST /_sovereign/signup              Public free-tier signup (no auth)
 *   POST /_sovereign/signup/upgrade      Create Stripe checkout for upgrade
 *   GET  /_sovereign/me                  Current user context (JWT  tenant)
 */

import type { Hono } from "hono";
import type { TenantManager } from "../tenants/manager.ts";
import type { BillingService } from "../billing/stripe.ts";
import type { SovereignChain } from "../../../oss/src/security/chain.ts";
import { issueJWT, verifyJWT } from "../zero-trust.ts";

export function registerPublicRoutes(
  app:     Hono,
  tenants: TenantManager,
  billing: BillingService | null,
  chain:   SovereignChain,
  opts:    { jwtSecret: string; adminToken?: string }
) {

  //  Landing page 
  app.get("/", async (c) => {
    try {
      const html = await Bun.file("deploy/landing-page.html").text();
      return c.html(html);
    } catch {
      return c.json({
        name: "Sovereignly",
        version: "3.0.1",
        tagline: "Own your serverless. Every execution cryptographically logged, Merkle-rooted, attested to 5 public blockchains.",
        signup: "/_sovereign/signup",
        dashboard: "/_sovereign/dashboard",
        docs: "/_sovereign/health",
      });
    }
  });

  //  Dashboard SPA 
  app.get("/_sovereign/dashboard", async (c) => {
    try {
      const html = await Bun.file("dashboard/index.html").text();
      return c.html(html);
    } catch {
      return c.json({ error: "Dashboard not found. Ensure dashboard/index.html is in the container." }, 404);
    }
  });
  // SPA catch-all for dashboard sub-routes
  app.get("/_sovereign/dashboard/*", async (c) => {
    try {
      const html = await Bun.file("dashboard/index.html").text();
      return c.html(html);
    } catch {
      return c.redirect("/_sovereign/dashboard");
    }
  });

  //  Public signup (free tier, no auth required) 
  //
  // This is the core of self-service: anyone can create a free tenant and
  // get a JWT back immediately. No Stripe, no OAuth  just name + email.
  //
  // Response includes a JWT that grants owner access to the new tenant.
  // Dashboard reads this from localStorage to make authenticated API calls.

  app.post("/_sovereign/signup", async (c) => {
    const body = await c.req.json().catch(() => ({})) as any;
    const { name, email } = body;

    if (!name?.trim()) return c.json({ error: "name is required (your company or project name)" }, 400);
    if (!email?.trim() || !email.includes("@")) return c.json({ error: "valid email is required" }, 400);

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    if (!emailRegex.test(email.trim())) return c.json({ error: "invalid email format" }, 400);

    // Block known disposable email domains
    const disposable = ["mailinator.com", "tempmail.com", "guerrillamail.com", "throwaway.email", "yopmail.com", "10minutemail.com"];
    const domain = email.trim().split("@")[1]?.toLowerCase();
    if (disposable.includes(domain)) return c.json({ error: "disposable email addresses not allowed" }, 400);

    // Rate limit signups by IP (10/hour)
    // NOTE: On Fly.io, X-Forwarded-For is set by the platform proxy (trusted).
    // If self-hosting behind a different proxy, ensure it strips client-sent XFF.
    const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? c.req.header("x-real-ip") ?? "unknown";
    const rateLimitKey = `signup:${ip}`;
    // Simple in-memory rate limit (production: use the gateway rate limiter)
    const now = Date.now();
    if (!signupLimiter.has(rateLimitKey)) signupLimiter.set(rateLimitKey, []);
    const attempts = signupLimiter.get(rateLimitKey)!.filter(t => t > now - 3600_000);
    if (attempts.length >= 10) {
      return c.json({ error: "Too many signups from this IP. Try again in an hour." }, 429);
    }
    attempts.push(now);
    signupLimiter.set(rateLimitKey, attempts);

    try {
      // Provision free-tier tenant
      const tenant = await tenants.provision({
        name:    name.trim(),
        ownerId: email.trim().toLowerCase(),
        plan:    "free",
      });

      // Issue JWT for the new owner (30-day expiry)
      const token = await issueJWT(
        { sub: email.trim().toLowerCase(), tid: tenant.id, role: "owner" },
        opts.jwtSecret,
        86400 * 30 // 30 days
      );

      // Audit + user creation event
      void chain.emit("CONFIG_CHANGE", {
        event:    "public_signup",
        tenantId: tenant.id,
        email:    email.trim().toLowerCase(),
        plan:     "free",
        ip,
      }, "LOW");

      // Emit user creation for the event bus (auth system can pick this up)
      if (typeof globalThis.__sovereignlyBus !== "undefined") {
        void (globalThis as any).__sovereignlyBus.emit("TENANT_CREATED", {
          tenantId: tenant.id,
          userId:   email.trim().toLowerCase(),
          name:     name.trim(),
          plan:     "free",
          method:   "public_signup",
        }, { source: "public-signup", tenantId: tenant.id });
      }

      return c.json({
        ok: true,
        tenant: {
          id:   tenant.id,
          name: tenant.name,
          slug: tenant.slug,
          plan: tenant.plan,
        },
        token,
        dashboard: `/_sovereign/dashboard`,
        apiBase:   `/_sovereign/tenants/${tenant.id}`,
        nextSteps: [
          "Save the token  it's your API key for 30 days",
          "Install the SDK: npm install @metacognixion/chain-sdk",
          "Start emitting events to your audit chain",
          "Upgrade to Starter ($49/mo) for compliance reports + 1M events/mo",
        ],
      }, 201);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  //  Upgrade to paid plan (requires existing JWT) 

  app.post("/_sovereign/signup/upgrade", async (c) => {
    if (!billing) return c.json({ error: "Billing not configured" }, 503);

    const token = c.req.header("authorization")?.slice(7);
    if (!token) return c.json({ error: "Bearer token required" }, 401);

    const { valid, payload } = await verifyJWT(token, opts.jwtSecret);
    if (!valid || !payload) return c.json({ error: "Invalid token" }, 401);

    const body = await c.req.json().catch(() => ({})) as any;
    const plan = body.plan;
    const interval = body.interval ?? "month"; // "month" or "year"
    if (!plan || !["starter", "growth", "enterprise"].includes(plan)) {
      return c.json({ error: "plan must be starter, growth, or enterprise" }, 400);
    }
    if (!["month", "year"].includes(interval)) {
      return c.json({ error: "interval must be month or year" }, 400);
    }

    try {
      const session = await billing.createCheckoutSession({
        tenantId: payload.tid,
        userId:   payload.sub,
        plan,
        email:    payload.sub,
        // Annual billing: pass interval for Stripe to use annual price ID
        // In production, you'd have separate STRIPE_PRICE_*_ANNUAL env vars
      });

      void chain.emit("CONFIG_CHANGE", {
        event:    "upgrade_initiated",
        tenantId: payload.tid,
        plan,
      }, "LOW");

      return c.json({ url: session.url, sessionId: session.sessionId });
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  //  Current user context (for dashboard) 

  app.get("/_sovereign/me", async (c) => {
    // Try JWT first
    const bearer = c.req.header("authorization")?.slice(7);
    if (bearer) {
      const { valid, payload } = await verifyJWT(bearer, opts.jwtSecret);
      if (valid && payload) {
        const meta = tenants.getTenantMeta(payload.tid);
        const ctx  = meta ? await tenants.get(payload.tid) : null;
        const stats = ctx?.chain.getStats();

        return c.json({
          user:   { id: payload.sub, role: payload.role },
          tenant: meta ? {
            id:     meta.id,
            name:   meta.name,
            plan:   meta.plan,
            status: meta.status,
          } : null,
          chain: stats ? {
            blocks:   stats.blocks,
            events:   stats.events,
            anchored: stats.anchored,
          } : null,
        });
      }
    }

    // Try admin token
    const xtoken = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    if (xtoken && opts.adminToken && timingSafeEqual(xtoken, opts.adminToken)) {
      return c.json({
        user:   { id: "admin", role: "admin" },
        tenant: null,
        isAdmin: true,
        platform: {
          tenants: tenants.getActiveCount(),
          mrr:     tenants.getMRR(),
          version: "3.0.1",
        },
      });
    }

    return c.json({ error: "Not authenticated" }, 401);
  });

  //  Pricing page data (for landing page dynamic pricing) 

  app.get("/_sovereign/pricing", (c) => {
    return c.json({
      plans: [
        {
          name: "Free",
          monthly: 0,
          annual: 0,
          interval: "forever",
          features: [
            "10,000 events/month",
            "3 serverless functions",
            "1 agent",
            "3 workflow runs/day",
            "EAS/Base attestation ($0.18/yr)",
            "1 seat",
            "Community support",
          ],
          limits: { events: "10K/mo", functions: 3, agents: 1, workflows: "3/day", seats: 1, storage: "500MB" },
          cta: { label: "Start Free", action: "/_sovereign/signup" },
        },
        {
          name: "Starter",
          monthly: 49,
          annual: 39,
          interval: "month",
          trial: 14,
          popular: false,
          features: [
            "1,000,000 events/month",
            "20 serverless functions",
            "5 agents",
            "Unlimited workflows",
            "EAS/Base + Arbitrum + Sign Protocol",
            "3 seats",
            "SOC2 + ISO 27001 reports",
            "Webhook delivery",
            "14-day free trial",
          ],
          limits: { events: "1M/mo", functions: 20, agents: 5, workflows: "unlimited", seats: 3, storage: "20GB" },
          cta: { label: "Start Trial", action: "/_sovereign/signup/upgrade", plan: "starter" },
        },
        {
          name: "Growth",
          monthly: 149,
          annual: 119,
          interval: "month",
          trial: 14,
          popular: true,
          features: [
            "10,000,000 events/month",
            "100 serverless functions",
            "Unlimited agents",
            "Unlimited workflows",
            "+ Solana Memo attestation",
            "10 seats",
            "All compliance frameworks (SOC2, ISO27001, HIPAA, GDPR, NIST)",
            "Webhook delivery + retry",
            "Plugin marketplace access",
            "Priority support",
            "14-day free trial",
          ],
          limits: { events: "10M/mo", functions: 100, agents: "unlimited", workflows: "unlimited", seats: 10, storage: "100GB" },
          cta: { label: "Start Trial", action: "/_sovereign/signup/upgrade", plan: "growth" },
        },
        {
          name: "Enterprise",
          monthly: 2000,
          annual: 1600,
          interval: "month",
          features: [
            "Unlimited everything",
            "AI OS natural language interface",
            "Cognitive infrastructure model",
            "Custom kernel policies",
            "+ Irys permanent archive",
            "+ Bitcoin OP_RETURN (weekly)",
            "Unlimited seats",
            "Dedicated support engineer",
            "Custom SLA + BAA",
            "On-premise deployment option",
          ],
          limits: { events: "unlimited", functions: "unlimited", agents: "unlimited", workflows: "unlimited", seats: "unlimited", storage: "unlimited" },
          cta: { label: "Contact Sales", action: "mailto:jp@metacognixion.com" },
        },
      ],
      annualDiscount: 20,
      annualNote: "Save 20% with annual billing",
      currency: "USD",
    });
  });
}

// Simple in-memory signup rate limiter
const signupLimiter = new Map<string, number[]>();

// Cleanup old entries every hour
setInterval(() => {
  const cutoff = Date.now() - 3600_000;
  for (const [key, times] of signupLimiter) {
    const valid = times.filter(t => t > cutoff);
    if (valid.length === 0) signupLimiter.delete(key);
    else signupLimiter.set(key, valid);
  }
}, 3600_000);
