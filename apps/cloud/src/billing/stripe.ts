/**
 * Sovereignly v3  Stripe Billing
 *
 * Handles the full subscription lifecycle:
 *   - Checkout session creation (new subscriptions)
 *   - Customer portal (self-serve plan changes, cancellations)
 *   - Webhook processing (subscription.updated, invoice.paid, etc.)
 *   - Usage-based metering for the free tier
 *   - Tenant plan sync on all billing events
 *
 * Pricing (live Stripe Price IDs from your dashboard):
 *   Free:       No Stripe record  local only
 *   Starter:    $49/mo  (STRIPE_PRICE_STARTER)
 *   Growth:     $149/mo (STRIPE_PRICE_GROWTH)
 *   Enterprise: $2000/mo (STRIPE_PRICE_ENTERPRISE)
 *
 * Flow:
 *   1. POST /billing/checkout   creates Stripe Checkout session  redirect
 *   2. User completes payment on Stripe-hosted page
 *   3. Stripe webhook  subscription.created  provision tenant
 *   4. POST /billing/portal    self-serve management
 */

import type { TenantManager, TenantPlan } from "../tenants/manager.ts";
import type { SovereignChain }             from "../../../oss/src/security/chain.ts";
import type { Hono }                       from "hono";
import { verifyJWT }                       from "../zero-trust.ts";

//  Stripe minimal client (no SDK  pure fetch, zero deps) 

class StripeClient {
  constructor(private secretKey: string) {}

  async request<T = any>(
    path:    string,
    method:  "GET" | "POST" | "DELETE" = "GET",
    body?:   Record<string, any>
  ): Promise<T> {
    const res = await fetch(`https://api.stripe.com/v1${path}`, {
      method,
      headers: {
        "Authorization":  `Bearer ${this.secretKey}`,
        "Content-Type":   "application/x-www-form-urlencoded",
        "Stripe-Version": "2024-04-10",
      },
      body: body ? new URLSearchParams(flattenStripe(body)).toString() : undefined,
      signal: AbortSignal.timeout(15_000),
    });

    const data = await res.json() as any;
    if (!res.ok) throw new Error(`Stripe ${res.status}: ${data.error?.message ?? JSON.stringify(data)}`);
    return data as T;
  }
}

// Stripe's API uses dot-notation for nested objects
function flattenStripe(obj: any, prefix = ""): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}[${k}]` : k;
    if (v === null || v === undefined) continue;
    if (typeof v === "object" && !Array.isArray(v)) {
      Object.assign(result, flattenStripe(v as any, key));
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => {
        if (typeof item === "object") {
          Object.assign(result, flattenStripe(item, `${key}[${i}]`));
        } else {
          result[`${key}[${i}]`] = String(item);
        }
      });
    } else {
      result[key] = String(v);
    }
  }
  return result;
}

//  Webhook signature verification 

async function verifyWebhookSignature(
  payload:   string,
  sigHeader: string,
  secret:    string
): Promise<boolean> {
  const parts = sigHeader.split(",").reduce((acc, part) => {
    const [k, v] = part.split("=");
    acc[k.trim()] = v?.trim();
    return acc;
  }, {} as Record<string, string>);

  const ts  = parts["t"];
  const sig = parts["v1"];
  if (!ts || !sig) return false;

  // Replay attack protection (5 minute window)
  if (Math.abs(Date.now() / 1000 - parseInt(ts)) > 300) return false;

  const signed  = `${ts}.${payload}`;
  const key     = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac     = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signed));
  const computed = Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  // Timing-safe compare
  let diff = 0;
  for (let i = 0; i < Math.min(computed.length, sig.length); i++) {
    diff |= computed.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return diff === 0 && computed.length === sig.length;
}

//  BillingService 

export interface BillingConfig {
  stripeSecretKey:     string;
  stripeWebhookSecret: string;
  prices: {
    starter:    string;   // price_xxx
    growth:     string;
    enterprise: string;
  };
  successUrl:   string;   // e.g. "https://app.sovereignly.io/dashboard?billing=success"
  cancelUrl:    string;   // e.g. "https://app.sovereignly.io/pricing"
}

const PLAN_FROM_PRICE: Record<string, TenantPlan> = {};

export class BillingService {
  private stripe: StripeClient;

  constructor(
    private cfg:     BillingConfig,
    private tenants: TenantManager,
    private chain:   SovereignChain
  ) {
    this.stripe = new StripeClient(cfg.stripeSecretKey);
    // Build price  plan map
    PLAN_FROM_PRICE[cfg.prices.starter]    = "starter";
    PLAN_FROM_PRICE[cfg.prices.growth]     = "growth";
    PLAN_FROM_PRICE[cfg.prices.enterprise] = "enterprise";
  }

  //  Create checkout session 

  async createCheckoutSession(opts: {
    tenantId:  string;
    userId:    string;
    plan:      Exclude<TenantPlan, "free">;
    email?:    string;
  }): Promise<{ url: string; sessionId: string }> {
    const tenant = this.tenants.getTenantMeta(opts.tenantId);
    if (!tenant) throw new Error("Tenant not found");

    const priceId = this.cfg.prices[opts.plan];
    if (!priceId) throw new Error(`No price configured for plan: ${opts.plan}`);

    // Create or retrieve Stripe customer
    let customerId = tenant.stripeCustomerId;
    if (!customerId) {
      const customer = await this.stripe.request<any>("/customers", "POST", {
        email:    opts.email,
        name:     tenant.name,
        metadata: { tenantId: opts.tenantId, userId: opts.userId },
      });
      customerId = customer.id;
    }

    const session = await this.stripe.request<any>("/checkout/sessions", "POST", {
      customer:   customerId,
      mode:       "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${this.cfg.successUrl}&session_id={CHECKOUT_SESSION_ID}&tenant=${opts.tenantId}`,
      cancel_url:  this.cfg.cancelUrl,
      metadata:    { tenantId: opts.tenantId, plan: opts.plan, userId: opts.userId },
      subscription_data: {
        metadata: { tenantId: opts.tenantId, plan: opts.plan },
        trial_period_days: ["starter", "growth"].includes(opts.plan) ? 14 : 0,
      },
      allow_promotion_codes: true,
      billing_address_collection: "auto",
    });

    void this.chain.emit("CONFIG_CHANGE", {
      event:     "checkout_initiated",
      tenantId:  opts.tenantId,
      plan:      opts.plan,
      sessionId: session.id,
    }, "LOW");

    return { url: session.url, sessionId: session.id };
  }

  //  Customer portal (self-serve) 

  async createPortalSession(tenantId: string, returnUrl: string): Promise<{ url: string }> {
    const tenant = this.tenants.getTenantMeta(tenantId);
    if (!tenant?.stripeCustomerId) throw new Error("No billing account found");

    const session = await this.stripe.request<any>("/billing_portal/sessions", "POST", {
      customer:   tenant.stripeCustomerId,
      return_url: returnUrl,
    });

    return { url: session.url };
  }

  //  Get current subscription 

  async getSubscription(tenantId: string): Promise<{
    plan:         TenantPlan;
    status:       string;
    currentPeriodEnd?: number;
    cancelAt?:    number;
    trialEnd?:    number;
    amount:       number;
  } | null> {
    const tenant = this.tenants.getTenantMeta(tenantId);
    if (!tenant?.stripeSubId) return { plan: tenant?.plan ?? "free", status: "active", amount: 0 };

    const sub = await this.stripe.request<any>(`/subscriptions/${tenant.stripeSubId}`);
    const priceId = sub.items?.data?.[0]?.price?.id;
    const plan    = PLAN_FROM_PRICE[priceId] ?? tenant.plan;
    const amounts: Record<string, number> = { starter: 49, growth: 149, enterprise: 2000 };

    return {
      plan,
      status:           sub.status,
      currentPeriodEnd: sub.current_period_end * 1000,
      cancelAt:         sub.cancel_at ? sub.cancel_at * 1000 : undefined,
      trialEnd:         sub.trial_end ? sub.trial_end * 1000 : undefined,
      amount:           amounts[plan] ?? 0,
    };
  }

  //  Webhook processing 

  async handleWebhook(rawBody: string, sigHeader: string): Promise<{ ok: boolean; event?: string }> {
    const valid = await verifyWebhookSignature(rawBody, sigHeader, this.cfg.stripeWebhookSecret);
    if (!valid) return { ok: false };

    let event: any;
    try { event = JSON.parse(rawBody); } catch { return { ok: false }; }

    switch (event.type) {
      case "checkout.session.completed": {
        const session   = event.data.object;
        const tenantId  = session.metadata?.tenantId;
        const plan      = session.metadata?.plan as TenantPlan;
        if (tenantId && plan) {
          await this.tenants.upgrade(tenantId, plan, {
            customerId: session.customer,
            subId:      session.subscription,
          });
          void this.chain.emit("CONFIG_CHANGE", {
            event: "subscription_activated",
            tenantId, plan,
            stripeSessionId: session.id,
          }, "LOW");
        }
        break;
      }

      case "customer.subscription.updated": {
        const sub       = event.data.object;
        const tenantId  = sub.metadata?.tenantId;
        const priceId   = sub.items?.data?.[0]?.price?.id;
        const plan      = PLAN_FROM_PRICE[priceId];
        if (tenantId && plan) {
          await this.tenants.upgrade(tenantId, plan, {
            customerId: sub.customer,
            subId:      sub.id,
          });
          void this.chain.emit("CONFIG_CHANGE", {
            event: "subscription_updated",
            tenantId, plan, status: sub.status,
          }, "LOW");
        }
        break;
      }

      case "customer.subscription.deleted": {
        const sub      = event.data.object;
        const tenantId = sub.metadata?.tenantId;
        if (tenantId) {
          await this.tenants.upgrade(tenantId, "free");
          void this.chain.emit("CONFIG_CHANGE", {
            event: "subscription_cancelled",
            tenantId, downgradedTo: "free",
          }, "MEDIUM");
        }
        break;
      }

      case "invoice.payment_failed": {
        const inv      = event.data.object;
        const tenantId = inv.subscription_details?.metadata?.tenantId;
        if (tenantId) {
          void this.chain.emit("ANOMALY", {
            event: "payment_failed",
            tenantId,
            attemptCount: inv.attempt_count,
          }, "MEDIUM");
        }
        break;
      }
    }

    return { ok: true, event: event.type };
  }
}

//  Register billing routes 

export function registerBillingRoutes(
  app:     Hono,
  billing: BillingService,
  opts:    { jwtSecret: string }
) {

  //  Create checkout session 
  app.post("/_sovereign/billing/checkout", async (c) => {
    const token = c.req.header("authorization")?.slice(7);
    if (!token) return c.json({ error: "auth required" }, 401);
    const { valid, payload } = await verifyJWT(token, opts.jwtSecret);
    if (!valid) return c.json({ error: "invalid token" }, 401);

    const { tenantId, plan, email } = await c.req.json();
    if (!tenantId || !plan) return c.json({ error: "tenantId and plan required" }, 400);
    if (!["starter", "growth", "enterprise"].includes(plan)) {
      return c.json({ error: "invalid plan" }, 400);
    }

    try {
      const session = await billing.createCheckoutSession({
        tenantId, plan, email, userId: payload!.sub,
      });
      return c.json(session);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  //  Customer portal 
  app.post("/_sovereign/billing/portal", async (c) => {
    const token = c.req.header("authorization")?.slice(7);
    if (!token) return c.json({ error: "auth required" }, 401);
    const { valid } = await verifyJWT(token, opts.jwtSecret);
    if (!valid) return c.json({ error: "invalid token" }, 401);

    const { tenantId, returnUrl } = await c.req.json();
    try {
      const portal = await billing.createPortalSession(tenantId, returnUrl);
      return c.json(portal);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  //  Subscription status 
  app.get("/_sovereign/billing/subscription/:tenantId", async (c) => {
    const token = c.req.header("authorization")?.slice(7);
    if (!token) return c.json({ error: "auth required" }, 401);
    const { valid } = await verifyJWT(token, opts.jwtSecret);
    if (!valid) return c.json({ error: "invalid token" }, 401);

    const tenantId = c.req.param("tenantId");
    const sub      = await billing.getSubscription(tenantId);
    if (!sub) return c.json({ error: "not found" }, 404);
    return c.json(sub);
  });

  //  Stripe webhook (no auth  verified by signature) 
  app.post("/_sovereign/billing/webhook", async (c) => {
    const sig = c.req.header("stripe-signature");
    if (!sig) return c.json({ error: "no signature" }, 400);

    const rawBody = await c.req.text();
    const result  = await billing.handleWebhook(rawBody, sig);

    if (!result.ok) return c.json({ error: "invalid signature" }, 400);
    return c.json({ received: true, event: result.event });
  });
}
