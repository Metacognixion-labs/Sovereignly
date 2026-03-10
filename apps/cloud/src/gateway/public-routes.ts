import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
/**
 * Sovereignly v4.0.0  Public Routes & Self-Service
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
        version: "4.0.0",
        tagline: "Own your serverless. Every execution cryptographically logged, Merkle-rooted, attested to 5 public blockchains.",
        signup: "/_sovereign/signup",
        dashboard: "/_sovereign/dashboard",
        docs: "/_sovereign/health",
      });
    }
  });

  //  Dashboard SPA (requires auth — JWT or admin token)
  const serveDashboard = async (c: any) => {
    // Check JWT token via cookie or query param (set by signin/signup JS)
    const bearer = c.req.header("authorization")?.slice(7)
      ?? c.req.query("token");
    if (bearer) {
      const { valid } = await verifyJWT(bearer, opts.jwtSecret);
      if (valid) {
        try {
          const html = await Bun.file("dashboard/index.html").text();
          return c.html(html);
        } catch {
          return c.json({ error: "Dashboard not found." }, 404);
        }
      }
    }
    // Check admin token
    const xtoken = c.req.header("x-sovereign-token")?.replace("Bearer ", "");
    if (xtoken && opts.adminToken && timingSafeEqual(xtoken, opts.adminToken)) {
      try {
        const html = await Bun.file("dashboard/index.html").text();
        return c.html(html);
      } catch {
        return c.json({ error: "Dashboard not found." }, 404);
      }
    }
    // No auth — serve a client-side auth gate that checks localStorage
    return c.html(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Sovereignly Dashboard</title>
<script>
var t=localStorage.getItem('sovereign_token');
if(t){location.replace('/_sovereign/dashboard?token='+encodeURIComponent(t));}
else{location.replace('/_sovereign/signin?next=dashboard');}
</script>
</head><body></body></html>`);
  };
  app.get("/_sovereign/dashboard", serveDashboard);
  app.get("/_sovereign/dashboard/*", serveDashboard);

  //  Sign-in page (GET) + API (POST)
  app.get("/_sovereign/signin", (c) => {
    const next = c.req.query("next") ?? "dashboard";
    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In — Sovereignly</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=DM+Sans:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg-void:#080f1e;--bg-card:#101d35;--bg-raised:#14233f;--bg-border:#1c334f;
--blue:#2B7FFF;--blue-bright:#4f97ff;--green:#5DB84A;
--t-primary:#f0f2f5;--t-secondary:#8fa3bf;--t-muted:#556b8a;
--f-display:'Syne',sans-serif;--f-body:'DM Sans',sans-serif;--f-mono:'JetBrains Mono',monospace;
--radius:8px;--radius-lg:12px}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg-void);color:var(--t-primary);font-family:var(--f-body);
min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.card{background:var(--bg-card);border:1px solid var(--bg-border);border-radius:var(--radius-lg);
padding:40px;width:100%;max-width:440px;margin:20px}
.back{display:inline-block;margin-bottom:20px;color:var(--t-muted);text-decoration:none;font-size:14px}
.back:hover{color:var(--t-secondary)}
h1{font-family:var(--f-display);font-size:24px;font-weight:700;margin-bottom:6px}
.sub{color:var(--t-secondary);font-size:14px;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:500;color:var(--t-secondary);margin-bottom:6px}
input{width:100%;padding:12px 14px;background:var(--bg-raised);border:1px solid var(--bg-border);
border-radius:var(--radius);color:var(--t-primary);font-family:var(--f-body);font-size:15px;
outline:none;transition:border-color .2s;margin-bottom:18px}
input:focus{border-color:var(--blue)}
input::placeholder{color:var(--t-muted)}
button{width:100%;padding:14px;background:var(--blue);color:#fff;border:none;border-radius:var(--radius);
font-family:var(--f-display);font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:var(--blue-bright)}
button:disabled{opacity:.6;cursor:not-allowed}
.msg{margin-top:16px;padding:14px;border-radius:var(--radius);font-size:14px;font-family:var(--f-mono);
line-height:1.6;display:none}
.msg.err{display:block;background:rgba(255,80,80,.1);border:1px solid rgba(255,80,80,.25);color:#ff6b6b}
.link{color:var(--blue);text-decoration:none;font-size:14px}
.link:hover{text-decoration:underline}
.footer{margin-top:20px;text-align:center;color:var(--t-muted);font-size:13px}
</style>
<script>
// If already signed in, skip to dashboard
var t=localStorage.getItem('sovereign_token');
if(t)location.replace('/_sovereign/dashboard');
</script>
</head>
<body>
<div class="card">
  <a href="/" class="back">&larr; Back to Sovereignly</a>
  <h1>Sign in</h1>
  <p class="sub">Enter the email you used to create your account.</p>
  <form id="f">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" placeholder="you@company.com" required autocomplete="email">
    <button type="submit" id="btn">Sign In</button>
  </form>
  <div id="msg" class="msg"></div>
  <div class="footer">No account yet? <a href="/_sovereign/signup" class="link">Create one free</a></div>
</div>
<script>
const f=document.getElementById('f'),msg=document.getElementById('msg'),btn=document.getElementById('btn');
f.addEventListener('submit',async e=>{
  e.preventDefault();btn.disabled=true;btn.textContent='Signing in…';
  msg.className='msg';msg.textContent='';
  try{
    const r=await fetch('/_sovereign/signin',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({email:f.email.value})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Sign in failed');
    localStorage.setItem('sovereign_token',d.token);
    localStorage.setItem('sovereign_tenant',d.tenant.id);
    location.href='/_sovereign/dashboard';
  }catch(err){
    msg.className='msg err';msg.textContent=err.message;
    btn.disabled=false;btn.textContent='Sign In';
  }
});
</script>
</body>
</html>`);
  });

  app.post("/_sovereign/signin", async (c) => {
    const body = await c.req.json().catch(() => ({})) as any;
    const { email } = body;
    if (!email?.trim() || !email.includes("@")) return c.json({ error: "Valid email is required" }, 400);

    const normalized = email.trim().toLowerCase();
    const tenant = tenants.getTenantByOwner(normalized);
    if (!tenant) return c.json({ error: "No account found for this email. Sign up first." }, 404);

    const token = await issueJWT(
      { sub: normalized, tid: tenant.id, role: "owner" },
      opts.jwtSecret,
      86400 * 30
    );

    void chain.emit("AUTH_SUCCESS", {
      event: "signin", tenantId: tenant.id, email: normalized,
    }, { severity: "LOW", source: "public-signin" });

    return c.json({
      ok: true,
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: tenant.plan },
      token,
      dashboard: "/_sovereign/dashboard",
    });
  });

  //  Signup form (GET  serves HTML form)
  app.get("/_sovereign/signup", (c) => {
    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign Up — Sovereignly</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=DM+Sans:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg-void:#080f1e;--bg-card:#101d35;--bg-raised:#14233f;--bg-border:#1c334f;
--blue:#2B7FFF;--blue-bright:#4f97ff;--blue-dark:#1660d8;--green:#5DB84A;
--t-primary:#f0f2f5;--t-secondary:#8fa3bf;--t-muted:#556b8a;
--f-display:'Syne',sans-serif;--f-body:'DM Sans',sans-serif;--f-mono:'JetBrains Mono',monospace;
--radius:8px;--radius-lg:12px}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg-void);color:var(--t-primary);font-family:var(--f-body);
min-height:100vh;display:flex;align-items:center;justify-content:center;
-webkit-font-smoothing:antialiased}
.card{background:var(--bg-card);border:1px solid var(--bg-border);border-radius:var(--radius-lg);
padding:40px;width:100%;max-width:440px;margin:20px}
.back{display:inline-block;margin-bottom:20px;color:var(--t-muted);text-decoration:none;font-size:14px}
.back:hover{color:var(--t-secondary)}
h1{font-family:var(--f-display);font-size:24px;font-weight:700;margin-bottom:6px}
.sub{color:var(--t-secondary);font-size:14px;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:500;color:var(--t-secondary);margin-bottom:6px}
input{width:100%;padding:12px 14px;background:var(--bg-raised);border:1px solid var(--bg-border);
border-radius:var(--radius);color:var(--t-primary);font-family:var(--f-body);font-size:15px;
outline:none;transition:border-color .2s;margin-bottom:18px}
input:focus{border-color:var(--blue)}
input::placeholder{color:var(--t-muted)}
button{width:100%;padding:14px;background:var(--blue);color:#fff;border:none;border-radius:var(--radius);
font-family:var(--f-display);font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:var(--blue-bright)}
button:disabled{opacity:.6;cursor:not-allowed}
.msg{margin-top:16px;padding:14px;border-radius:var(--radius);font-size:14px;font-family:var(--f-mono);
line-height:1.6;display:none}
.msg.ok{display:block;background:rgba(93,184,74,.1);border:1px solid rgba(93,184,74,.25);color:var(--green)}
.msg.err{display:block;background:rgba(255,80,80,.1);border:1px solid rgba(255,80,80,.25);color:#ff6b6b}
.success-actions{margin-top:16px;display:flex;gap:10px}
.success-actions a{display:inline-block;padding:10px 18px;border-radius:var(--radius);font-size:13px;
font-weight:600;text-decoration:none;font-family:var(--f-display)}
.btn-dash{background:var(--blue);color:#fff}
.btn-dash:hover{background:var(--blue-bright)}
</style>
</head>
<body>
<div class="card">
  <a href="/" class="back">&larr; Back to Sovereignly</a>
  <h1>Create your account</h1>
  <p class="sub">Free tier — 10K events/mo, 3 functions, instant activation.</p>
  <form id="f">
    <label for="name">Organization / Project Name</label>
    <input id="name" name="name" type="text" placeholder="Acme Corp" required autocomplete="organization">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" placeholder="you@company.com" required autocomplete="email">
    <button type="submit" id="btn">Create Account</button>
  </form>
  <div id="msg" class="msg"></div>
  <div class="footer" style="margin-top:20px;text-align:center;color:#556b8a;font-size:13px">Already have an account? <a href="/_sovereign/signin" style="color:#2B7FFF;text-decoration:none">Sign in</a></div>
</div>
<script>
// If already signed in, skip to dashboard
var t=localStorage.getItem('sovereign_token');
if(t)location.replace('/_sovereign/dashboard');

const f=document.getElementById('f'),msg=document.getElementById('msg'),btn=document.getElementById('btn');
f.addEventListener('submit',async e=>{
  e.preventDefault();btn.disabled=true;btn.textContent='Creating…';
  msg.className='msg';msg.textContent='';
  try{
    const r=await fetch('/_sovereign/signup',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({name:f.name.value,email:f.email.value})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Signup failed');
    localStorage.setItem('sovereign_token',d.token);
    localStorage.setItem('sovereign_tenant',d.tenant.id);
    location.href='/_sovereign/dashboard';
  }catch(err){
    msg.className='msg err';msg.textContent=err.message;
    btn.disabled=false;btn.textContent='Create Account';
  }
});
</script>
</body>
</html>`);
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
          version: "4.0.0",
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
