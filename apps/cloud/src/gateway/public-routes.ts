import { timingSafeEqual } from "../../../oss/src/security/crypto.ts";
/**
 * Sovereignly v4.0.0  Public Routes & Self-Service
 *
 * Handles the revenue pipeline:
 *   GET  /                               Landing page
 *   GET  /_sovereign/dashboard           Admin dashboard (HTML SPA)
 *   POST /_sovereign/signin              Step 1: request magic-link code
 *   POST /_sovereign/signin/verify       Step 2: verify code → JWT (or TOTP challenge)
 *   POST /_sovereign/signin/totp         Step 3: verify TOTP/backup code → full JWT
 *   POST /_sovereign/signup              Public free-tier signup (no auth)
 *   POST /_sovereign/signup/verify       Verify email after signup
 *   POST /_sovereign/signup/upgrade      Create Stripe checkout for upgrade
 *   GET  /_sovereign/me                  Current user context (JWT  tenant)
 */

import type { Hono } from "hono";
import type { TenantManager } from "../tenants/manager.ts";
import type { BillingService } from "../billing/stripe.ts";
import type { SovereignChain } from "../../../oss/src/security/chain.ts";
import type { MagicLinkService } from "../../../oss/src/auth/magic-link.ts";
import type { TOTPService }     from "../../../oss/src/auth/totp.ts";
import { issueJWT, verifyJWT } from "../zero-trust.ts";
import { registerSetupWizard, isSetupComplete } from "./setup-wizard.ts";

export function registerPublicRoutes(
  app:       Hono,
  tenants:   TenantManager,
  billing:   BillingService | null,
  chain:     SovereignChain,
  opts:      { jwtSecret: string; adminToken?: string },
  magicLink?: MagicLinkService,
  totp?:      TOTPService,
) {

  //  Setup Wizard Guard — redirect to setup if no tenants exist
  if (magicLink) {
    registerSetupWizard(app, { tenants, magicLink, jwtSecret: opts.jwtSecret });
    app.use("*", async (c, next) => {
      const path = new URL(c.req.url).pathname;
      if (!isSetupComplete(tenants)
        && path !== "/_sovereign/setup"
        && path !== "/_sovereign/health"
        && !path.startsWith("/_sovereign/auth/passkeys")) {
        return c.redirect("/_sovereign/setup");
      }
      return next();
    });
  }

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
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#050a10;--surface:#0d151f;--card:#111b2a;--raised:#162236;--border:#1e293b;
--brand:#0df23b;--brand-bright:#3dff62;--quantum:#a78bfa;
--t-primary:#f0f2f5;--t-secondary:#94a3b8;--t-muted:#475569;
--font:'Space Grotesk',sans-serif;--mono:'JetBrains Mono',monospace;
--radius:8px;--radius-lg:12px}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--t-primary);font-family:var(--font);
min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);
padding:40px;width:100%;max-width:440px;margin:20px}
.back{display:inline-block;margin-bottom:20px;color:var(--t-muted);text-decoration:none;font-size:14px;transition:color .2s}
.back:hover{color:var(--t-secondary)}
h1{font-size:24px;font-weight:700;margin-bottom:6px;letter-spacing:-.02em}
.sub{color:var(--t-secondary);font-size:14px;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:500;color:var(--t-secondary);margin-bottom:6px}
input{width:100%;padding:12px 14px;background:var(--raised);border:1px solid var(--border);
border-radius:var(--radius);color:var(--t-primary);font-family:var(--font);font-size:15px;
outline:none;transition:border-color .2s;margin-bottom:18px}
input:focus{border-color:var(--brand)}
input::placeholder{color:var(--t-muted)}
button{width:100%;padding:14px;background:var(--brand);color:#050a10;border:none;border-radius:var(--radius);
font-family:var(--font);font-size:15px;font-weight:600;cursor:pointer;transition:all .2s}
button:hover{background:var(--brand-bright);box-shadow:0 0 24px rgba(13,242,59,.2)}
button:disabled{opacity:.6;cursor:not-allowed}
.msg{margin-top:16px;padding:14px;border-radius:var(--radius);font-size:14px;font-family:var(--mono);
line-height:1.6;display:none}
.msg.err{display:block;background:rgba(255,80,80,.1);border:1px solid rgba(255,80,80,.25);color:#ff6b6b}
.link{color:var(--brand);text-decoration:none;font-size:14px}
.link:hover{text-decoration:underline}
.footer{margin-top:20px;text-align:center;color:var(--t-muted);font-size:13px}
</style>
<script>
var t=localStorage.getItem('sovereign_token');
if(t)location.replace('/_sovereign/dashboard');
</script>
<style>
.step{display:none}.step.active{display:block}
.code-row{display:flex;gap:8px;margin-bottom:18px}
.code-row input{width:44px;text-align:center;font-family:var(--mono);font-size:18px;font-weight:600;padding:12px 0}
</style>
</head>
<body>
<div class="card">
  <a href="/" class="back">&larr; Back to Sovereignly</a>
  <h1>Sign in</h1>

  <!-- Step 1: Email -->
  <div class="step active" id="s1">
    <p class="sub">Enter your email and we'll send you a magic link to sign in.</p>
    <form id="f1">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" placeholder="you@company.com" required autocomplete="email">
      <button type="submit" id="btn1">Continue with email</button>
    </form>
  </div>

  <!-- Step 2: Check email / Code fallback -->
  <div class="step" id="s2">
    <div style="text-align:center;margin-bottom:20px">
      <div style="width:48px;height:48px;border-radius:50%;background:rgba(13,242,59,.1);border:2px solid rgba(13,242,59,.2);display:inline-flex;align-items:center;justify-content:center">
        <svg width="22" height="22" fill="none" stroke="#0df23b" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
      </div>
    </div>
    <p class="sub" style="text-align:center">Check your email! We sent a sign-in link to <strong id="emailShow" style="color:var(--brand)"></strong></p>
    <p style="color:var(--t-muted);font-size:12px;text-align:center;margin-bottom:20px">Click the link in the email, or enter the 6-digit code below.</p>
    <form id="f2">
      <div class="code-row" id="codeRow">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
      </div>
      <button type="submit" id="btn2">Verify</button>
    </form>
  </div>

  <!-- Step 3: TOTP (if enabled) -->
  <div class="step" id="s3">
    <p class="sub">Enter the code from your authenticator app, or a backup code.</p>
    <form id="f3">
      <label for="totp">Authenticator Code</label>
      <input id="totp" type="text" placeholder="000000 or xxxx-xxxx" required autocomplete="one-time-code" style="font-family:var(--mono);text-align:center;font-size:18px;letter-spacing:.15em">
      <button type="submit" id="btn3">Sign In</button>
    </form>
  </div>

  <div id="msg" class="msg"></div>
  <div class="footer">No account yet? <a href="/_sovereign/signup" class="link">Create one free</a></div>
</div>
<script>
let savedEmail='',pendingToken='';
const msg=document.getElementById('msg');
function showErr(t){msg.className='msg err';msg.textContent=t;}
function hideMsg(){msg.className='msg';}
function showStep(n){document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));document.getElementById('s'+n).classList.add('active');}

// Code inputs auto-advance
const cis=document.querySelectorAll('.ci');
cis.forEach((ci,i)=>{
  ci.addEventListener('input',()=>{if(ci.value&&i<cis.length-1)cis[i+1].focus();});
  ci.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!ci.value&&i>0)cis[i-1].focus();});
  ci.addEventListener('paste',e=>{const t=(e.clipboardData||window.clipboardData).getData('text').replace(/\\D/g,'');
    if(t.length===6){e.preventDefault();cis.forEach((c,j)=>{c.value=t[j]||'';});cis[5].focus();}});
});

// Step 1: Request code
document.getElementById('f1').addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();const btn=document.getElementById('btn1');
  btn.disabled=true;btn.textContent='Sending…';
  savedEmail=document.getElementById('email').value;
  try{
    const r=await fetch('/_sovereign/signin',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({email:savedEmail})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Failed');
    if(d.requiresCode){
      document.getElementById('emailShow').textContent=savedEmail;
      showStep(2);cis[0].focus();
    }else if(d.token){
      localStorage.setItem('sovereign_token',d.token);
      localStorage.setItem('sovereign_tenant',d.tenant.id);
      location.href='/_sovereign/dashboard';
    }
  }catch(err){showErr(err.message);btn.disabled=false;btn.textContent='Send Code';}
});

// Step 2: Verify code
document.getElementById('f2').addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();const btn=document.getElementById('btn2');
  btn.disabled=true;btn.textContent='Verifying…';
  const code=Array.from(cis).map(c=>c.value).join('');
  if(code.length!==6){showErr('Enter all 6 digits');btn.disabled=false;btn.textContent='Verify';return;}
  try{
    const r=await fetch('/_sovereign/signin/verify',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({email:savedEmail,code})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Verification failed');
    if(d.requiresTOTP){
      pendingToken=d.pendingToken;showStep(3);document.getElementById('totp').focus();
    }else{
      localStorage.setItem('sovereign_token',d.token);
      localStorage.setItem('sovereign_tenant',d.tenant.id);
      location.href='/_sovereign/dashboard';
    }
  }catch(err){showErr(err.message);btn.disabled=false;btn.textContent='Verify';}
});

// Step 3: TOTP
document.getElementById('f3').addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();const btn=document.getElementById('btn3');
  btn.disabled=true;btn.textContent='Verifying…';
  try{
    const r=await fetch('/_sovereign/signin/totp',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({pendingToken,code:document.getElementById('totp').value})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Invalid code');
    localStorage.setItem('sovereign_token',d.token);
    if(d.tenant)localStorage.setItem('sovereign_tenant',d.tenant.id);
    location.href='/_sovereign/dashboard';
  }catch(err){showErr(err.message);btn.disabled=false;btn.textContent='Sign In';}
});
</script>
</body>
</html>`);
  });

  //  POST /_sovereign/signin — Step 1: send verification code
  app.post("/_sovereign/signin", async (c) => {
    const body = await c.req.json().catch(() => ({})) as any;
    const { email } = body;
    if (!email?.trim() || !email.includes("@")) return c.json({ error: "Valid email is required" }, 400);

    const normalized = email.trim().toLowerCase();
    const tenant = tenants.getTenantByOwner(normalized);
    if (!tenant) return c.json({ error: "No account found for this email. Sign up first." }, 404);

    if (magicLink) {
      const result = await magicLink.requestCode(normalized, "signin");
      if (!result.ok) return c.json({ error: result.error }, 429);
      return c.json({ ok: true, requiresCode: true, message: "Verification code sent to your email" });
    }

    // Fallback if magic-link not configured (shouldn't happen in production)
    const token = await issueJWT(
      { sub: normalized, tid: tenant.id, role: "owner" },
      opts.jwtSecret,
      86400 * 30
    );
    return c.json({ ok: true, tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: tenant.plan }, token });
  });

  //  POST /_sovereign/signin/verify — Step 2: verify code → JWT or TOTP challenge
  app.post("/_sovereign/signin/verify", async (c) => {
    if (!magicLink) return c.json({ error: "Magic link not configured" }, 503);

    const body = await c.req.json().catch(() => ({})) as any;
    const { email, code } = body;
    if (!email?.trim() || !code?.trim()) return c.json({ error: "Email and code required" }, 400);

    const normalized = email.trim().toLowerCase();
    const tenant = tenants.getTenantByOwner(normalized);
    if (!tenant) return c.json({ error: "No account found" }, 404);

    const result = await magicLink.verifyCode(normalized, code, "signin");
    if (!result.valid) return c.json({ error: result.error }, 401);

    // Check if TOTP is enabled for this user
    if (totp?.isEnabled(normalized)) {
      // Issue a short-lived pending token (5 min) that requires TOTP to upgrade
      const pendingToken = await issueJWT(
        { sub: normalized, tid: tenant.id, role: "owner", scope: "totp_pending" } as any,
        opts.jwtSecret,
        300 // 5 minutes
      );
      return c.json({ ok: true, requiresTOTP: true, pendingToken });
    }

    // No TOTP — issue full session JWT
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

  //  POST /_sovereign/signin/totp — Step 3: verify TOTP or backup code
  app.post("/_sovereign/signin/totp", async (c) => {
    if (!totp) return c.json({ error: "TOTP not configured" }, 503);

    const body = await c.req.json().catch(() => ({})) as any;
    const { pendingToken, code } = body;
    if (!pendingToken || !code?.trim()) return c.json({ error: "Pending token and code required" }, 400);

    const { valid, payload } = await verifyJWT(pendingToken, opts.jwtSecret);
    if (!valid || !payload || (payload as any).scope !== "totp_pending") {
      return c.json({ error: "Invalid or expired pending token" }, 401);
    }

    const codeClean = code.trim();
    let verified = false;

    // Try TOTP code (6 digits) or backup code (xxxx-xxxx format)
    if (/^\d{6}$/.test(codeClean)) {
      verified = await totp.verify(payload.sub, codeClean);
    } else if (/^[a-f0-9]{4}-[a-f0-9]{4}$/i.test(codeClean)) {
      verified = await totp.verifyBackupCode(payload.sub, codeClean);
    }

    if (!verified) return c.json({ error: "Invalid code" }, 401);

    const tenant = tenants.getTenantByOwner(payload.sub);
    const token = await issueJWT(
      { sub: payload.sub, tid: payload.tid, role: "owner" },
      opts.jwtSecret,
      86400 * 30
    );

    void chain.emit("AUTH_SUCCESS", {
      event: "signin_totp", tenantId: payload.tid, email: payload.sub,
    }, { severity: "LOW", source: "public-signin" });

    return c.json({
      ok: true,
      tenant: tenant ? { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: tenant.plan } : null,
      token,
      dashboard: "/_sovereign/dashboard",
    });
  });

  //  GET /_sovereign/auth/magic — Magic link handler (click from email)
  app.get("/_sovereign/auth/magic", async (c) => {
    if (!magicLink) return c.json({ error: "Magic links not configured" }, 503);

    const token = c.req.query("token") ?? "";
    const email = c.req.query("email") ?? "";
    const purpose = (c.req.query("purpose") ?? "signin") as "signin" | "signup";

    if (!token || !email) {
      return c.html(magicResultPage("Invalid link", "This magic link is missing required parameters.", false));
    }

    const result = await magicLink.verifyMagicToken(token, email, purpose);
    if (!result.valid) {
      return c.html(magicResultPage("Link expired or invalid", result.error ?? "Please request a new sign-in link.", false));
    }

    const normalized = email.trim().toLowerCase();

    // Signup: provision tenant
    if (purpose === "signup") {
      const existing = tenants.getTenantByOwner(normalized);
      if (existing) {
        // Already signed up — just sign them in
        const jwt = await issueJWT(
          { sub: normalized, tid: existing.id, role: "owner", verified: true } as any,
          opts.jwtSecret, 86400 * 30
        );
        return c.html(magicResultPage("Welcome back!", "Redirecting to dashboard…", true, jwt, existing.id));
      }
      // New signup — we need the org name, redirect to a completion page
      const pendingToken = await issueJWT(
        { sub: normalized, role: "owner", scope: "signup_verified" } as any,
        opts.jwtSecret, 300
      );
      return c.html(magicResultPage("Email verified!", "Completing your signup…", true, undefined, undefined, pendingToken));
    }

    // Signin: check TOTP
    const tenant = tenants.getTenantByOwner(normalized);
    if (!tenant) {
      return c.html(magicResultPage("No account found", "No account exists for this email. Please sign up first.", false));
    }

    if (totp?.isEnabled(normalized)) {
      const pendingToken = await issueJWT(
        { sub: normalized, tid: tenant.id, role: "owner", scope: "totp_pending" } as any,
        opts.jwtSecret, 300
      );
      // Redirect to TOTP step
      return c.html(magicResultPage("2FA Required", "Redirecting to enter your authenticator code…", true, undefined, undefined, undefined, pendingToken));
    }

    // No TOTP — issue full JWT
    const jwt = await issueJWT(
      { sub: normalized, tid: tenant.id, role: "owner" },
      opts.jwtSecret, 86400 * 30
    );

    void chain.emit("AUTH_SUCCESS", {
      event: "magic_link_signin", tenantId: tenant.id, email: normalized,
    }, { severity: "LOW", source: "magic-link" });

    return c.html(magicResultPage("Signed in!", "Redirecting to dashboard…", true, jwt, tenant.id));
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
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#050a10;--surface:#0d151f;--card:#111b2a;--raised:#162236;--border:#1e293b;
--brand:#0df23b;--brand-bright:#3dff62;--quantum:#a78bfa;
--t-primary:#f0f2f5;--t-secondary:#94a3b8;--t-muted:#475569;
--font:'Space Grotesk',sans-serif;--mono:'JetBrains Mono',monospace;
--radius:8px;--radius-lg:12px}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--t-primary);font-family:var(--font);
min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);
padding:40px;width:100%;max-width:440px;margin:20px}
.back{display:inline-block;margin-bottom:20px;color:var(--t-muted);text-decoration:none;font-size:14px;transition:color .2s}
.back:hover{color:var(--t-secondary)}
h1{font-size:24px;font-weight:700;margin-bottom:6px;letter-spacing:-.02em}
.sub{color:var(--t-secondary);font-size:14px;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:500;color:var(--t-secondary);margin-bottom:6px}
input{width:100%;padding:12px 14px;background:var(--raised);border:1px solid var(--border);
border-radius:var(--radius);color:var(--t-primary);font-family:var(--font);font-size:15px;
outline:none;transition:border-color .2s;margin-bottom:18px}
input:focus{border-color:var(--brand)}
input::placeholder{color:var(--t-muted)}
button{width:100%;padding:14px;background:var(--brand);color:#050a10;border:none;border-radius:var(--radius);
font-family:var(--font);font-size:15px;font-weight:600;cursor:pointer;transition:all .2s}
button:hover{background:var(--brand-bright);box-shadow:0 0 24px rgba(13,242,59,.2)}
button:disabled{opacity:.6;cursor:not-allowed}
.msg{margin-top:16px;padding:14px;border-radius:var(--radius);font-size:14px;font-family:var(--mono);
line-height:1.6;display:none}
.msg.ok{display:block;background:rgba(13,242,59,.08);border:1px solid rgba(13,242,59,.2);color:var(--brand)}
.msg.err{display:block;background:rgba(255,80,80,.1);border:1px solid rgba(255,80,80,.25);color:#ff6b6b}
.link{color:var(--brand);text-decoration:none;font-size:14px}
.link:hover{text-decoration:underline}
.footer{margin-top:20px;text-align:center;color:var(--t-muted);font-size:13px}
</style>
<style>
.step{display:none}.step.active{display:block}
.code-row{display:flex;gap:8px;margin-bottom:18px}
.code-row input{width:44px;text-align:center;font-family:var(--mono);font-size:18px;font-weight:600;padding:12px 0}
</style>
<script>
var t=localStorage.getItem('sovereign_token');
if(t)location.replace('/_sovereign/dashboard');
</script>
</head>
<body>
<div class="card">
  <a href="/" class="back">&larr; Back to Sovereignly</a>

  <!-- Step 1: Name + Email -->
  <div class="step active" id="s1">
    <h1>Create your account</h1>
    <p class="sub">Free tier — 10K events/mo, 3 functions, instant activation.</p>
    <form id="f1">
      <label for="name">Organization / Project Name</label>
      <input id="name" name="name" type="text" placeholder="Acme Corp" required autocomplete="organization">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" placeholder="you@company.com" required autocomplete="email">
      <button type="submit" id="btn1">Create Account</button>
    </form>
  </div>

  <!-- Step 2: Verify Email -->
  <div class="step" id="s2">
    <div style="text-align:center;margin-bottom:16px">
      <div style="width:48px;height:48px;border-radius:50%;background:rgba(13,242,59,.1);border:2px solid rgba(13,242,59,.2);display:inline-flex;align-items:center;justify-content:center">
        <svg width="22" height="22" fill="none" stroke="#0df23b" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
      </div>
    </div>
    <h1 style="text-align:center">Check your email</h1>
    <p class="sub" style="text-align:center">We sent a verification link to <strong id="emailShow" style="color:var(--brand)"></strong></p>
    <p style="color:var(--t-muted);font-size:12px;text-align:center;margin-bottom:20px">Click the link in your email, or enter the code below.</p>
    <form id="f2">
      <div class="code-row">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
        <input type="text" maxlength="1" class="ci" inputmode="numeric" autocomplete="off">
      </div>
      <button type="submit" id="btn2">Verify & Create</button>
    </form>
  </div>

  <div id="msg" class="msg"></div>
  <div class="footer">Already have an account? <a href="/_sovereign/signin" class="link">Sign in</a></div>
</div>
<script>
let savedName='',savedEmail='';
const msg=document.getElementById('msg');
function showErr(t){msg.className='msg err';msg.textContent=t;}
function showOk(t){msg.className='msg ok';msg.textContent=t;}
function hideMsg(){msg.className='msg';}
function showStep(n){document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));document.getElementById('s'+n).classList.add('active');}

const cis=document.querySelectorAll('.ci');
cis.forEach((ci,i)=>{
  ci.addEventListener('input',()=>{if(ci.value&&i<cis.length-1)cis[i+1].focus();});
  ci.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!ci.value&&i>0)cis[i-1].focus();});
  ci.addEventListener('paste',e=>{const t=(e.clipboardData||window.clipboardData).getData('text').replace(/\\D/g,'');
    if(t.length===6){e.preventDefault();cis.forEach((c,j)=>{c.value=t[j]||'';});cis[5].focus();}});
});

// Step 1: Submit signup
document.getElementById('f1').addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();const btn=document.getElementById('btn1');
  btn.disabled=true;btn.textContent='Creating…';
  savedName=document.getElementById('name').value;
  savedEmail=document.getElementById('email').value;
  try{
    const r=await fetch('/_sovereign/signup',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({name:savedName,email:savedEmail})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Signup failed');
    if(d.requiresVerification){
      document.getElementById('emailShow').textContent=savedEmail;
      showStep(2);cis[0].focus();
    }else if(d.token){
      localStorage.setItem('sovereign_token',d.token);
      localStorage.setItem('sovereign_tenant',d.tenant.id);
      location.href='/_sovereign/dashboard';
    }
  }catch(err){showErr(err.message);btn.disabled=false;btn.textContent='Create Account';}
});

// Step 2: Verify code
document.getElementById('f2').addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();const btn=document.getElementById('btn2');
  btn.disabled=true;btn.textContent='Verifying…';
  const code=Array.from(cis).map(c=>c.value).join('');
  if(code.length!==6){showErr('Enter all 6 digits');btn.disabled=false;btn.textContent='Verify & Create';return;}
  try{
    const r=await fetch('/_sovereign/signup/verify',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({name:savedName,email:savedEmail,code})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Verification failed');
    localStorage.setItem('sovereign_token',d.token);
    localStorage.setItem('sovereign_tenant',d.tenant.id);
    showOk('Account created! Redirecting…');
    setTimeout(()=>location.href='/_sovereign/dashboard',1000);
  }catch(err){showErr(err.message);btn.disabled=false;btn.textContent='Verify & Create';}
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
      const normalized = email.trim().toLowerCase();

      // If magic-link is available, send verification code first (don't provision yet)
      if (magicLink) {
        const codeResult = await magicLink.requestCode(normalized, "signup");
        if (!codeResult.ok) return c.json({ error: codeResult.error }, 429);

        return c.json({
          ok: true,
          requiresVerification: true,
          message: "Verification code sent to your email. Please verify to complete signup.",
        }, 200);
      }

      // Fallback: provision immediately (when magic-link not configured)
      const tenant = await tenants.provision({
        name:    name.trim(),
        ownerId: normalized,
        plan:    "free",
      });

      const token = await issueJWT(
        { sub: normalized, tid: tenant.id, role: "owner" },
        opts.jwtSecret,
        86400 * 30
      );

      void chain.emit("CONFIG_CHANGE", {
        event: "public_signup", tenantId: tenant.id, email: normalized, plan: "free", ip,
      }, "LOW");

      return c.json({
        ok: true,
        tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: tenant.plan },
        token,
        dashboard: `/_sovereign/dashboard`,
      }, 201);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  //  Verify signup email
  app.post("/_sovereign/signup/verify", async (c) => {
    if (!magicLink) return c.json({ error: "Email verification not configured" }, 503);

    const body = await c.req.json().catch(() => ({})) as any;
    const { name, email, code } = body;
    if (!email?.trim() || !code?.trim()) return c.json({ error: "Email and code required" }, 400);

    const normalized = email.trim().toLowerCase();
    const result = await magicLink.verifyCode(normalized, code, "signup");
    if (!result.valid) return c.json({ error: result.error }, 401);

    // Now provision the tenant
    const tenant = await tenants.provision({
      name:    (name ?? "").trim() || normalized.split("@")[0],
      ownerId: normalized,
      plan:    "free",
    });

    const token = await issueJWT(
      { sub: normalized, tid: tenant.id, role: "owner", verified: true } as any,
      opts.jwtSecret,
      86400 * 30
    );

    const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
    void chain.emit("CONFIG_CHANGE", {
      event: "public_signup_verified", tenantId: tenant.id, email: normalized, plan: "free", ip,
    }, "LOW");

    return c.json({
      ok: true,
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: tenant.plan },
      token,
      dashboard: `/_sovereign/dashboard`,
    }, 201);
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

// ── Magic Link Result Page (handles redirects after clicking email link) ──────

function magicResultPage(
  title: string,
  message: string,
  success: boolean,
  token?: string,
  tenantId?: string,
  signupPendingToken?: string,
  totpPendingToken?: string,
): string {
  const icon = success
    ? `<div style="width:56px;height:56px;border-radius:50%;background:rgba(13,242,59,.1);border:2px solid rgba(13,242,59,.3);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
        <svg width="24" height="24" fill="none" stroke="#0df23b" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>
       </div>`
    : `<div style="width:56px;height:56px;border-radius:50%;background:rgba(255,80,80,.1);border:2px solid rgba(255,80,80,.3);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
        <svg width="24" height="24" fill="none" stroke="#ff6b6b" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
       </div>`;

  let script = "";
  if (token && tenantId) {
    script = `<script>
localStorage.setItem('sovereign_token','${token}');
localStorage.setItem('sovereign_tenant','${tenantId}');
setTimeout(()=>location.href='/_sovereign/dashboard',1500);
</script>`;
  } else if (signupPendingToken) {
    script = `<script>
sessionStorage.setItem('signup_pending','${signupPendingToken}');
setTimeout(()=>location.href='/_sovereign/signup?verified=1',1000);
</script>`;
  } else if (totpPendingToken) {
    script = `<script>
sessionStorage.setItem('totp_pending','${totpPendingToken}');
setTimeout(()=>location.href='/_sovereign/signin?step=totp',1000);
</script>`;
  } else if (!success) {
    script = `<script>setTimeout(()=>location.href='/_sovereign/signin',3000);</script>`;
  }

  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${title} — Sovereignly</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body style="margin:0;background:#050a10;color:#f0f2f5;font-family:'Space Grotesk',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;-webkit-font-smoothing:antialiased">
<div style="text-align:center;background:#111b2a;border:1px solid #1e293b;border-radius:16px;padding:48px 40px;max-width:440px;width:100%;margin:20px">
  ${icon}
  <h1 style="font-size:22px;font-weight:700;margin:0 0 8px;letter-spacing:-.02em">${title}</h1>
  <p style="color:#94a3b8;font-size:14px;margin:0;line-height:1.5">${message}</p>
  ${!success ? '<a href="/_sovereign/signin" style="display:inline-block;margin-top:24px;padding:12px 32px;background:#0df23b;color:#050a10;font-weight:600;text-decoration:none;border-radius:8px;font-size:14px">Try again</a>' : '<div style="margin-top:24px"><div style="width:20px;height:20px;border:2px solid #0df23b;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;display:inline-block"></div></div><style>@keyframes spin{to{transform:rotate(360deg)}}</style>'}
</div>
${script}
</body></html>`;
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
