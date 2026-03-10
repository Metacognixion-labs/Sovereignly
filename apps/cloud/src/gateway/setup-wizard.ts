/**
 * Sovereignly  Admin Setup Wizard
 *
 * First-run detection + initial admin provisioning.
 * Locks out after first admin is created.
 */

import type { Hono } from "hono";
import type { TenantManager } from "../tenants/manager.ts";
import type { MagicLinkService } from "../../../oss/src/auth/magic-link.ts";
import { issueJWT } from "../zero-trust.ts";

export interface SetupWizardOpts {
  tenants:   TenantManager;
  magicLink: MagicLinkService;
  jwtSecret: string;
}

let setupComplete = false;

export function isSetupComplete(tenants: TenantManager): boolean {
  if (setupComplete) return true;
  const count = tenants.getActiveCount();
  if (count > 0) {
    setupComplete = true;
    return true;
  }
  return false;
}

export function registerSetupWizard(app: Hono, opts: SetupWizardOpts) {

  //  GET /_sovereign/setup — serves the wizard UI
  app.get("/_sovereign/setup", (c) => {
    if (isSetupComplete(opts.tenants)) {
      return c.redirect("/");
    }
    return c.html(SETUP_HTML);
  });

  //  POST /_sovereign/setup — processes setup
  app.post("/_sovereign/setup", async (c) => {
    if (isSetupComplete(opts.tenants)) {
      return c.json({ error: "Setup already completed" }, 403);
    }

    const body = await c.req.json().catch(() => ({})) as any;
    const { name, email, step, code } = body;

    // Step 1: Submit org name + email → send verification code
    if (step === "email") {
      if (!name?.trim()) return c.json({ error: "Organization name is required" }, 400);
      if (!email?.trim() || !email.includes("@")) return c.json({ error: "Valid email is required" }, 400);

      const result = await opts.magicLink.requestCode(email.trim().toLowerCase(), "signup");
      if (!result.ok) return c.json({ error: result.error }, 429);

      return c.json({ ok: true, message: "Verification code sent to your email" });
    }

    // Step 2: Verify code → provision admin tenant
    if (step === "verify") {
      if (!email?.trim() || !code?.trim()) return c.json({ error: "Email and code required" }, 400);

      const normalized = email.trim().toLowerCase();
      const verify = await opts.magicLink.verifyCode(normalized, code.trim(), "signup");
      if (!verify.valid) return c.json({ error: verify.error }, 401);

      // Provision admin tenant
      const tenant = await opts.tenants.provision({
        name:    name?.trim() || "Admin",
        ownerId: normalized,
        plan:    "enterprise",
      });

      // Issue admin JWT (30-day)
      const token = await issueJWT(
        { sub: normalized, tid: tenant.id, role: "owner" },
        opts.jwtSecret,
        86400 * 30
      );

      setupComplete = true;

      return c.json({
        ok: true,
        tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: tenant.plan },
        token,
        dashboard: "/_sovereign/dashboard",
      });
    }

    return c.json({ error: "Invalid step" }, 400);
  });
}

// ── Setup Wizard HTML ─────────────────────────────────────────────────────────

const SETUP_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Setup — Sovereignly</title>
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
.wizard{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);
padding:48px;width:100%;max-width:520px;margin:20px}
.badge{display:inline-block;padding:4px 12px;background:rgba(13,242,59,.1);border:1px solid rgba(13,242,59,.2);
border-radius:20px;font-size:11px;font-weight:600;color:var(--brand);letter-spacing:.05em;margin-bottom:16px}
h1{font-size:28px;font-weight:700;margin-bottom:8px;letter-spacing:-.03em}
.sub{color:var(--t-secondary);font-size:15px;margin-bottom:32px;line-height:1.5}
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
.step{display:none}.step.active{display:block}
.steps{display:flex;gap:8px;margin-bottom:28px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--border);transition:background .3s}
.dot.active{background:var(--brand)}
.code-inputs{display:flex;gap:8px;justify-content:center;margin-bottom:18px}
.code-inputs input{width:48px;text-align:center;font-family:var(--mono);font-size:20px;font-weight:600;letter-spacing:.05em}
</style>
</head>
<body>
<div class="wizard">
  <span class="badge">FIRST-TIME SETUP</span>
  <h1>Welcome to Sovereignly</h1>
  <p class="sub">Set up your admin account to get started. This wizard only runs once.</p>
  <div class="steps"><div class="dot active" id="dot1"></div><div class="dot" id="dot2"></div></div>

  <!-- Step 1: Org + Email -->
  <div class="step active" id="step1">
    <form id="f1">
      <label for="name">Organization Name</label>
      <input id="name" type="text" placeholder="Acme Corp" required autocomplete="organization">
      <label for="email">Admin Email</label>
      <input id="email" type="email" placeholder="admin@company.com" required autocomplete="email">
      <button type="submit" id="btn1">Send Verification Code</button>
    </form>
  </div>

  <!-- Step 2: Verify Code -->
  <div class="step" id="step2">
    <p style="color:var(--t-secondary);font-size:14px;margin-bottom:18px">
      Enter the 6-digit code sent to <strong id="emailDisplay" style="color:var(--brand)"></strong>
    </p>
    <form id="f2">
      <div class="code-inputs">
        <input type="text" maxlength="1" class="ci" autocomplete="off" inputmode="numeric">
        <input type="text" maxlength="1" class="ci" autocomplete="off" inputmode="numeric">
        <input type="text" maxlength="1" class="ci" autocomplete="off" inputmode="numeric">
        <input type="text" maxlength="1" class="ci" autocomplete="off" inputmode="numeric">
        <input type="text" maxlength="1" class="ci" autocomplete="off" inputmode="numeric">
        <input type="text" maxlength="1" class="ci" autocomplete="off" inputmode="numeric">
      </div>
      <button type="submit" id="btn2">Complete Setup</button>
    </form>
  </div>

  <div id="msg" class="msg"></div>
</div>

<script>
const f1=document.getElementById('f1'),f2=document.getElementById('f2');
const btn1=document.getElementById('btn1'),btn2=document.getElementById('btn2');
const msg=document.getElementById('msg');
const step1=document.getElementById('step1'),step2=document.getElementById('step2');
const dot1=document.getElementById('dot1'),dot2=document.getElementById('dot2');
let savedName='',savedEmail='';

function showMsg(text,type){msg.className='msg '+type;msg.textContent=text;}
function hideMsg(){msg.className='msg';}

// Step 1: Send code
f1.addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();btn1.disabled=true;btn1.textContent='Sending…';
  savedName=document.getElementById('name').value;
  savedEmail=document.getElementById('email').value;
  try{
    const r=await fetch('/_sovereign/setup',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({step:'email',name:savedName,email:savedEmail})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Failed to send code');
    step1.classList.remove('active');step2.classList.add('active');
    dot2.classList.add('active');
    document.getElementById('emailDisplay').textContent=savedEmail;
    document.querySelectorAll('.ci')[0].focus();
  }catch(err){
    showMsg(err.message,'err');btn1.disabled=false;btn1.textContent='Send Verification Code';
  }
});

// Code input auto-advance
const cis=document.querySelectorAll('.ci');
cis.forEach((ci,i)=>{
  ci.addEventListener('input',()=>{
    if(ci.value&&i<cis.length-1)cis[i+1].focus();
  });
  ci.addEventListener('keydown',e=>{
    if(e.key==='Backspace'&&!ci.value&&i>0)cis[i-1].focus();
  });
  ci.addEventListener('paste',e=>{
    const text=(e.clipboardData||window.clipboardData).getData('text').replace(/\\D/g,'');
    if(text.length===6){e.preventDefault();cis.forEach((c,j)=>{c.value=text[j]||'';});cis[5].focus();}
  });
});

// Step 2: Verify
f2.addEventListener('submit',async e=>{
  e.preventDefault();hideMsg();btn2.disabled=true;btn2.textContent='Verifying…';
  const code=Array.from(cis).map(c=>c.value).join('');
  if(code.length!==6){showMsg('Enter all 6 digits','err');btn2.disabled=false;btn2.textContent='Complete Setup';return;}
  try{
    const r=await fetch('/_sovereign/setup',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({step:'verify',name:savedName,email:savedEmail,code})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Verification failed');
    localStorage.setItem('sovereign_token',d.token);
    localStorage.setItem('sovereign_tenant',d.tenant.id);
    showMsg('Setup complete! Redirecting to dashboard…','ok');
    setTimeout(()=>location.href='/_sovereign/dashboard',1500);
  }catch(err){
    showMsg(err.message,'err');btn2.disabled=false;btn2.textContent='Complete Setup';
  }
});
</script>
</body>
</html>`;
