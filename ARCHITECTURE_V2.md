> **Archive document** — Historical decision log for v2 → v3 migration. Do not update.

# METACOGNIXION — GENERATIONAL ARCHITECTURE
## The Dominant Design | March 2026

---

## THE CORE CHALLENGE

We have been building SovereignCloud as a product.
The generational opportunity is to build it as a PROTOCOL.

The difference:

```
PRODUCT THINKING              │  PROTOCOL THINKING
──────────────────────────────┼──────────────────────────────────────
"Switch from Cloudflare to us"│  "Add sovereignty to whatever you run"
Compete for runtime market    │  Become infrastructure for compliance market
One customer = one migration  │  One SDK install = immediate revenue
TAM: $6.8B serverless         │  TAM: $50B+ (every company needs SOC2)
Ceiling: $100M ARR            │  Ceiling: $10B+ (Stripe analogy)
```

---

## THE FIVE ENGINES

Everything we have built, correctly named:

```
┌─────────────────────────────────────────────────────────────────────┐
│                   METACOGNIXION PROTOCOL STACK                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ENGINE 1: SovereignChain Protocol                                   │
│  ─────────────────────────────────                                   │
│  The immutable compliance ledger. Standalone. Language-agnostic.    │
│  ANY app on ANY stack writes events → gets SOC2 evidence.           │
│  Distribution: npm SDK + Docker + JSON-RPC API                      │
│  Revenue model: $49–499/org/mo (Drata is $25K/yr for worse)        │
│  Status: BUILT ✓ — needs SDK extraction                             │
│                                                                       │
│  ENGINE 2: SovereignAuth                                             │
│  ────────────────────────                                            │
│  The identity layer. Auth events go on-chain automatically.         │
│  Passkeys PRIMARY. OAuth social. SIWE + Solana wallet.              │
│  Distribution: npm SDK + hosted service + Docker                    │
│  Revenue model: $0.02/MAU (Auth0 charges $0.07)                    │
│  Status: PARTIAL — missing Passkeys (the primary method)           │
│                                                                       │
│  ENGINE 3: SovereignRuntime                                          │
│  ──────────────────────────                                          │
│  Bun serverless. Composes Engine 1 + 2.                             │
│  Our reference implementation of what sovereign infra looks like.   │
│  Revenue model: $49–2000/mo managed hosting                         │
│  Status: BUILT ✓                                                    │
│                                                                       │
│  ENGINE 4: SovereignGateway  ← DOES NOT EXIST YET                  │
│  ──────────────────────────────────────────────────                 │
│  Reverse proxy + auth enforcement + rate limiting + chain logging.  │
│  Sits in front of ANY existing infrastructure.                      │
│  Deploy it in front of AWS Lambda / Vercel / Railway.               │
│  All requests get chain-logged. Zero migration required.            │
│  Revenue model: $99/mo — highest value, lowest friction             │
│  Status: MISSING — this is the fastest path to $1M ARR            │
│                                                                       │
│  ENGINE 5: SovereignOS  ← DOES NOT EXIST YET                       │
│  ──────────────────────────────────────────────                     │
│  The unified control plane. Manages all engines across tenants.     │
│  Think: Heroku Dashboard + Datadog + Drata rolled into one.         │
│  Revenue model: Platform fee, included in Growth+                   │
│  Status: MISSING — needed for managed hosting at scale             │
│                                                                       │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 0: Settlement & Proof                                         │
│  Meridian Ledger — every 100 blocks (fast, cheap, ours)            │
│  Ethereum Mainnet — every 1000 blocks (credibility, $0.50/anchor)  │
│  Both run same AuditAnchor.sol. One contract, two chains.          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## THE THREE CHALLENGES

### CHALLENGE 1: PASSKEYS, NOT EMAIL OTP

**Current assumption:** Email OTP is a reasonable auth primitive.

**Why it's wrong for a sovereign platform:**

Email OTP requires:
- External SMTP delivery (Resend, SES, Postmark) — third-party dependency
- The user's email provider to not be down
- Deliverability tuning, spam reputation management
- A dependency on Google/Microsoft/Apple just to receive a 6-digit code

**The dominant alternative: WebAuthn Passkeys (FIDO2)**

```
How it works:
  Register:  Browser generates keypair in TPM/Secure Enclave
             Public key stored on server
             Private key NEVER leaves device
  
  Login:     Server sends challenge
             Device signs with private key (FaceID/TouchID/Windows Hello)
             Server verifies with stored public key
             Zero external calls. Zero SMTP. Zero phishing possible.

Dependencies: NONE
  - navigator.credentials API (all browsers since 2022)
  - Web Crypto API (we already use this)
  - CBOR decoding for attestation (200 lines, we can own it)

Security: SUPERIOR to every other method
  - Domain-bound (cannot be phished to fake site)
  - Biometric or hardware-backed
  - NIST 800-63B AAL3 compliant
  - Already passes SOC2 CC6.1 authentication controls

Market timing: RIGHT NOW
  Apple added passkeys 2022, Google 2022, Microsoft 2022
  GitHub launched passkeys 2023, Google made them default 2023
  This is where auth is going. We build it first as a sovereign stack.

What we build:
  src/auth/passkeys.ts  — WebAuthn server-side verification
                          (CBOR decode, attestation verify, assertion verify)
  Frontend UI           — One-click "Sign in with Face ID / Touch ID"
```

---

### CHALLENGE 2: THE CHAIN SDK IS THE REVENUE FLYWHEEL

**Current assumption:** Customers must run SovereignCloud to use SovereignChain.

**Why this caps our market:**

Every company that needs SOC2 compliance is a potential customer.
There are 200,000+ companies currently paying for SOC2 compliance tooling.
Very few will migrate their serverless infrastructure.
All of them will install an npm package.

**The correct architecture:**

```typescript
// Any existing app — Next.js, Express, Django, Laravel, Rails
import { SovereignChain } from '@metacognixion/chain-sdk';

const chain = new SovereignChain({
  endpoint: 'https://chain.metacognixion.com',
  orgId: 'org_xxx',
  apiKey: 'sk_xxx',
});

// Now ANY event is compliance-audited
await chain.emit('USER_LOGIN', { userId, ip, method: 'oauth' });
await chain.emit('DATA_EXPORT', { userId, recordCount: 1500 });
await chain.emit('CONFIG_CHANGE', { field: 'payment_processor', changedBy: admin });

// SOC2 evidence report — generated instantly
const report = await chain.complianceReport({ type: 'SOC2', period: 'Q4_2025' });
```

The customer replaces Drata ($2,000–25,000/yr) with our SDK ($600/yr).
No infrastructure migration. Installs in 10 minutes.
This is the go-to-market wedge.

---

### CHALLENGE 3: PER-TENANT CHAIN ISOLATION

**Current assumption:** All tenants share one SovereignChain instance.

**Why this blocks enterprise sales:**

Every enterprise customer will ask:
1. "Are our events isolated from other customers?" → NO (currently)
2. "Can your engineers read our audit trail?" → YES (currently)
3. "Can you prove cryptographic isolation?" → NO (currently)

**The correct architecture:**

```
data/
  tenants/
    org_abc123/
      chain.db       ← Per-tenant SQLite chain (encrypted at rest)
      kv.db          ← Per-tenant KV store
      storage/       ← Per-tenant file storage
    org_def456/
      chain.db
      kv.db
      storage/

Global:
  anchor/
    global.db        ← Root-of-roots: Merkle of all tenant chain tips
    
Ethereum anchor payload:
  keccak256(merkle(
    tenant_A_chain_tip,
    tenant_B_chain_tip,
    tenant_C_chain_tip,
    ...
  ))
```

Per-tenant chain DB = per-tenant encryption key (derived from org secret + server key)
Tenant can export their DB file and verify it offline.
Server engineers see encrypted blobs, not event content.
This is cryptographic multi-tenancy. Nobody else ships this.

---

## BUILD ORDER — MAXIMUM VELOCITY

```
WEEK 1 — THE ENGINES
─────────────────────────────────────────────────────
Day 1: Passkeys engine (WebAuthn server-side)
       → src/auth/passkeys.ts
       → Zero deps, pure Web Crypto
       → This replaces email OTP entirely
       
Day 2: Per-tenant isolation refactor
       → data/{tenantId}/ directory structure
       → Tenant provisioning: createTenant(), getTenant()
       → Encryption: per-tenant AES-256-GCM
       
Day 3: Chain SDK extraction
       → packages/chain-sdk/  
       → @metacognixion/chain-sdk on npm
       → 200-line TypeScript, zero deps, works anywhere
       
Day 4: Ethereum dual-anchor
       → src/security/ethereum-anchor.ts
       → Same AuditAnchor.sol, different chain
       → Every 1000 blocks → ~$0.50/anchor
       
Day 5: SovereignGateway  ← HIGHEST VALUE
       → src/gateway/proxy.ts
       → Reverse proxy + chain logging + auth enforcement
       → Works in front of any existing infrastructure
       → This enables "no migration required" sales

WEEK 2 — GO TO MARKET
─────────────────────────────────────────────────────
Day 6: Stripe billing + tenant provisioning API
Day 7: SovereignOS dashboard (React SPA)
Day 8: Docs site + chain-sdk README
Day 9: GitHub release + npm publish
Day 10: Launch
```

---

## THE COMPETITIVE POSITION

```
                    SOVEREIGNTY
                         │
              SovereignCloud
              (where we are)
    ←─────────────────────┼─────────────────────→
MANAGED                   │                    SELF-HOSTED
HOSTING                   │
              AWS Lambda  │
              Cloudflare  │
              Vercel      │
                          │
                      COMPLIANCE
                          │
                    Drata/Vanta
                    (no sovereignty)
                         
With SovereignGateway + Chain SDK:
We expand to fill ALL FOUR QUADRANTS simultaneously.
No competitor is in more than one.
```

---

## WHAT CHANGES IMMEDIATELY

1. **Drop `privy.ts`** — replaced by `passkeys.ts` + `oauth.ts` (already built) + `siwe.ts` (already built)

2. **Add `@noble/hashes` as proper dep** — SIWE currently has a dynamic import hack for keccak256. Fix it.

3. **Rename the project architecture** internally — we are building the MetaCognixion Protocol Stack, not just "SovereignCloud v2"

4. **Create `packages/chain-sdk`** — this is the fastest path to developer adoption and the compliance market

5. **Implement per-tenant provisioning** — blocks all enterprise sales until done

---

## THE ONE-LINE INVESTOR PITCH

> "We are Stripe for compliance infrastructure —
> a protocol that any application embeds to achieve
> cryptographically-verifiable SOC2 compliance,
> anchored to Ethereum."

This is the company that compounds for 20 years.
Not because we built a cheaper Cloudflare.
Because we own the trust layer of the sovereign web.
