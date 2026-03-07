# ⬡ Sovereignly v3.0.1 — API Reference

**Base URL:** `https://sovereignly.fly.dev` (or your custom domain)
**Auth header:** `Authorization: Bearer <jwt>` or `x-sovereign-token: Bearer <admin_token>`
**73 endpoints** across 9 modules

---

## Authentication

All admin endpoints accept `x-sovereign-token: Bearer <ADMIN_TOKEN>`.
Tenant endpoints accept JWT issued via `/signup`, `/auth/token`, or any auth flow.

---

## Public (No Auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Landing page (HTML) |
| GET | `/_sovereign/health` | System health + subsystem status. Returns `503` if degraded. |
| GET | `/_sovereign/metrics` | JSON or Prometheus (`?format=prometheus`) metrics |
| GET | `/_sovereign/pricing` | Plan features, pricing, CTAs |
| POST | `/_sovereign/signup` | **Free-tier signup.** Body: `{ name, email }` → Returns `{ tenant, token }` |
| GET | `/_sovereign/dashboard` | Admin dashboard SPA |

### POST /_sovereign/signup

```json
// Request
{ "name": "Acme Corp", "email": "alice@acme.com" }

// Response 201
{
  "ok": true,
  "tenant": { "id": "org_abc123", "name": "Acme Corp", "plan": "free" },
  "token": "eyJ...",
  "nextSteps": ["Save the token", "Install the SDK", "Start emitting events"]
}
```

---

## Auth Module `/_sovereign/auth/*`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/token` | Admin | Issue JWT. Body: `{ sub, role, ttl }` |
| GET | `/auth/passkeys/register/begin` | JWT | Start WebAuthn registration |
| POST | `/auth/passkeys/register/complete` | JWT | Complete passkey registration |
| GET | `/auth/passkeys/login/begin` | Public | Start passkey login |
| POST | `/auth/passkeys/login/complete` | Public | Complete passkey login → JWT |
| GET | `/auth/oauth/:provider/start` | Public | OAuth redirect (google\|github\|discord\|meta) |
| GET | `/auth/oauth/:provider/callback` | Public | OAuth callback → JWT |
| GET | `/auth/siwe/nonce` | Public | Get SIWE nonce |
| POST | `/auth/siwe/verify` | Public | Verify SIWE signature → JWT |
| GET | `/auth/solana/nonce` | Public | Get Solana nonce |
| POST | `/auth/solana/verify` | Public | Verify Solana wallet sig → JWT |
| POST | `/auth/refresh` | JWT | Refresh token |
| POST | `/auth/logout` | JWT | Invalidate session |
| GET | `/auth/me` | JWT | Current user info |
| GET | `/auth/users` | Admin | List users |
| PATCH | `/auth/users/:id` | Admin | Update user role/plan |
| GET | `/auth/stats` | Admin | Auth statistics |

---

## Chain Module `/_sovereign/chain/*`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/chain/stats` | Admin | Block count, event count, anchored, critical |
| GET | `/chain/tip` | Admin | Latest block |
| GET | `/chain/blocks` | Admin | List blocks. Query: `?limit=20&offset=0` |
| GET | `/chain/block/:index` | Admin | Block by index |
| GET | `/chain/events` | Admin | Query events. Query: `?type=AUTH_SUCCESS&severity=HIGH&since=<ts>&limit=50` |
| GET | `/chain/verify` | Admin | Full chain integrity verification (O(n)) |
| GET | `/chain/anchor/latest` | Admin | Latest omnichain attestation receipts |
| GET | `/chain/anchor/schema` | Admin | EAS schema UID and config |
| POST | `/chain/block` | Peer | Ingest block from peer node |

---

## Compliance `/_sovereign/compliance/*`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/compliance/soc2` | Admin | SOC2 Type II readiness report |
| GET | `/compliance/iso27001` | Admin | ISO 27001:2022 report |
| GET | `/compliance/report` | Admin | Generic: `?standard=NIST\|HIPAA\|GDPR\|SOC2\|ISO27001` |
| GET | `/compliance/export` | Admin | Full audit trail export |

---

## Tenants `/_sovereign/tenants/*`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/tenants` | JWT/Admin | Provision tenant. Body: `{ name, plan?, domain? }` |
| GET | `/tenants` | Admin | List all tenants + MRR + plan breakdown |
| GET | `/tenants/:id` | Owner/Admin | Tenant detail + chain stats |
| PATCH | `/tenants/:id` | Owner/Admin | Update tenant (plan changes = admin only) |
| DELETE | `/tenants/:id` | Admin | Suspend tenant. Body: `{ reason }` |
| GET | `/tenants/:id/stats` | Owner/Admin | Usage stats, billing, chain metrics |
| GET | `/tenants/:id/chain/events` | Owner/Admin | Tenant audit events. Query: `?type=&severity=&since=&limit=` |
| GET | `/tenants/:id/chain/report` | Owner/Admin | Compliance report (Starter+ only) |
| POST | `/tenants/:id/chain/export` | Owner/Admin | Portable chain export with verify instructions |

---

## Webhooks `/_sovereign/tenants/:id/webhooks/*`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/tenants/:id/webhooks` | Owner/Admin | Register webhook. Body: `{ url, events?, secret? }` |
| GET | `/tenants/:id/webhooks` | Owner/Admin | List webhooks (secrets redacted) |
| DELETE | `/tenants/:id/webhooks/:whId` | Owner/Admin | Delete webhook |
| POST | `/tenants/:id/webhooks/:whId/test` | Owner/Admin | Test delivery |

### Webhook events

| Event | Trigger |
|-------|---------|
| `anchor_completed` | Omnichain attestation succeeded |
| `anchor_failed` | Attestation error |
| `anomaly_detected` | Brute-force, recon, rate limit |
| `compliance_report` | SOC2/ISO report generated |
| `tenant_event` | Any chain event (high volume) |
| `*` | All events |

Payloads signed with `X-Sovereign-Signature: sha256=<hmac>`. Verify with your webhook secret.

---

## Billing `/_sovereign/billing/*`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/billing/checkout` | JWT | Create Stripe checkout. Body: `{ tenantId, plan, email? }` |
| POST | `/billing/portal` | JWT | Stripe customer portal. Body: `{ tenantId, returnUrl }` |
| GET | `/billing/subscription/:tenantId` | JWT | Current subscription status |
| POST | `/billing/webhook` | Stripe sig | Stripe webhook (no auth — signature verified) |

---

## SDK Ingest `/_sovereign/sdk/events`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/sdk/events` | Bearer + x-org-id | Batch event ingest (max 100/call) |

```json
// Headers
x-org-id: org_abc123
Authorization: Bearer <api_key>

// Request
{ "events": [
  { "type": "USER_LOGIN", "payload": { "userId": "u1", "method": "passkey" }, "severity": "LOW" },
  { "type": "DATA_ACCESS", "payload": { "resource": "/api/users" }, "severity": "LOW" }
]}

// Response — rate limit headers included
{ "results": [
  { "eventId": "uuid", "timestamp": 1709654400000 },
  { "eventId": "uuid", "timestamp": 1709654400001 }
]}
```

Rate limits per plan: Free 100/min, Starter 1K/min, Growth 10K/min, Enterprise 50K/min.

---

## Self-Service

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/signup` | Public | Free-tier signup → tenant + JWT |
| POST | `/signup/upgrade` | JWT | Create Stripe checkout for upgrade |
| GET | `/me` | JWT/Admin | Current user + tenant context |
| GET | `/pricing` | Public | Structured pricing data |

---

## Functions (Serverless)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/functions` | Admin | Deploy function. Body: `{ id, route, code, methods, env }` |
| GET | `/functions` | Admin | List deployed functions |
| GET | `/functions/:id` | Admin | Function detail |
| DELETE | `/functions/:id` | Admin | Delete function |
| * | `/<route>` | Public | Invoke deployed function by route |

---

## KV Store

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/kv/:ns/:key` | Admin | Get value |
| PUT | `/kv/:ns/:key` | Admin | Set value. Body: `{ value, ttl? }` |
| DELETE | `/kv/:ns/:key` | Admin | Delete key |
| GET | `/kv/:ns` | Admin | List keys. Query: `?prefix=` |

---

## Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/platform/stats` | Admin | Full platform metrics (tenants, MRR, global root) |
| GET | `/ops` | Admin | System status (rate limiter, webhooks, HTTP stats) |

---

*Sovereignly v3.0.1 · MetaCognixion · 73 endpoints · 3 dependencies · MIT License*
