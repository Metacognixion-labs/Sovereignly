# ⬡ Sovereignly

**Own your serverless. Every execution cryptographically logged, Merkle-rooted, attested to 5 public blockchains.**

Sovereignly is an open-core compliance infrastructure platform. The core engine is MIT-licensed. The multi-tenant SaaS layer uses the Business Source License.

## Editions

| | **OSS** | **Cloud** |
|---|---|---|
| **License** | MIT | BSL 1.1 (→ MIT after 4 years) |
| **Path** | `apps/oss/` | `apps/cloud/` |
| **Audit chain** | ✓ Ed25519 PoA, Merkle batching | ✓ same |
| **Omnichain attestation** | ✓ EAS/Base, Arbitrum, Solana, Irys, Bitcoin | ✓ same |
| **Auth** | ✓ Passkeys, OAuth, SIWE, Solana wallet | ✓ same |
| **Serverless runtime** | ✓ Bun worker pool | ✓ same |
| **KV store** | ✓ SQLite-backed | ✓ same |
| **Multi-tenancy** | — single tenant | ✓ per-tenant isolated chains |
| **SOC2 / ISO27001 reports** | — | ✓ |
| **Stripe billing** | — | ✓ checkout, portal, webhooks |
| **Self-service signup** | — | ✓ public signup + upgrade |
| **Webhooks** | — | ✓ HMAC-signed, retry, backoff |
| **Zero-trust** | — | ✓ anomaly detection, RBAC |
| **Per-tenant rate limits** | — | ✓ plan-based |
| **Admin dashboard** | — | ✓ |

## Quick Start

### OSS Edition (MIT)

```bash
git clone https://github.com/Metacognixion-labs/Sovereignly.git
cd Sovereignly
bun install

# Generate secrets
export SOVEREIGN_SERVER_KEY=$(openssl rand -hex 32)
export JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_TOKEN=$(openssl rand -hex 16)

# Start
bun run dev
# → http://localhost:8787/_sovereign/health
```

### Cloud Edition (requires license)

```bash
bun run dev:cloud
# → http://localhost:8787/_sovereign/dashboard
```

### Docker

```bash
# OSS
docker build -f apps/oss/Dockerfile -t sovereignly-oss .
docker run -p 8787:8787 -e SOVEREIGN_SERVER_KEY=... sovereignly-oss

# Cloud (with Litestream backup)
docker build -f apps/cloud/Dockerfile -t sovereignly-cloud .
docker run -p 8787:8787 -e SOVEREIGN_SERVER_KEY=... -e LITESTREAM_BUCKET=... sovereignly-cloud
```

## Monorepo Structure

```
sovereignly/
├── packages/
│   ├── core/              MIT — shared types (Block, AuditEvent, Tenant)
│   └── sdk/               MIT — @metacognixion/chain-sdk (npm client)
├── apps/
│   ├── oss/               MIT — single-tenant open-source server
│   │   └── src/
│   │       ├── server.ts        Entry point
│   │       ├── security/        chain.ts, crypto.ts, omnichain-anchor.ts
│   │       ├── auth/            passkeys, OAuth, SIWE, Solana
│   │       ├── gateway/         Hono router, chain routes, auth routes
│   │       ├── kv/              SQLite KV store
│   │       ├── runtime/         Serverless worker pool
│   │       ├── scheduler/       Cron tasks
│   │       ├── storage/         Blob storage
│   │       └── test/            Integration tests
│   └── cloud/             BSL — multi-tenant SaaS (premium)
│       └── src/
│           ├── server.ts        Entry point (extends OSS)
│           ├── compliance.ts    SOC2, ISO27001, HIPAA, GDPR, NIST
│           ├── zero-trust.ts    Anomaly detection, RBAC, secret scanning
│           ├── tenants/         Multi-tenant manager + routes
│           ├── billing/         Stripe integration
│           ├── gateway/         Public signup, tenant rate limiter
│           └── webhooks/        HMAC-signed delivery + retry
├── contracts/             MIT — AuditAnchor.sol (EVM)
├── dashboard/             HTML SPA admin panel
├── deploy/                Fly.io, Docker, Grafana, Litestream
└── API.md                 73 endpoints documented
```

## Dependencies

**3 runtime dependencies.** That's it.

| Package | Why | Size |
|---------|-----|------|
| `hono` | HTTP framework (fastest JS router) | 14KB |
| `@noble/curves` | secp256k1 (EVM), ed25519 (Solana) | 45KB |
| `@noble/hashes` | keccak256, SHA-256, RIPEMD-160 | 25KB |

## Omnichain Attestation

Every audit chain block is sealed and attested to public blockchains:

| Chain | Tier | Annual Cost | Verification |
|-------|------|-------------|-------------|
| EAS / Base | Free+ | $0.18/yr | [base.easscan.org](https://base.easscan.org) |
| EAS / Arbitrum | Starter+ | $0.09/yr | [arbitrum.easscan.org](https://arbitrum.easscan.org) |
| Sign Protocol | Starter+ | $0.05/yr | [scan.sign.global](https://scan.sign.global) |
| Solana Memo | Growth+ | $0.27/yr | [solscan.io](https://solscan.io) |
| Irys | Enterprise | ~$0/yr | [irys.xyz](https://irys.xyz) |
| Bitcoin OP_RETURN | Enterprise | $26/yr | Any block explorer |

**COGS at Growth tier (365 anchors/yr): $0.63/yr** per tenant.

## SDK

```bash
npm install @metacognixion/chain-sdk
```

```typescript
import { SovereignChain } from '@metacognixion/chain-sdk';

const chain = new SovereignChain({
  endpoint: 'https://sovereignly.io',
  orgId:    'org_abc123',
  apiKey:   'sk_...',
});

await chain.emit('USER_LOGIN', { userId: 'u1', method: 'passkey' });
const report = await chain.complianceReport({ type: 'SOC2' });
```

## License

- `packages/`, `apps/oss/`, `contracts/` — [MIT](./LICENSE)
- `apps/cloud/` — [Business Source License 1.1](./apps/cloud/LICENSE)
  - You may view, fork, and modify the code.
  - You may NOT offer it as a hosted service to third parties.
  - Converts to MIT after 4 years from publication.
  - Commercial hosting license: jp@metacognixion.com

## Contributing

Contributions to the MIT-licensed components are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

**MetaCognixion** · [@Jepetocrypto](https://twitter.com/Jepetocrypto) · [sovereignly.io](https://sovereignly.io)
