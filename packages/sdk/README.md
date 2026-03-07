# @metacognixion/chain-sdk

**Embed cryptographically-verifiable SOC2 compliance into any application.**

One npm package. No infrastructure migration. Works on AWS Lambda, Vercel, Railway, Fly.io, or bare metal.

```typescript
import { SovereignChain } from '@metacognixion/chain-sdk';

const chain = new SovereignChain({
  endpoint: 'https://chain.yourcompany.com',
  orgId:    'org_xxxxxxxxxxxxxxxx',
  apiKey:   'sk_live_...',
});

// Every event is hashed, Merkle-rooted, and anchored omnichain (EAS/Base, Arbitrum, Solana)
await chain.emit('USER_LOGIN', { userId: 'usr_123', method: 'passkey', ip: '1.2.3.4' });

// Generate a SOC2 evidence report from your audit trail
const report = await chain.complianceReport({ type: 'SOC2', from: '2025-01-01', to: '2025-12-31' });
console.log(`SOC2 score: ${report.score}/100`);
```

## Why this exists

Every company over ~20 employees eventually needs SOC2. The current solutions:

| Option | Cost | Time | Trust |
|---|---|---|---|
| Drata / Vanta | $15,000–40,000/yr | 6–12 months | You trust their platform |
| Manual audit prep | $50,000+ in eng time | 12+ months | Auditor trusts your docs |
| **@metacognixion/chain-sdk** | **$600/yr** | **10 minutes** | **Omnichain proof: EAS/Base + Arbitrum + Solana + Irys** |

The difference: every event is hashed into a Merkle tree, sealed into a block, and attested omnichain via EAS (Base + Arbitrum), Solana Memo Program, and Irys permanent archive. Your auditor verifies at easscan.org without trusting you — or us.

## Installation

```bash
npm install @metacognixion/chain-sdk
# or
bun add @metacognixion/chain-sdk
# or
yarn add @metacognixion/chain-sdk
```

## Quick start

### 1. Get credentials

Sign up at [sovereigncloud.dev](https://sovereigncloud.dev) and create an organization. You'll get an `orgId` and API key.

### 2. Emit your first event

```typescript
import { SovereignChain } from '@metacognixion/chain-sdk';

const chain = new SovereignChain({
  endpoint: 'https://chain.sovereigncloud.dev',
  orgId:    process.env.SOVEREIGN_ORG_ID!,
  apiKey:   process.env.SOVEREIGN_API_KEY!,
});

// Async mode (default): fire-and-forget, no await needed
chain.emit('USER_LOGIN', {
  userId:    req.user.id,
  ip:        req.ip,
  userAgent: req.headers['user-agent'],
  method:    'oauth_google',
});

// Flush before process exit
process.on('SIGTERM', async () => {
  await chain.close();
  process.exit(0);
});
```

### 3. Add framework middleware

```typescript
// Express / Hono / Fastify
app.use(chain.expressMiddleware({
  logBody:     false,   // don't log request bodies (PII)
  logHeaders:  false,
  ignorePaths: ['/health', '/metrics'],
}));

// Next.js API route
export default chain.withNextjs(handler);
```

## API reference

### `new SovereignChain(config)`

```typescript
const chain = new SovereignChain({
  endpoint:    string,    // Your SovereignCloud endpoint
  orgId:       string,    // org_xxxxxxxxxxxxxxxx
  apiKey:      string,    // sk_live_... or sk_test_...
  async?:      boolean,   // default true — fire-and-forget
  batchSize?:  number,    // default 50 events per flush
  batchMs?:    number,    // default 5000ms flush interval
  timeout?:    number,    // default 10000ms per request
  onError?:    (err: Error) => void,
});
```

### `chain.emit(type, payload, severity?)`

Record a single audit event.

```typescript
chain.emit('DATA_EXPORT', {
  userId:      'usr_123',
  resource:    'customer_records',
  recordCount: 1500,
  format:      'csv',
}, 'MEDIUM');  // LOW | MEDIUM | HIGH | CRITICAL
```

**Built-in event types** (40+ predefined):

| Category | Types |
|---|---|
| Auth | `AUTH_SUCCESS`, `AUTH_FAILURE`, `MFA_CHALLENGE`, `PASSWORD_CHANGE`, `SESSION_END` |
| Data | `DATA_READ`, `DATA_WRITE`, `DATA_DELETE`, `DATA_EXPORT`, `PII_ACCESS` |
| Config | `CONFIG_CHANGE`, `PERMISSION_CHANGE`, `ROLE_ASSIGNED`, `ROLE_REVOKED` |
| Deploy | `FUNCTION_DEPLOY`, `FUNCTION_DELETE`, `ENV_SECRET_ACCESS` |
| Security | `ANOMALY`, `RATE_LIMIT_HIT`, `BLOCKED_REQUEST`, `VULNERABILITY_SCAN` |
| Network | `NODE_JOIN`, `NODE_LEAVE`, `PEER_CONNECT` |

Custom types: any string in `SCREAMING_SNAKE_CASE`.

### `chain.emitBatch(events)`

Emit multiple events atomically (single Merkle leaf for the batch).

```typescript
await chain.emitBatch([
  { type: 'DATA_READ',   payload: { resource: 'orders', count: 250 } },
  { type: 'DATA_EXPORT', payload: { format: 'json', destination: 's3' }, severity: 'MEDIUM' },
]);
```

### `chain.complianceReport(opts)`

Generate a compliance evidence report from your audit trail.

```typescript
const report = await chain.complianceReport({
  type:  'SOC2',        // SOC2 | ISO27001 | HIPAA | GDPR | NIST
  from:  '2025-01-01',
  to:    '2025-12-31',
});

console.log(report.score);       // 0–100
console.log(report.controls);    // [{id, name, status, evidence}]
console.log(report.gaps);        // controls not yet satisfied
```

### `chain.exportEvents(opts?)`

Export your raw audit events with Merkle proofs for offline verification.

```typescript
const { events, merkleProofs, attestations } = await chain.exportEvents({
  from:  Date.now() - 30 * 86400_000,
  limit: 10_000,
});
// Verifiable: base.easscan.org/attestation/view/{uid}  |  solscan.io/tx/{sig}
```

### `chain.status()`

Get chain health and latest omnichain anchor receipts.

```typescript
const { blocks, events, tip, anchors } = await chain.status();
console.log(`Anchored chains: ${anchors.chains?.join(', ')}`);
```

### `chain.verifyEvent(eventId)`

Verify a specific event's inclusion in the chain with a Merkle proof.

```typescript
const { included, merkleProof, blockIndex, anchorTxHash } = await chain.verifyEvent('evt_xxx');
// Share merkleProof with your auditor — verifiable without trusting us
```

## Framework integrations

### Express / Hono / Fastify middleware

```typescript
// Automatically logs every request as a chain event
app.use(chain.expressMiddleware());
```

### Next.js

```typescript
// pages/api/users.ts
import { chain } from '../../lib/chain';

export default chain.withNextjs(async (req, res) => {
  res.json({ users: await getUsers() });
});
```

### Generic wrapper

```typescript
const handler = chain.withChain(async (req: Request) => {
  return new Response(JSON.stringify({ ok: true }));
});
```

## Self-hosting

The SDK works with self-hosted SovereignCloud nodes. All logic runs in the server — the SDK is a thin HTTP client.

```bash
# Clone and start a local node
git clone https://github.com/metacognixion/sovereign-cloud
cd sovereign-cloud
cp .env.example .env  # fill in SOVEREIGN_SERVER_KEY, JWT_SECRET, ADMIN_TOKEN
docker compose up -d

# Point the SDK at your node
const chain = new SovereignChain({
  endpoint: 'http://localhost:8787',
  orgId:    'org_your_org_id',
  apiKey:   'your_api_key',
});
```

## Verification

Anyone can verify your audit trail. No account required. No trust required.

```bash
# Verify a single event with its Merkle proof
curl https://chain.sovereigncloud.dev/verify \
  -d '{"eventId":"evt_xxx","merkleProof":"..."}'

# Verify the EAS attestation at easscan.org
https://etherscan.io/tx/0x...
```

## Pricing

| Plan | Events/mo | Reports | Price |
|---|---|---|---|
| Free | 10,000 | — | $0 |
| Starter | 1,000,000 | SOC2 | $49/mo |
| Growth | 10,000,000 | SOC2 + ISO27001 | $149/mo |
| Enterprise | Unlimited | All standards | Custom |
| Self-hosted | Unlimited | All standards | Free |

## How it works

```
Your app
  │
  ├── chain.emit('AUTH_SUCCESS', {...})
  │
  ▼
SovereignCloud / Sovereignly
  │
  ├── SHA-256 hash of event payload
  ├── Merkle tree of block events
  ├── Ed25519 block signature (node key)
  ├── Attestation to EAS/Base (every 100 blocks, ~$0.18/yr)
  └── Attestation to EAS/Arbitrum + Solana (growth tier)
          │
          └── keccak256(Merkle(all_tenant_tips))
                    │
                    └── base.easscan.org/attestation/view/0x...
                         ← anyone can verify here
                            without trusting us
```

## License

MIT — [github.com/metacognixion/sovereign-cloud](https://github.com/metacognixion/sovereign-cloud)

---

Built by [MetaCognixion](https://metacognixion.com) · [@Jepetocrypto](https://twitter.com/Jepetocrypto)
