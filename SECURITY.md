# Sovereignly v3 — Security Architecture

> **Classification:** Public  
> **Standard:** SOC 2 Type II Ready · ISO 27001:2022 · NIST SP 800-53 Rev 5  
> **Last updated:** 2026-03

---

## Overview

Sovereignly implements defence-in-depth across 7 layers, anchored to an embedded Proof-of-Authority blockchain (SovereignChain) that provides cryptographic, tamper-evident audit records for every security-relevant event. At configurable intervals, chain Merkle roots are attested to **5 independent public networks** via OmnichainAnchor — providing external, permissionless verifiability with zero custom contracts.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SOVEREIGNLY v3 — SECURITY STACK                      │
├──────────┬───────────────────────────────────────────────────────────────┤
│ Layer 7  │  OmnichainAnchor v3  (EAS/Base · EAS/Arbitrum · Solana       │
│          │  · Sign Protocol · Irys · Bitcoin OP_RETURN)                 │
├──────────┼───────────────────────────────────────────────────────────────┤
│ Layer 6  │  SovereignChain  (PoA audit blockchain — embedded)           │
│          │  Ed25519 blocks · Merkle-batched events · peer replication   │
├──────────┼───────────────────────────────────────────────────────────────┤
│ Layer 5  │  Compliance Engine  (SOC2 / ISO27001 / NIST evidence)        │
├──────────┼───────────────────────────────────────────────────────────────┤
│ Layer 4  │  Zero-Trust Middleware                                        │
│          │  RBAC · JWT auth · anomaly detection · IP blocking           │
├──────────┼───────────────────────────────────────────────────────────────┤
│ Layer 3  │  Secret Scanner  (10 credential patterns pre-deploy)         │
├──────────┼───────────────────────────────────────────────────────────────┤
│ Layer 2  │  Runtime Isolation  (Bun Worker OS-level process isolation)  │
├──────────┼───────────────────────────────────────────────────────────────┤
│ Layer 1  │  Transport  (Caddy + TLS 1.2+  · HSTS · HTTP/3)              │
└──────────┴───────────────────────────────────────────────────────────────┘
```

---

## SovereignChain — Embedded Audit Blockchain

### Why a blockchain?

Traditional centralised audit logs have a fundamental flaw: the same entity that controls the system also controls the logs. SovereignChain eliminates this with:

- **Hash-linked blocks** — altering any event invalidates every subsequent block hash
- **Ed25519 signatures** — each block is cryptographically signed by the producing node
- **Merkle tree batching** — any individual event's inclusion is provable without revealing others
- **Peer replication** — in cluster mode, no single node can forge or suppress history
- **Omnichain attestation** — 5 independent validator sets provide external, public reference

### Block Structure

```
Block {
  index:      uint64        — monotonically increasing
  timestamp:  ISO-8601      — UTC, millisecond precision
  events:     Event[]       — array of security events in this block
  merkleRoot: bytes32       — keccak256(sorted leaves)
  prevHash:   bytes32       — links to previous block
  hash:       bytes32       — keccak256(index‖timestamp‖merkleRoot‖prevHash)
  signature:  bytes64       — Ed25519(hash, nodePrivKey)
  anchor?:    string        — EAS attestation UID (Base mainnet)
}
```

### Seal & Attest flow

```
Every ANCHOR_INTERVAL blocks (default: 100):
  1. Compute Merkle root of all events since last anchor
  2. Call OmnichainAnchor.anchor(root, blockIndex, eventCount, orgId)
  3. EAS/Base: schemaEncoder.encodeData → attest() → emit uid
  4. EAS/Arbitrum (starter+): same schema, second chain
  5. Solana (growth+): Memo Program → base64(root)
  6. Sign Protocol (growth+): SPS attestation
  7. Irys (enterprise): permanent arweave storage
  8. Bitcoin (enterprise, weekly): OP_RETURN → sha256d(root)
  9. Store uid in block anchor field
```

---

## OmnichainAnchor v3 — Chain Details

### EAS Schema (shared across all EVM chains)

```
bytes32 merkleRoot, uint256 blockIndex, uint32 eventCount, string orgId, string protocol
```

Schema UID: `0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc`  
Selector: `0x3cb73d33` (EAS v1.3.0 `attest((bytes32,address,uint64,bool,bytes32,bytes,uint256))`)

Verify: `https://base.easscan.org/schema/view/0xa3518350...`

### Cost breakdown (Growth tier, 365 daily anchors)

| Chain | Protocol | Cost/yr |
|---|---|---|
| Base | EAS v1.3.0 | ~$0.18 |
| Arbitrum One | EAS v1.3.0 | ~$0.18 |
| Solana | Memo Program | ~$0.18 |
| Sign Protocol | SPS schema | ~$0.09 |
| **Total** | | **~$0.63** |

### Cryptographic primitives

| Use | Algorithm | Library |
|---|---|---|
| Block signing | Ed25519 | `@noble/curves/ed25519` |
| EVM address derivation | keccak256(pubkey[1:]) | `@noble/hashes/sha3` |
| Bitcoin OP_RETURN | SHA256d (double SHA-256) | `@noble/hashes/sha256` |
| Block hash | SHA-256 | `@noble/hashes/sha256` |
| Merkle leaves | keccak256 | `@noble/hashes/sha3` |
| AES-256-GCM | Tenant chain encryption | Web Crypto API |

---

## Authentication — Zero External Dependencies

All auth methods run in-process. No third-party identity service handles credentials.

| Method | Standard | Implementation |
|---|---|---|
| Passkeys | WebAuthn / FIDO2 | `src/auth/passkeys.ts` — Web Crypto API |
| OAuth | RFC 6749 | `src/auth/oauth.ts` — HTTP redirect flow |
| SIWE | EIP-4361 | `src/auth/siwe.ts` — secp256k1 ecrecover |
| Solana | Ed25519 | `src/auth/solana.ts` — nacl verify |
| JWT | RS256/HS256 | `src/security/zero-trust.ts` — HMAC-SHA256 |

Every auth event is emitted as a SovereignChain event and included in the next block's Merkle root. Auth is self-auditing.

---

## Zero-Trust Middleware

Every request passes through a validation chain before reaching any handler:

```
Request
  → IP block check
  → Rate limiting (configurable per-min)
  → JWT verification (HMAC-SHA256)
  → RBAC enforcement (role → route matrix)
  → Anomaly detection (burst patterns, impossible travel)
  → Secret scanner (10 credential patterns in request body)
  → Handler
  → Chain event emission (every request logged)
```

RBAC roles: `admin`, `tenant_admin`, `tenant_user`, `auditor`, `readonly`

---

## Data Protection

| Layer | Mechanism |
|---|---|
| Tenant chain data | AES-256-GCM, per-tenant key derived from `SOVEREIGN_SERVER_KEY + tenantId` |
| KV store | SQLite with WAL mode; Litestream replication to S3/R2 |
| Secrets in transit | TLS 1.2+ minimum, HSTS enforced via Caddy |
| Secrets at rest | Env vars only — never stored in DB or chain |
| PII in chain events | Events store hashes only, not raw values |

---

## Responsible Disclosure

Security issues: security@metacognixion.com  
PGP: available on request  
Response SLA: 48 hours acknowledgement, 30 days for critical

