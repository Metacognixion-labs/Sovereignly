# Sovereignly v4.0 — Complete Project Handoff

**Date:** 2026-03-07
**Author:** JP (Metacognixion) + Claude Opus 4.6
**Status:** Live at https://sovereignly.io (Fly.io)

---

## 1. WHAT IS SOVEREIGNLY?

Sovereignly is a **sovereign cloud infrastructure platform** that provides:

- **SovereignChain** — An embedded proof-of-authority blockchain that cryptographically logs every operation (deploys, auth events, config changes) with Ed25519 signatures and Merkle trees
- **Omnichain Anchoring** — Merkle roots attested to 5+ public blockchains (EAS/Base, Arbitrum, Sign Protocol, Solana, Irys, Bitcoin) for independent tamper-proof verification at ~$630/year total
- **Multi-Tenant Isolation** — Per-tenant encrypted chains, KV stores, and storage with AES-256-GCM encryption derived from a single server key
- **AI Kernel** — Cognitive model with z-score anomaly detection, health analysis, decision engine, and autonomous agents (observe → plan → execute)
- **Compliance as Code** — Auto-generated SOC2, ISO 27001, HIPAA, GDPR, NIST reports from chain evidence

**Business Model:** Open-core. MIT-licensed core (`apps/oss`), BSL 1.1 cloud edition (`apps/cloud`) that converts to MIT after 4 years. SaaS at sovereignly.io with Free/Starter($49)/Growth($149)/Enterprise($2000) tiers.

**Public SDK:** `@metacognixion/chain-sdk` on npm — zero-dep client library for emitting audit events and generating compliance reports.

---

## 2. MONOREPO STRUCTURE

```
Sovereignly-v3.0.1-final/
├── package.json                    # Bun workspace root
├── tsconfig.json                   # ESNext, bundler resolution
├── fly.toml                        # Fly.io config (main cloud app)
├── docker-compose.yml              # Local dev: sovereign + caddy + prometheus + grafana + litestream
├── Dockerfile.control-plane        # Control plane container
├── Dockerfile.edge                 # Edge node container
├── .env.example                    # 64 environment variables documented
│
├── packages/
│   ├── core/                       # @sovereignly/core — shared types (Block, AuditEvent, Tenant)
│   │   └── src/
│   │       ├── index.ts
│   │       └── types.ts
│   └── sdk/                        # @metacognixion/chain-sdk — public npm package
│       ├── src/
│       └── README.md
│
├── apps/
│   ├── oss/                        # MIT — Single-tenant open-source server
│   │   └── src/                    # 34 TypeScript files
│   │       ├── server.ts           # OSS entry point
│   │       ├── security/           # chain.ts, omnichain-anchor.ts, crypto.ts
│   │       ├── events/             # bus.ts (typed pub/sub, 32 event types)
│   │       ├── policies/           # engine.ts (ABAC policy engine)
│   │       ├── workflows/          # engine.ts (DAG executor), builtins.ts
│   │       ├── agents/             # runtime.ts (sandboxed agents), builtins.ts
│   │       ├── auth/               # passkeys.ts, oauth.ts, siwe.ts, solana.ts
│   │       ├── gateway/            # Hono router, rate limiter, cache
│   │       ├── kv/                 # SQLite-backed KV with TTL
│   │       ├── runtime/            # Bun worker pool (sandboxed functions)
│   │       ├── storage/            # S3-compatible blob store
│   │       ├── scheduler/          # Cron tasks
│   │       └── ecosystem/          # plugins, templates, gamification
│   │
│   ├── cloud/                      # BSL 1.1 — Multi-tenant SaaS
│   │   ├── Dockerfile              # Bun 1.x alpine + Litestream
│   │   └── src/                    # 30+ TypeScript files
│   │       ├── server.ts           # Production entry point (v4.0.0)
│   │       ├── server-minimal.ts   # [DELETE ME] Bisect test artifact
│   │       ├── compliance.ts       # SOC2/ISO/HIPAA/GDPR/NIST reports
│   │       ├── zero-trust.ts       # RBAC, JWT, anomaly detection, secret scanning
│   │       ├── bootstrap/          # Initialization (config → chain → auth → tenants → kernel → ecosystem → cluster → gateway)
│   │       ├── tenants/            # manager.ts (per-tenant isolation), routes.ts
│   │       ├── billing/            # stripe.ts (checkout, portal, webhooks, metering)
│   │       ├── webhooks/           # HMAC-signed event delivery with retry
│   │       ├── gateway/            # public-routes.ts (signup, pricing), tenant-limiter.ts
│   │       ├── cluster/            # node-registry.ts, node-heartbeat.ts, cluster-topology.ts
│   │       ├── global/             # global-anchor.ts (root-of-roots), cluster-root.ts
│   │       ├── kernel/             # sovereign-kernel.ts + 12 subsystem files
│   │       └── ai/                 # cluster-balancer, cost-optimizer, network-anomaly-detector, workload-planner
│   │
│   ├── control-plane/              # Global orchestration (port 9090)
│   │   ├── fly.toml                # Fly.io: sovereignly-control-plane
│   │   └── src/server.ts
│   │
│   └── edge/                       # Edge compute nodes (port 8788)
│       ├── fly.toml                # Fly.io: sovereignly-edge
│       └── src/server.ts
│
├── dashboard/
│   └── index.html                  # Admin SPA (vanilla HTML/CSS/JS, dark theme)
│
├── deploy/
│   ├── entrypoint.sh               # Container entrypoint (Litestream wrapper)
│   ├── landing-page.html           # Marketing site at sovereignly.io
│   ├── litestream.yml              # SQLite → S3/R2 continuous replication
│   ├── Caddyfile                   # Reverse proxy + auto-TLS
│   ├── prometheus.yml              # Metrics scraping
│   ├── docker-compose.network.yml  # Multi-region local dev topology
│   ├── DEPLOY.ps1                  # Deployment automation
│   ├── BETA_LAUNCH.ps1             # Beta launch script
│   ├── SMOKE_TEST.ps1              # Post-deploy verification
│   ├── fly-multi-region.sh         # Fly.io multi-region setup
│   ├── add-validator.mjs           # Blockchain validator registration
│   ├── deploy-contracts.mjs        # Smart contract deployment
│   ├── register-eas-schema.mjs     # EAS schema registration
│   └── grafana/                    # Grafana dashboards + provisioning
│
└── docs/architecture/              # 10 architecture documents
    ├── SYSTEM_BIBLE.md
    ├── CLAUDE_MASTER_PROMPT.md
    ├── CLAUDE_CONTINUITY_PROMPT.md
    ├── PLATFORM_PROTOCOL.md
    ├── DEVELOPER_ECOSYSTEM.md
    ├── WORKFLOWS.md
    ├── EVENTS.md
    ├── AGENTS.md
    └── AI_OS_INTERFACE.md
```

---

## 3. TECH STACK

| Layer | Technology | Notes |
|-------|-----------|-------|
| **Runtime** | Bun 1.x | JavaScript/TypeScript, fast startup, native SQLite |
| **Web Framework** | Hono 4.6.0 | Lightweight, Web Standard APIs |
| **Database** | SQLite (WAL mode) | Per-tenant isolated DBs |
| **Backup** | Litestream | Continuous replication to S3/R2 (~1s lag) |
| **Cryptography** | Web Crypto API + @noble/curves 1.6.0 + @noble/hashes 1.4.0 | Ed25519, AES-256-GCM, keccak256, secp256k1 |
| **Deployment** | Fly.io (Firecracker VMs) | shared-cpu-1x, 2GB RAM, iad region |
| **Reverse Proxy** | Caddy | Auto-TLS, HTTP/3, load balancing |
| **Monitoring** | Prometheus + Grafana | Custom sovereign-ops dashboard |
| **CI/CD** | Manual `fly deploy` | From monorepo root |

**Total runtime dependencies:** 3 packages (hono, @noble/curves, @noble/hashes)

---

## 4. BOOTSTRAP SEQUENCE (apps/cloud)

The production server (`apps/cloud/src/server.ts`) boots in this order:

```
1. Config           → Read 64 env vars, derive defaults
2. OmnichainAnchor  → Initialize blockchain attestation clients
3. SovereignChain   → Platform audit chain (data/platform/chain.db)
4. Auth             → OAuth (Google/GitHub) + Passkeys + SIWE + Solana
5. TenantManager    → Multi-tenant isolation + global tenant registry
6. BillingService   → Stripe integration (if STRIPE_SECRET_KEY set)
7. WebhookManager   → HMAC-signed event delivery
8. EventBus         → Platform pub/sub (32 event types)
9. PolicyEngine     → ABAC rules (agent-sandbox, tenant-isolation, free-tier-limits)
10. WorkflowEngine  → DAG executor with retry logic
11. AgentRuntime    → Observe → plan → execute sandbox
12. StateRegistry   → Event-sourced entity state
13. HealthAnalyzer  → Anomaly detection + self-healing workflows
14. DecisionEngine  → Multi-criteria infrastructure decisions
15. PlacementEngine → Workload placement optimization
16. MigrationEngine → Live tenant migration
17. TopologyEngine  → Infrastructure graph analysis
18. AIOperatingSystem → Natural language infrastructure control
19. CognitiveModel  → ML-based predictions + risk scoring
20. SovereignKernel → Modular runtime (registers all above as services)
21. PluginRegistry  → Plugin system
22. TemplateRegistry → Project templates
23. Gamification    → Badges + leaderboards
24. NodeRegistry    → Cluster node tracking
25. NodeHeartbeat   → 30s health pings (starts immediately)
26. ClusterTopology → Network graph
27. GlobalAnchor    → Root-of-roots attestation
28. ClusterRoot     → Per-cluster Merkle root (every N blocks)
29. AI Cluster      → ClusterBalancer, WorkloadPlanner, NetworkAnomalyDetector, CostOptimizer
30. Hono Gateway    → Register all HTTP routes + middleware
31. HTTP Server     → Listen on PORT (default 8787)
32. Health Watchdog → Self-exits if unresponsive for 15s
```

**Graceful Shutdown:** Flushes chains, stops heartbeat, closes all services.

---

## 5. API ROUTES (73 endpoints)

### Public (No Auth)
| Method | Path | Handler |
|--------|------|---------|
| GET | `/` | Landing page (deploy/landing-page.html) |
| GET | `/_sovereign/health` | Health check (Fly.io uses this) |
| GET | `/_sovereign/metrics` | Prometheus-compatible metrics |
| GET | `/_sovereign/signup` | Signup form (HTML) |
| POST | `/_sovereign/signup` | Create free tenant → returns JWT |
| POST | `/_sovereign/signup/upgrade` | Stripe checkout session |
| GET | `/_sovereign/pricing` | Pricing data (JSON) |
| GET | `/_sovereign/dashboard` | Admin SPA |
| POST | `/_sovereign/control/heartbeat` | Node heartbeat receiver |

### Authenticated (Bearer JWT or x-sovereign-token)
| Module | Endpoints | Key Routes |
|--------|-----------|------------|
| **Auth** | 18 | Passkey register/login, OAuth flows, SIWE/Solana verify, token refresh |
| **Chain** | 8+ | GET blocks, events, anchor receipts, verify integrity |
| **Tenants** | 7 | CRUD, stats, compliance reports (SOC2/ISO/HIPAA/GDPR/NIST) |
| **Billing** | 4 | Checkout, portal, subscription status, Stripe webhook |
| **Webhooks** | 4 | Register, list, delete, test |
| **Kernel** | 8 | State, health, decisions, placement, migration, topology |
| **AI** | 6 | NL commands, parse, predictions, risk, frequency, stats |
| **Agents** | ~4 | List, get, start, stop |
| **Workflows** | ~4 | List, trigger, status, cancel |
| **Cluster** | 7 | Nodes, topology, region, best-node, deregister, stats |
| **Ecosystem** | ~6 | Plugins, templates |
| **Admin** | 1 | `/_sovereign/ops` — full platform stats |

### SDK Event Ingestion
| Method | Path | Notes |
|--------|------|-------|
| POST | `/_sovereign/tenants/:id/events` | Per-tenant rate limited by plan |

---

## 6. SECURITY ARCHITECTURE (7 Layers)

```
Layer 1: Transport      → Caddy + TLS 1.2+ + HSTS + HTTP/3
Layer 2: Gateway        → Rate limiting (per-IP + per-tenant by plan)
Layer 3: Zero-Trust     → JWT RBAC (admin/owner/deployer/reader/auditor)
                          Anomaly detection (brute-force: 5 fails → 15min block)
                          Secret scanning (10 credential patterns)
                          Security headers (OWASP recommended)
Layer 4: Policy Engine  → ABAC rules: agent-sandbox, tenant-isolation, free-tier-limits
Layer 5: Tenant Isolation → Per-tenant DBs, encrypted KV, derived AES keys
Layer 6: SovereignChain → PoA blockchain, Ed25519 signatures, Merkle batching
Layer 7: Omnichain      → EAS/Base, Arbitrum, Sign Protocol, Solana, Irys, Bitcoin
```

### Cryptographic Primitives
| Algorithm | Use |
|-----------|-----|
| Ed25519 | Block signing, node identity, chain verification |
| AES-256-GCM | Per-tenant payload encryption at rest |
| SHA-256 | Block hashing, Merkle trees |
| HMAC-SHA256 | JWT signing, webhook signatures, key derivation |
| keccak256 | EVM address derivation, Ethereum tx hashing |
| PBKDF2 | Key derivation from server key |
| secp256k1 | Ethereum/Bitcoin transaction signing |

### RBAC Permissions
| Role | Permissions |
|------|------------|
| admin | Everything |
| owner | Tenant CRUD, billing, users, chain read, deploy, webhook manage |
| deployer | Deploy functions, read chain, read tenant |
| reader | Read chain events, read tenant info |
| auditor | Read chain, read compliance reports, read tenant |

---

## 7. SOVEREIGNCHAIN — HOW IT WORKS

### Block Structure
```typescript
{
  index:       number,        // Sequential block number
  timestamp:   number,        // Unix ms
  prevHash:    string,        // SHA-256 of previous block
  merkleRoot:  string,        // Merkle root of all events in this block
  eventCount:  number,
  nodeId:      string,        // Node that sealed the block
  signature:   string,        // Ed25519 signature of canonical fields
  blockHash:   string,        // SHA-256 of all block fields
  acks:        string[],      // Peer acknowledgments (PBFT-lite)
  anchored:    boolean,       // Whether attested to external chains
}
```

### Event Types (14)
`FUNCTION_DEPLOY`, `FUNCTION_INVOKE`, `CONFIG_CHANGE`, `AUTH_SUCCESS`, `AUTH_FAILURE`,
`ANOMALY`, `RATE_LIMIT_HIT`, `SECRET_ROTATION`, `DATA_READ`, `DATA_EXPORT`,
`PERMISSION_CHANGE`, `TENANT_CREATED`, `TENANT_DELETED`, `POLICY_VIOLATED`

### Seal Flow
1. Events accumulate in pending queue
2. Every 30 seconds (or when queue is full), `sealBlock()` fires
3. Merkle tree computed from all pending event hashes
4. Block fields canonicalized and SHA-256 hashed
5. Block signed with node's Ed25519 private key
6. Block stored in SQLite, events updated with `block_idx`
7. Every 100 blocks, Merkle root anchored to external chains via OmnichainAnchor

### Anchoring Tiers & Costs
| Tier | Chains | Annual Cost |
|------|--------|-------------|
| Free | EAS/Base | $0.18 |
| Starter ($49/mo) | + Arbitrum + Sign Protocol | $0.38 |
| Growth ($149/mo) | + Solana | $0.65 |
| Enterprise ($2K/mo) | + Irys + Bitcoin | ~$630 |

### Anchor Hierarchy
```
Tenant Chain → Cluster Root → Global Root
     ↓              ↓             ↓
  Per-tenant     Per-cluster   Platform-wide
  Merkle root    aggregation   root-of-roots
                               attested to
                               public chains
```

---

## 8. AI KERNEL SUBSYSTEMS

### CognitiveModel (`kernel/cognitive-model.ts`)
- Subscribes to all events (`*` wildcard)
- Tracks event frequency per entity over 120s windows
- Z-score anomaly detection (threshold: 2.5 standard deviations)
- Risk scoring per entity (0-1 scale)
- Metric predictions based on trend analysis

### HealthAnalyzer (`kernel/health-analyzer.ts`)
- 30s health sweep interval
- 5-minute anomaly windows per entity
- Signals: `repeated_failures` (5+ in 5m), `degradation_pattern` (3+ in 5m)
- Auto-triggers healing workflows for critical entities

### DecisionEngine (`kernel/decision-engine.ts`)
- Multi-criteria decision making using health signals + state + policies
- Exposes recent decisions via API

### Built-in Agents
| Agent | Schedule | Purpose |
|-------|----------|---------|
| health-monitor | 30s | Watch anomalies, machine failures → emit CONFIG_CHANGE |
| compliance-agent | 60s | Auth failures, data exports → emit POLICY_VIOLATED |
| cost-optimizer | 300s | Idle machines → suggest scale-down |

### AI Cluster Components
| Component | Interval | Purpose |
|-----------|----------|---------|
| ClusterBalancer | 60s | Load balancing, migration recommendations |
| NetworkAnomalyDetector | 30s | Network pattern analysis, ANOMALY events |
| CostOptimizer | 300s | Cost reduction algorithms |
| WorkloadPlanner | on-demand | Long-term capacity planning |

### AIOperatingSystem (`kernel/ai-os.ts`)
- Natural language infrastructure control (admin-only)
- Parses intent → generates plan → executes operations
- Example: "scale down idle machines in us-east"

---

## 9. MULTI-TENANCY

### Per-Tenant Isolation
```
data/
├── platform/
│   └── chain.db          # Platform audit chain
├── global/
│   ├── tenants.db        # Global tenant registry
│   └── anchor.db         # Global anchor roots
└── tenants/
    └── {tenantId}/
        ├── chain.db      # Tenant's private audit chain
        ├── kv.db         # Tenant's encrypted KV store
        ├── passkeys.db   # Tenant's WebAuthn credentials
        ├── users.db      # Tenant's user records
        └── storage/      # Tenant's blob storage
```

### Encryption
- Each tenant gets a unique AES-256-GCM key derived via: `HMAC(serverKey, "tenant-encryption:{tenantId}")`
- Single server key rotation rotates all tenant keys

### Plan Limits
| Resource | Free | Starter | Growth | Enterprise |
|----------|------|---------|--------|-----------|
| Events/mo | 10K | 1M | 10M | Unlimited |
| Functions | 3 | 20 | 100 | Unlimited |
| Agents | 1 | 5 | Unlimited | Unlimited |
| Workflows | 3/day | Unlimited | Unlimited | Unlimited |
| Storage | 500MB | 20GB | 100GB | Unlimited |
| Seats | 1 | 3 | 10 | Unlimited |
| API calls/min | 60 | 300 | 1,000 | 5,000 |
| Events/min | 100 | 1,000 | 10,000 | 50,000 |

### Rate Limiting
- **Per-IP**: Sliding window (configurable, default 60 req/min)
- **Per-Tenant**: By plan tier (see table above)
- **Signup**: 10 signups/hour per IP

---

## 10. DEPLOYMENT

### Current Production (Fly.io)
```
App: sovereignly
URL: https://sovereignly.io / https://sovereignly.fly.dev
Region: iad (US-East)
Machine: shared-cpu-1x, 2048 MB RAM
Volume: /data (persistent)
Health: GET /_sovereign/health every 30s
Entry: deploy/entrypoint.sh → Litestream wraps Bun
```

### Deploy Command
```bash
cd "Sovereignly-v3.0.1-final (6)"
fly deploy
```

### Entrypoint Logic (`deploy/entrypoint.sh`)
```
if LITESTREAM_BUCKET is set:
  1. Restore chain.db and tenants.db from S3/R2 (if missing)
  2. Start Litestream with Bun as subprocess (continuous backup)
else:
  1. Run plain Bun (local dev, no backup)
```

### Environment Variables (Required)
```bash
SOVEREIGN_SERVER_KEY    # Master encryption key (never changes)
JWT_SECRET              # JWT signing key
ADMIN_TOKEN             # Admin API access token
PORT                    # Default: 8787
```

### Environment Variables (Optional but Important)
```bash
# Stripe Billing
STRIPE_SECRET_KEY       # Stripe API key
STRIPE_WEBHOOK_SECRET   # Webhook signature verification
STRIPE_PRICE_STARTER    # Price ID for Starter plan
STRIPE_PRICE_GROWTH     # Price ID for Growth plan
STRIPE_PRICE_ENTERPRISE # Price ID for Enterprise plan

# Omnichain Anchoring
ANCHOR_TIER             # free/starter/growth/enterprise
EAS_BASE_RPC            # Base RPC endpoint
EAS_SIGNER_KEY          # EVM signer private key
EAS_ARB_RPC             # Arbitrum RPC endpoint
SOLANA_RPC              # Solana RPC endpoint
SOLANA_SIGNER_KEY       # Solana ed25519 key
IRYS_NODE               # Irys gateway URL
IRYS_TOKEN              # Irys payment token
BITCOIN_RPC             # Bitcoin RPC endpoint
BITCOIN_SIGNER_WIF      # Bitcoin WIF private key

# Cluster
NODE_ROLE               # control / cluster / edge
NODE_REGION             # e.g., us-east-1
CLUSTER_ID              # Cluster identifier
CONTROL_PLANE_URL       # URL of control plane (if not control plane)
CLUSTER_PEERS           # Comma-separated peer URLs

# Litestream Backup
LITESTREAM_BUCKET       # S3/R2 bucket name
LITESTREAM_ACCESS_KEY_ID
LITESTREAM_SECRET_ACCESS_KEY
LITESTREAM_ENDPOINT     # S3-compatible endpoint (R2, MinIO)
LITESTREAM_REGION       # Bucket region

# OAuth
GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
```

### Not Yet Deployed
| Component | Fly App Name | Status |
|-----------|-------------|--------|
| Control Plane | sovereignly-control-plane | Dockerfile exists, fly.toml configured, not deployed |
| Edge Nodes | sovereignly-edge | Dockerfile exists, fly.toml configured, not deployed |

### Docker Compose (Local Dev)
```bash
# Basic: sovereign + caddy
docker compose up

# With monitoring: + prometheus + grafana
docker compose --profile monitoring up

# With backup: + litestream
docker compose --profile backup up

# Multi-region topology (5 nodes)
docker compose -f deploy/docker-compose.network.yml up
```

---

## 11. LITESTREAM BACKUP

SQLite databases are continuously replicated to S3/R2:

| Database | Sync Interval | Retention | Purpose |
|----------|--------------|-----------|---------|
| `/data/platform/chain.db` | 1s | 72h | Platform audit log |
| `/data/platform/users.db` | 5s | default | User + passkey DB |
| `/data/global/tenants.db` | 5s | default | Global tenant registry |
| `/data/tenants/*/chain.db` | 5s | 30d | Per-tenant audit chains |
| `/data/tenants/*/kv.db` | 10s | 7d | Per-tenant KV stores |

On container restart, `entrypoint.sh` restores from replica if DBs don't exist locally.

---

## 12. KNOWN BUGS FIXED

### 503 Crash — ~3 Minute Death Spiral (Fixed 2026-03-07)
**Root Cause:** Three bugs combined into an event cascade:
1. `node-heartbeat.ts` reported `heapUsed/heapTotal ≈ 1.0` on Bun (5MB/5MB initial heap)
2. `NetworkAnomalyDetector` saw `avgLoad > 0.9`, emitted `ANOMALY` every 30s
3. `health-monitor` agent subscribed to `ANOMALY`, after 5+ anomalies re-emitted `ANOMALY` — infinite cascade flooded microtask queue

**Fixes:**
- `node-heartbeat.ts`: Changed load metric to `rss / 512MB` (capped at 0.95)
- `agents/runtime.ts`: Added `inst.running` re-entrancy guard
- `agents/builtins.ts`: Changed agent emissions from `ANOMALY` to `CONFIG_CHANGE`

### "Start for Free" Button 404 (Fixed 2026-03-07)
- Changed all CTA links from `https://app.sovereignly.io` to `/_sovereign/signup`
- Added `GET /_sovereign/signup` route serving an HTML signup form

---

## 13. CLEANUP NEEDED

| Item | Location | Action |
|------|----------|--------|
| Bisect test file | `apps/cloud/src/server-minimal.ts` | Delete (was used to debug 503 crash) |
| Version mismatch | Root `package.json` says 3.0.1, server says 4.0.0 | Align to 4.0.0 |

---

## 14. PENDING WORK

### High Priority
- [ ] **Fly secrets setup** — Set production values for `SOVEREIGN_SERVER_KEY`, `JWT_SECRET`, `ADMIN_TOKEN` via `fly secrets set`
- [ ] **Stripe integration** — Set `STRIPE_SECRET_KEY` + price IDs for paid tiers
- [ ] **Litestream backup** — Configure `LITESTREAM_BUCKET` + S3/R2 credentials
- [ ] **Custom domain SSL** — Verify TLS on sovereignly.io (currently works via Fly proxy)

### Medium Priority
- [ ] **Deploy Control Plane** — `fly apps create sovereignly-control-plane` + `fly deploy -c apps/control-plane/fly.toml`
- [ ] **Deploy Edge Nodes** — `fly apps create sovereignly-edge` + `fly deploy -c apps/edge/fly.toml`
- [ ] **Dashboard UI** — `dashboard/index.html` exists as a shell, needs real data wiring
- [ ] **Omnichain keys** — Set signer keys for EAS, Solana, Irys, Bitcoin anchoring
- [ ] **OAuth providers** — Configure Google + GitHub OAuth app credentials

### Low Priority
- [ ] **SDK publish** — Publish `@metacognixion/chain-sdk` to npm
- [ ] **Multi-region** — Use `deploy/fly-multi-region.sh` to expand to eu-west, sjc
- [ ] **Grafana dashboards** — Deploy `deploy/grafana/` monitoring stack
- [ ] **CI/CD pipeline** — Automate `fly deploy` on push to main
- [ ] **Integration tests** — Run `apps/oss/src/test/integration.test.ts`

---

## 15. HOW TO RUN LOCALLY

### Prerequisites
- [Bun](https://bun.sh) v1.x
- No other dependencies needed

### Quick Start
```bash
# Install dependencies
bun install

# Run OSS (single-tenant, MIT)
bun run dev:oss
# → http://localhost:8787

# Run Cloud (multi-tenant, BSL)
bun run dev:cloud
# → http://localhost:8787

# Run Control Plane
bun run dev:control-plane
# → http://localhost:9090

# Run Edge
bun run dev:edge
# → http://localhost:8788
```

### Minimum .env for Local Dev
```bash
SOVEREIGN_SERVER_KEY=dev-server-key-change-in-production
JWT_SECRET=dev-jwt-secret-change-in-production
ADMIN_TOKEN=dev-admin-token
PORT=8787
DATA_DIR=./data
LOG_LEVEL=debug
```

### Verify
```bash
curl http://localhost:8787/_sovereign/health
# → {"status":"healthy","version":"4.0.0",...}

curl http://localhost:8787/_sovereign/pricing
# → {"plans":[...]}
```

---

## 16. KEY DESIGN DECISIONS

| Decision | Rationale |
|----------|-----------|
| **SQLite over Postgres** | Per-tenant DB isolation, zero-config, Litestream for durability |
| **Bun over Node** | 3x faster startup, native SQLite, smaller containers (50MB) |
| **Hono over Express** | Web Standard APIs, 14KB, works everywhere |
| **Ed25519 over ECDSA** | Faster signing, deterministic, no nonce reuse risk |
| **EAS over direct L1** | 99.9% cheaper ($0.18/yr vs $876/yr on Ethereum mainnet) |
| **Event sourcing** | All state derived from chain events = complete auditability |
| **ABAC over RBAC** | More flexible policy rules (tenant context, agent scope, plan limits) |
| **No external deps** | Only 3 runtime deps = minimal supply chain attack surface |
| **BSL over AGPL** | Protects cloud revenue while converting to MIT in 4 years |
| **In-process agents** | No separate agent service = simpler deployment, lower latency |

---

## 17. CONTACT

- **JP** — jp@metacognixion.com
- **GitHub** — github.com/Metacognixion-labs/Sovereignly
- **Live** — https://sovereignly.io
