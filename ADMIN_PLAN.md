# Super Admin Platform — Complete Plan

> Everything MetaCognixion needs to operate Sovereignly as a business.

---

## What EXISTS in Backend But Has NO Admin UI

### Token System (14 API endpoints, 0 admin pages)
```
GET  /_sovereign/tokens/config         → view all token settings
PUT  /_sovereign/tokens/config         → change any setting
GET  /_sovereign/tokens/status         → CLOSED/PRE_PUBLIC/PUBLIC
PUT  /_sovereign/tokens/status         → transition state
POST /_sovereign/tokens/freeze         → emergency halt ALL operations
POST /_sovereign/tokens/unfreeze       → resume operations
GET  /_sovereign/tokens/supply         → circulating, staked, treasury, fees
POST /_sovereign/tokens/award          → mint tokens to user
GET  /_sovereign/tokens/balance/:id    → user balance
GET  /_sovereign/tokens/transactions   → transaction history
POST /_sovereign/tokens/transfer       → move tokens between accounts
POST /_sovereign/tokens/withdraw       → user withdrawal
POST /_sovereign/tokens/stake          → lock tokens for APY
POST /_sovereign/tokens/unstake        → unlock staked tokens
```

### Tenant Management (10 API endpoints, mock data only)
```
POST   /_sovereign/tenants              → create tenant
GET    /_sovereign/tenants              → list all tenants
GET    /_sovereign/tenants/:id          → tenant detail
PATCH  /_sovereign/tenants/:id          → update tenant
DELETE /_sovereign/tenants/:id          → delete tenant
GET    /_sovereign/tenants/:id/stats    → tenant chain/KV stats
GET    /_sovereign/tenants/:id/chain/events → tenant events
GET    /_sovereign/tenants/:id/chain/report → compliance report
POST   /_sovereign/tenants/:id/chain/export → export audit trail
GET    /_sovereign/platform/stats       → global platform stats
```

### AI Kernel (5 subsystems, 0 admin visibility)
```
DecisionEngine    → evaluates health → decides actions (scale, restart, migrate)
HealthAnalyzer    → ingests all events → scores platform health
CognitiveModel    → z-score anomaly detection, trend prediction
PlacementEngine   → optimal node selection for workloads
TopologyEngine    → maps tenants → machines → resources
```

### Agent System (3 built-in agents, 0 admin visibility)
```
health-monitor    → watches chain events, flags anomalies
compliance-agent  → evaluates SOC2 controls continuously
cost-optimizer    → analyzes resource usage, suggests savings
```

---

## THE PLAN — 5 Modules

### Module 1: Real Tenant Management (replace mock data)

**Admin Tenants Page** (`/admin/tenants`):
- Connect to real `GET /_sovereign/tenants` API
- Show actual tenant data (org ID, name, plan, status, owner, events, storage)
- Inline plan change → `PATCH /_sovereign/tenants/:id`
- Suspend/activate → `PATCH /_sovereign/tenants/:id { status }`
- Delete → `DELETE /_sovereign/tenants/:id`
- Create tenant → `POST /_sovereign/tenants`
- Per-tenant drill-down:
  - Chain events viewer
  - Compliance report
  - Usage stats (events, storage, functions)
  - Export audit trail

### Module 2: Billing & Pricing Admin

**Admin Billing Page** (`/admin/billing`):
- **Revenue Dashboard**: MRR, ARR, churn rate, tenant count per plan
- **Pricing Editor**:
  - Set price per plan (Free/Starter/Growth/Enterprise)
  - Monthly vs annual toggle with discount %
  - Custom enterprise pricing per tenant
  - Feature matrix editor (what each plan includes)
- **Stripe Management**:
  - View/update Stripe product IDs
  - Webhook status
  - Recent payments list
  - Failed payment alerts
- **Coupon/Discount Management**:
  - Create discount codes
  - Set expiry, max uses, % or fixed amount
  - View active coupons
- **Usage Limits Editor**:
  - Events/month per plan
  - Functions max per plan
  - Storage GB per plan
  - Seats per plan
  - Custom limits per tenant override

### Module 3: SVRN Tokenomics Admin

**Admin Token Page** (`/admin/tokens`):
- **Status Control**:
  - CLOSED → PRE_PUBLIC → PUBLIC state machine
  - Emergency freeze/unfreeze with reason
  - Visual state indicator with transition confirmation
- **Configuration Editor** (all fields from TokenSystemConfig):
  - Token name & symbol
  - Transfer fee %
  - Withdrawal fee %
  - Daily/weekly withdrawal limits
  - Staking APY %
  - Min stake days
  - Points-to-token conversion rate
  - Feature gates (canTransfer, canWithdraw, canStake, canEarn, canView)
- **Supply Dashboard**:
  - Total minted, circulating, staked, treasury, fee pool, burned
  - Pie chart visualization
  - Mint/burn history
- **Operations**:
  - Award tokens to users
  - View all transactions (filterable)
  - User balance lookup
  - Manual transfer between accounts
- **Public Launch Controls**:
  - Pre-public checklist (legal, KYC, terms)
  - Terms & conditions text editor
  - Launch readiness score
  - Go-public button with confirmation flow

### Module 4: AI Operations Center

**Admin AI Page** (`/admin/ai`):
- **Decision Engine Dashboard**:
  - Recent decisions (scale_up, restart, investigate, scale_down)
  - Decision confidence scores
  - Auto-approved vs blocked by policy
  - Decision history timeline
- **Health Analyzer**:
  - Real-time health score (0-100)
  - Signal breakdown (CPU, memory, latency, errors, queue depth)
  - Anomaly history with z-scores
  - Alert thresholds configuration
- **Agent Control Panel**:
  - List all registered agents (health-monitor, compliance, cost-optimizer)
  - Start/stop/restart agents
  - Execution history (observe → plan → execute → report)
  - Agent logs
  - Register custom agents
- **Cognitive Model**:
  - Prediction dashboard (what the AI thinks will happen)
  - Trend analysis
  - Anomaly detection sensitivity slider
- **Cost Optimization**:
  - Current resource utilization
  - AI recommendations (resize, consolidate, schedule)
  - Estimated savings
  - Auto-apply toggle

### Module 5: Platform Analytics

**Admin Analytics Page** (`/admin/analytics`):
- **Global Metrics**: total requests, events, functions deployed, active users
- **Growth Charts**: signups over time, MRR trend, churn
- **Chain Analytics**: blocks/day, events/day, anchor frequency
- **Geographic Distribution**: requests by region
- **Top Tenants**: by events, functions, storage usage
- **Error Analytics**: error rate trend, top errors, affected tenants

---

## Execution Priority

| Sprint | Module | Pages | Effort |
|--------|--------|-------|--------|
| **Sprint A** | Module 1: Real Tenants | 2 pages | 1 day |
| **Sprint B** | Module 3: Tokenomics | 1 page (complex) | 1 day |
| **Sprint C** | Module 2: Billing Admin | 1 page (complex) | 1 day |
| **Sprint D** | Module 4: AI Ops | 1 page (complex) | 1-2 days |
| **Sprint E** | Module 5: Analytics | 1 page | 1 day |

---

## Architecture Notes

### All admin pages should:
1. **Require admin token** — check before rendering
2. **Log all actions** — every admin action → SovereignChain event
3. **Confirm destructive actions** — double confirmation for delete/freeze/public launch
4. **Show audit trail** — who did what, when

### Token Public Launch Flow:
```
CLOSED (internal only)
  ↓ Admin sets status to PRE_PUBLIC
PRE_PUBLIC (limited external access)
  ↓ Admin completes checklist:
  ✓ Legal review
  ✓ Terms & conditions published
  ✓ KYC/AML compliance
  ✓ Smart contract audit (if on-chain)
  ✓ Fee structure finalized
  ✓ Withdrawal limits tested
  ↓ Admin clicks "Go Public"
PUBLIC (full external access)
  - Transfers enabled
  - Withdrawals enabled
  - Staking enabled
  - Public marketplace
```

### AI Agent Architecture:
```
HealthAnalyzer (ingests ALL events)
  ↓ anomaly detected
DecisionEngine (evaluates + decides)
  ↓ action needed
PolicyEngine (approves/blocks)
  ↓ approved
AgentRuntime (executes)
  ↓ result
SovereignChain (logs everything)
```
