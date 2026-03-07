# Sovereignly — Architecture Alignment Plan

## System Bible → Implementation Mapping

The Super Pack defines a 7-layer AI-native infrastructure OS.
Current repo implements layers 5-7 partially. This plan aligns bottom-up.

---

## Phase 1: EVENT BUS + PLATFORM PROTOCOL (Foundation)
**Everything else depends on this.**

### 1A. Event Bus (`apps/oss/src/events/bus.ts`)
Current: `chain.emit()` writes to SQLite audit chain. No pub/sub.
Target: In-process pub/sub with typed events, subscriber registration,
        and chain logging as one subscriber among many.

Events from EVENTS.md:
  TENANT_CREATED, TENANT_DELETED
  WORKFLOW_STARTED, WORKFLOW_COMPLETED
  AGENT_EXECUTED
  MACHINE_STARTED, MACHINE_FAILED

Plus existing chain events:
  AUTH_SUCCESS, AUTH_FAILURE, CONFIG_CHANGE, ANOMALY, etc.

### 1B. Platform Protocol v1 (`apps/oss/src/protocol/`)
Current: `/_sovereign/*` custom routes
Target: Standard REST + event-driven primitives

  POST /v1/tenants         → provision
  GET  /v1/tenants/:id     → detail
  POST /v1/machines        → register machine
  POST /v1/workflows/trigger → start workflow
  POST /v1/agents/execute  → run agent
  GET  /v1/events          → query events
  POST /v1/policies        → create policy

### 1C. Policy Engine (`apps/oss/src/policies/engine.ts`)
Current: RBAC in zero-trust.ts, rate limits
Target: Declarative policy documents that gate all operations

---

## Phase 2: WORKFLOW ENGINE
**Depends on: Event Bus, Policy Engine**

### 2A. Workflow Runtime (`apps/cloud/src/workflows/engine.ts`)
DAG-based workflow execution. Each step emits events.

Built-in workflows:
  tenant-onboarding: create tenant → provision DB → deploy runtime → start agents
  tenant-teardown: stop agents → archive data → delete tenant
  compliance-audit: gather events → generate report → anchor to chain

### 2B. Workflow API
  POST /v1/workflows/trigger   { name, tenantId, params }
  GET  /v1/workflows/:id       status + step progress
  POST /v1/workflows/:id/cancel

---

## Phase 3: AGENT CONTROL LAYER
**Depends on: Event Bus, Workflow Engine, Policy Engine**

### 3A. Agent Runtime (`apps/cloud/src/agents/runtime.ts`)
Sandboxed execution environment for AI agents.
Agents observe system state, trigger workflows, call platform tools.

Agent contract:
  - observe(): read events, metrics, state
  - plan(): decide actions
  - execute(): call platform tools
  - report(): emit results as events

Constraints (from AGENTS.md):
  - Cannot bypass policies
  - Cannot access unauthorized tenant data
  - Cannot execute arbitrary shell commands

### 3B. Built-in Agents
  health-monitor: watches metrics → triggers alerts
  cost-optimizer: analyzes usage → suggests scaling
  compliance-agent: monitors events → flags violations
  onboarding-agent: guides new tenant setup

---

## Phase 4: AUTONOMOUS INFRASTRUCTURE KERNEL
**Depends on: Agent Runtime, Event Bus, State Registry**

### 4A. State Registry (`apps/cloud/src/kernel/state-registry.ts`)
Global state of all tenants, machines, workflows, agents.
SQLite-backed, event-sourced from the Event Bus.

### 4B. Health Analyzer (`apps/cloud/src/kernel/health-analyzer.ts`)
Consumes health events. Detects degradation patterns.
Triggers self-healing workflows.

### 4C. Decision Engine (`apps/cloud/src/kernel/decision-engine.ts`)
Takes health signals + policies → decides actions.
Uses rule-based logic (Phase 4), upgradeable to ML (Phase 6).

### 4D. Placement Engine (`apps/cloud/src/kernel/placement-engine.ts`)
Decides where to run workloads (region, machine size).
Inputs: latency requirements, data residency policies, cost.

### 4E. Migration Engine (`apps/cloud/src/kernel/migration-engine.ts`)
Moves tenants between regions/machines with zero downtime.
Coordinates with Litestream for SQLite migration.

### 4F. Topology Engine (`apps/cloud/src/kernel/topology-engine.ts`)
Maps the infrastructure graph: tenants → machines → regions → chains.

---

## Phase 5: DEVELOPER ECOSYSTEM
**Depends on: Platform Protocol, Agent Runtime**

CLI, plugin system, marketplace, templates, gamification.
This is a product/GTM layer — build after the kernel works.

---

## Phase 6: COGNITIVE INFRASTRUCTURE MODEL
**Depends on: All above**

ML-powered decision engine. Learns from historical events.
Predicts failures, optimizes placement, auto-scales.
This replaces rule-based decisions in Phase 4.

---

## Phase 7: AI OS INTERFACE
**Depends on: All above**

Natural language → intent parser → task planner → workflow execution.
"Deploy tenant environment for Acme in Europe" → workflow trigger.

---

## Implementation Priority

| Phase | Scope | Lines | Deps |
|-------|-------|-------|------|
| 1     | Event Bus + Protocol + Policy | ~800 | None |
| 2     | Workflow Engine | ~600 | Phase 1 |
| 3     | Agent Runtime | ~700 | Phase 1-2 |
| 4     | Kernel (6 engines) | ~1200 | Phase 1-3 |
| 5     | Developer Ecosystem | ~500 | Phase 1 |
| 6     | Cognitive Model | ~400 | Phase 4 |
| 7     | AI OS Interface | ~300 | Phase 1-4 |

Total new code: ~4,500 lines across 7 phases.
Current codebase: ~10,500 lines.
Target: ~15,000 lines for full architecture alignment.
