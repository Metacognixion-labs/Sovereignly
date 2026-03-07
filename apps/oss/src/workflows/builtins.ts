// Sovereignly Built-in Workflows -- MIT License
//
// From WORKFLOWS.md:
//   tenant-onboarding: create tenant -> provision database -> deploy runtime -> start agents
//
// These are registered at boot. Custom workflows can be added via API.

import type { WorkflowDefinition, WorkflowContext, StepResult } from "./engine.ts";
import type { EventBus } from "../events/bus.ts";

// Helper: create a step result
const ok = (output?: Record<string, unknown>): StepResult => ({ ok: true, output });
const fail = (error: string): StepResult => ({ ok: false, error });

// ============================================================================
// tenant-onboarding
// ============================================================================

export function tenantOnboardingWorkflow(bus: EventBus): WorkflowDefinition {
  return {
    name: "tenant-onboarding",
    description: "Provision a new tenant: create -> database -> runtime -> agents",
    version: "1.0.0",
    steps: [
      {
        id: "validate",
        name: "Validate tenant parameters",
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantName, plan, ownerId } = ctx.params;
          if (!tenantName) return fail("tenantName required");
          if (!ownerId)    return fail("ownerId required");
          return ok({ tenantName, plan: plan ?? "free", ownerId });
        },
      },
      {
        id: "create-tenant",
        name: "Create tenant record",
        dependsOn: ["validate"],
        retries: 1,
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantName, plan, ownerId } = ctx.stepOutputs.validate as any;
          const tenantId = `org_${crypto.randomUUID().slice(0, 16)}`;

          await bus.emit("TENANT_CREATED", {
            tenantId, name: tenantName, plan, ownerId,
            workflowId: ctx.workflowId,
          }, { source: "workflow:tenant-onboarding", tenantId });

          return ok({ tenantId, name: tenantName, plan });
        },
      },
      {
        id: "provision-database",
        name: "Provision tenant database",
        dependsOn: ["create-tenant"],
        retries: 2,
        timeoutMs: 15_000,
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId } = ctx.stepOutputs["create-tenant"] as any;

          // In production: TenantManager.provision() handles this
          // Here we emit the event for the chain bridge to pick up
          await bus.emit("CONFIG_CHANGE", {
            event: "database_provisioned", tenantId,
            engine: "sqlite", isolation: "per-tenant",
          }, { source: "workflow:tenant-onboarding", tenantId });

          return ok({ tenantId, dbReady: true });
        },
      },
      {
        id: "deploy-runtime",
        name: "Deploy tenant runtime environment",
        dependsOn: ["provision-database"],
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId } = ctx.stepOutputs["create-tenant"] as any;

          await bus.emit("MACHINE_STARTED", {
            tenantId, type: "tenant-runtime",
            workflowId: ctx.workflowId,
          }, { source: "workflow:tenant-onboarding", tenantId });

          return ok({ tenantId, runtimeReady: true });
        },
      },
      {
        id: "start-agents",
        name: "Start default tenant agents",
        dependsOn: ["deploy-runtime"],
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId, plan } = ctx.stepOutputs["create-tenant"] as any;

          // Default agents by plan
          const agents = ["health-monitor"];
          if (plan !== "free") agents.push("compliance-agent");

          for (const agent of agents) {
            await bus.emit("AGENT_REGISTERED", {
              agentId: `agent_${agent}_${tenantId.slice(4, 12)}`,
              name: agent, tenantId,
            }, { source: "workflow:tenant-onboarding", tenantId });
          }

          return ok({ tenantId, agents });
        },
      },
    ],
  };
}

// ============================================================================
// tenant-teardown
// ============================================================================

export function tenantTeardownWorkflow(bus: EventBus): WorkflowDefinition {
  return {
    name: "tenant-teardown",
    description: "Decommission a tenant: stop agents -> archive data -> delete",
    version: "1.0.0",
    steps: [
      {
        id: "stop-agents",
        name: "Stop all tenant agents",
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId } = ctx.params;
          if (!tenantId) return fail("tenantId required");

          await bus.emit("CONFIG_CHANGE", {
            event: "agents_stopped", tenantId,
          }, { source: "workflow:tenant-teardown", tenantId: tenantId as string });

          return ok({ tenantId, agentsStopped: true });
        },
      },
      {
        id: "archive-data",
        name: "Archive tenant data",
        dependsOn: ["stop-agents"],
        timeoutMs: 60_000,
        retries: 2,
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId } = ctx.params;

          await bus.emit("DATA_EXPORT", {
            event: "tenant_archived", tenantId,
            destination: "r2-archive",
          }, { source: "workflow:tenant-teardown", tenantId: tenantId as string });

          return ok({ tenantId, archived: true });
        },
      },
      {
        id: "delete-tenant",
        name: "Delete tenant record",
        dependsOn: ["archive-data"],
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId } = ctx.params;

          await bus.emit("TENANT_DELETED", {
            tenantId, reason: ctx.params.reason ?? "teardown workflow",
          }, { source: "workflow:tenant-teardown", tenantId: tenantId as string, severity: "HIGH" });

          return ok({ tenantId, deleted: true });
        },
      },
    ],
  };
}

// ============================================================================
// compliance-audit
// ============================================================================

export function complianceAuditWorkflow(bus: EventBus): WorkflowDefinition {
  return {
    name: "compliance-audit",
    description: "Gather events -> generate report -> anchor to chain",
    version: "1.0.0",
    steps: [
      {
        id: "gather-events",
        name: "Gather audit events",
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId, standard, fromTs } = ctx.params;
          const since = (fromTs as number) ?? Date.now() - 30 * 24 * 60 * 60 * 1000;

          // In production: queries tenant chain
          return ok({
            tenantId,
            standard: standard ?? "SOC2",
            periodStart: since,
            periodEnd: Date.now(),
          });
        },
      },
      {
        id: "generate-report",
        name: "Generate compliance report",
        dependsOn: ["gather-events"],
        timeoutMs: 30_000,
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId, standard } = ctx.stepOutputs["gather-events"] as any;

          await bus.emit("CONFIG_CHANGE", {
            event: "compliance_report_generated",
            tenantId, standard,
            workflowId: ctx.workflowId,
          }, { source: "workflow:compliance-audit", tenantId });

          return ok({ tenantId, standard, reportReady: true });
        },
      },
      {
        id: "anchor-to-chain",
        name: "Anchor report hash to blockchain",
        dependsOn: ["generate-report"],
        retries: 3,
        timeoutMs: 60_000,
        handler: async (ctx: WorkflowContext): Promise<StepResult> => {
          const { tenantId, standard } = ctx.stepOutputs["generate-report"] as any;

          await bus.emit("CONFIG_CHANGE", {
            event: "compliance_report_anchored",
            tenantId, standard,
            workflowId: ctx.workflowId,
          }, { source: "workflow:compliance-audit", tenantId });

          return ok({ tenantId, standard, anchored: true });
        },
      },
    ],
  };
}

// ============================================================================
// Register all built-in workflows
// ============================================================================

export function registerBuiltinWorkflows(
  engine: import("./engine.ts").WorkflowEngine,
  bus:    EventBus,
): void {
  engine.register(tenantOnboardingWorkflow(bus));
  engine.register(tenantTeardownWorkflow(bus));
  engine.register(complianceAuditWorkflow(bus));
}
