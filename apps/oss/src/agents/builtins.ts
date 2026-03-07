// Sovereignly Built-in Agents -- MIT License
//
// Agents that ship with the platform. Each follows the observe/plan/execute contract.
// All actions are policy-gated and event-driven.

import type {
  AgentDefinition, AgentContext, AgentObservation,
  AgentPlan, AgentReport, AgentSignal, PlannedAction,
} from "./runtime.ts";

// ============================================================================
// health-monitor
// ============================================================================
// Watches platform metrics. Triggers alerts and self-healing workflows
// when degradation is detected.

export const healthMonitorAgent: AgentDefinition = {
  id:          "agent_health_monitor",
  name:        "health-monitor",
  description: "Monitors system health, triggers alerts on degradation",
  version:     "1.0.0",
  scope:       "platform",
  schedule:    30_000,   // every 30s
  events:      ["ANOMALY", "MACHINE_FAILED"],

  handler: {
    async observe(ctx: AgentContext): Promise<AgentObservation> {
      const metrics = ctx.getMetrics() as any;
      const signals: AgentSignal[] = [];

      // Check error rates
      const recentAnomalies = ctx.queryEvents({ type: "ANOMALY", since: Date.now() - 300_000 });
      if (recentAnomalies.length > 5) {
        signals.push({
          type: "high_anomaly_rate",
          severity: "warning",
          value: recentAnomalies.length,
          source: "event-bus",
        });
      }

      // Check workflow failures
      if (metrics.workflows?.failed > metrics.workflows?.completed * 0.1) {
        signals.push({
          type: "high_workflow_failure_rate",
          severity: "warning",
          value: metrics.workflows.failed,
          source: "workflow-engine",
        });
      }

      // Check machine failures
      const machineFails = ctx.queryEvents({ type: "MACHINE_FAILED", since: Date.now() - 600_000 });
      if (machineFails.length > 0) {
        signals.push({
          type: "machine_failures",
          severity: "critical",
          value: machineFails.length,
          source: "machine-registry",
        });
      }

      return {
        signals,
        summary: signals.length === 0
          ? "All systems nominal"
          : `${signals.length} signal(s) detected: ${signals.map(s => s.type).join(", ")}`,
        timestamp: Date.now(),
      };
    },

    async plan(ctx: AgentContext, obs: AgentObservation): Promise<AgentPlan> {
      const actions: PlannedAction[] = [];

      for (const signal of obs.signals) {
        switch (signal.type) {
          case "high_anomaly_rate":
            actions.push({
              type: "emit_event",
              params: { type: "ANOMALY", payload: { alert: "high_anomaly_rate", count: signal.value } },
              reason: `${signal.value} anomalies in last 5 minutes`,
            });
            break;

          case "machine_failures":
            actions.push({
              type: "alert",
              params: { level: "critical", message: `${signal.value} machine failure(s) detected` },
              reason: "Machine failures require operator attention",
            });
            break;

          case "high_workflow_failure_rate":
            actions.push({
              type: "emit_event",
              params: { type: "ANOMALY", payload: { alert: "workflow_failure_spike" } },
              reason: "Workflow failure rate exceeds 10%",
            });
            break;
        }
      }

      if (actions.length === 0) {
        actions.push({ type: "noop", params: {}, reason: "No action needed" });
      }

      return {
        actions,
        reasoning: obs.signals.length === 0
          ? "System healthy, no intervention needed"
          : `Responding to ${obs.signals.length} signal(s)`,
      };
    },

    async execute(ctx: AgentContext, plan: AgentPlan): Promise<AgentReport> {
      const start = Date.now();
      const results: AgentReport["results"] = [];

      for (const action of plan.actions) {
        try {
          switch (action.type) {
            case "emit_event":
              await ctx.emitEvent(
                action.params.type as string,
                action.params.payload as Record<string, unknown>,
              );
              results.push({ action: action.type, ok: true, detail: action.reason });
              break;

            case "trigger_workflow":
              const wfId = await ctx.triggerWorkflow(
                action.params.name as string,
                action.params.params as Record<string, unknown>,
              );
              results.push({ action: action.type, ok: true, detail: `workflow: ${wfId}` });
              break;

            case "alert":
              await ctx.emitEvent("ANOMALY", {
                agent: "health-monitor",
                level: action.params.level,
                message: action.params.message,
              });
              results.push({ action: "alert", ok: true, detail: action.params.message as string });
              break;

            case "noop":
              results.push({ action: "noop", ok: true });
              break;
          }
        } catch (err: any) {
          results.push({ action: action.type, ok: false, detail: err.message });
        }
      }

      return {
        ok: results.every(r => r.ok),
        actions: results.length,
        results,
        durationMs: Date.now() - start,
      };
    },
  },
};

// ============================================================================
// compliance-agent
// ============================================================================
// Monitors events for compliance violations. Flags policy breaches.

export const complianceAgent: AgentDefinition = {
  id:          "agent_compliance",
  name:        "compliance-agent",
  description: "Monitors events for compliance violations and policy breaches",
  version:     "1.0.0",
  scope:       "platform",
  schedule:    60_000,   // every 60s
  events:      ["AUTH_FAILURE", "POLICY_VIOLATED", "DATA_EXPORT"],

  handler: {
    async observe(ctx: AgentContext): Promise<AgentObservation> {
      const signals: AgentSignal[] = [];
      const window = Date.now() - 300_000; // 5 min

      // Auth failures (brute force indicator)
      const authFails = ctx.queryEvents({ type: "AUTH_FAILURE", since: window });
      if (authFails.length > 10) {
        signals.push({
          type: "excessive_auth_failures",
          severity: "critical",
          value: authFails.length,
          source: "auth",
        });
      }

      // Unauthorized data exports
      const exports = ctx.queryEvents({ type: "DATA_EXPORT", since: window });
      if (exports.length > 3) {
        signals.push({
          type: "frequent_data_exports",
          severity: "warning",
          value: exports.length,
          source: "data-access",
        });
      }

      return {
        signals,
        summary: signals.length === 0
          ? "No compliance issues detected"
          : `${signals.length} compliance signal(s)`,
        timestamp: Date.now(),
      };
    },

    async plan(_ctx: AgentContext, obs: AgentObservation): Promise<AgentPlan> {
      const actions: PlannedAction[] = [];

      for (const signal of obs.signals) {
        if (signal.severity === "critical") {
          actions.push({
            type: "emit_event",
            params: {
              type: "POLICY_VIOLATED",
              payload: { signal: signal.type, value: signal.value, source: signal.source },
            },
            reason: `Critical compliance signal: ${signal.type}`,
          });
        } else {
          actions.push({
            type: "emit_event",
            params: {
              type: "ANOMALY",
              payload: { compliance: true, signal: signal.type, value: signal.value },
            },
            reason: `Compliance warning: ${signal.type}`,
          });
        }
      }

      if (actions.length === 0) {
        actions.push({ type: "noop", params: {}, reason: "Compliant" });
      }

      return { actions, reasoning: `${actions.length} compliance action(s)` };
    },

    async execute(ctx: AgentContext, plan: AgentPlan): Promise<AgentReport> {
      const start = Date.now();
      const results: AgentReport["results"] = [];

      for (const action of plan.actions) {
        if (action.type === "emit_event") {
          await ctx.emitEvent(
            action.params.type as string,
            action.params.payload as Record<string, unknown>,
          );
          results.push({ action: "compliance_alert", ok: true, detail: action.reason });
        } else {
          results.push({ action: "noop", ok: true });
        }
      }

      return { ok: true, actions: results.length, results, durationMs: Date.now() - start };
    },
  },
};

// ============================================================================
// cost-optimizer
// ============================================================================
// Analyzes resource usage patterns and suggests optimizations.

export const costOptimizerAgent: AgentDefinition = {
  id:          "agent_cost_optimizer",
  name:        "cost-optimizer",
  description: "Analyzes usage patterns and suggests cost optimizations",
  version:     "1.0.0",
  scope:       "platform",
  schedule:    300_000,  // every 5 min

  handler: {
    async observe(ctx: AgentContext): Promise<AgentObservation> {
      const signals: AgentSignal[] = [];
      const metrics = ctx.getMetrics() as any;

      // Check if there are idle machines
      const machineStarts = ctx.queryEvents({ type: "MACHINE_STARTED", since: Date.now() - 3600_000 });
      const machineStops  = ctx.queryEvents({ type: "MACHINE_STOPPED", since: Date.now() - 3600_000 });
      const activeMachines = machineStarts.length - machineStops.length;

      if (activeMachines > 3 && metrics.workflows?.running === 0) {
        signals.push({
          type: "idle_machines",
          severity: "info",
          value: activeMachines,
          source: "machine-registry",
        });
      }

      return {
        signals,
        summary: signals.length === 0
          ? "Resource usage optimal"
          : `${signals.length} optimization opportunity(ies)`,
        timestamp: Date.now(),
      };
    },

    async plan(_ctx: AgentContext, obs: AgentObservation): Promise<AgentPlan> {
      const actions: PlannedAction[] = [];

      for (const signal of obs.signals) {
        if (signal.type === "idle_machines") {
          actions.push({
            type: "emit_event",
            params: {
              type: "CONFIG_CHANGE",
              payload: { suggestion: "scale_down", idleMachines: signal.value },
            },
            reason: `${signal.value} machines idle with no running workflows`,
          });
        }
      }

      if (actions.length === 0) {
        actions.push({ type: "noop", params: {}, reason: "No optimizations found" });
      }

      return { actions, reasoning: `${actions.length} optimization(s)` };
    },

    async execute(ctx: AgentContext, plan: AgentPlan): Promise<AgentReport> {
      const start = Date.now();
      const results: AgentReport["results"] = [];

      for (const action of plan.actions) {
        if (action.type === "emit_event") {
          await ctx.emitEvent(
            action.params.type as string,
            action.params.payload as Record<string, unknown>,
          );
          results.push({ action: "optimization_suggested", ok: true, detail: action.reason });
        } else {
          results.push({ action: "noop", ok: true });
        }
      }

      return { ok: true, actions: results.length, results, durationMs: Date.now() - start };
    },
  },
};

// ============================================================================
// Register all built-in agents
// ============================================================================

export function registerBuiltinAgents(runtime: import("./runtime.ts").AgentRuntime): void {
  runtime.register(healthMonitorAgent);
  runtime.register(complianceAgent);
  runtime.register(costOptimizerAgent);

  // Start platform agents
  runtime.start("agent_health_monitor");
  runtime.start("agent_compliance");
  runtime.start("agent_cost_optimizer");
}
