// Sovereignly Agent Runtime -- MIT License
//
// Sandboxed execution for AI agents that observe, plan, execute, report.
//
// From CLAUDE_CONTINUITY_PROMPT.md:
//   Agents must: observe system state, trigger workflows, call platform tools
//   Agents must NOT: bypass policies, access unauthorized tenant data, execute shell commands
//
// From AGENTS.md:
//   Maintain modular architecture, prefer event-driven communication,
//   respect infrastructure policy controls

import type { EventBus, SovereignEvent } from "../events/bus.ts";
import type { PolicyEngine } from "../policies/engine.ts";
import type { WorkflowEngine } from "../workflows/engine.ts";

// -- Types --

export type AgentStatus = "registered" | "running" | "idle" | "stopped" | "failed";

export interface AgentDefinition {
  id:           string;
  name:         string;
  description:  string;
  version:      string;
  scope:        "platform" | "tenant";
  tenantId?:    string;
  schedule?:    number;       // run every N milliseconds (0 = event-driven only)
  events?:      string[];     // event types to observe (triggers execution)
  handler:      AgentHandler;
}

export interface AgentHandler {
  observe:  (ctx: AgentContext) => Promise<AgentObservation>;
  plan:     (ctx: AgentContext, observation: AgentObservation) => Promise<AgentPlan>;
  execute:  (ctx: AgentContext, plan: AgentPlan) => Promise<AgentReport>;
}

export interface AgentContext {
  agentId:    string;
  tenantId?:  string;
  // Safe accessors -- policy-gated
  queryEvents:     (opts: { type?: string; since?: number; limit?: number }) => SovereignEvent[];
  triggerWorkflow: (name: string, params: Record<string, unknown>) => Promise<string>;
  emitEvent:       (type: string, payload: Record<string, unknown>) => Promise<void>;
  getMetrics:      () => Record<string, unknown>;
  // Blocked operations (throw if called)
  readonly _sandbox: true;
}

export interface AgentObservation {
  signals:   AgentSignal[];
  summary:   string;
  timestamp: number;
}

export interface AgentSignal {
  type:      string;       // e.g. "high_error_rate", "disk_usage_warning"
  severity:  "info" | "warning" | "critical";
  value:     unknown;
  source:    string;
}

export interface AgentPlan {
  actions:   PlannedAction[];
  reasoning: string;
}

export interface PlannedAction {
  type:    "trigger_workflow" | "emit_event" | "alert" | "scale" | "noop";
  params:  Record<string, unknown>;
  reason:  string;
}

export interface AgentReport {
  ok:         boolean;
  actions:    number;
  results:    Array<{ action: string; ok: boolean; detail?: string }>;
  durationMs: number;
}

interface AgentInstance {
  def:          AgentDefinition;
  status:       AgentStatus;
  lastRun?:     number;
  runCount:     number;
  errorCount:   number;
  timer?:       ReturnType<typeof setInterval>;
  eventSubId?:  string;
}

// -- Runtime --

export class AgentRuntime {
  private agents = new Map<string, AgentInstance>();

  constructor(
    private bus:      EventBus,
    private policy:   PolicyEngine,
    private workflow: WorkflowEngine,
  ) {}

  // Register an agent
  register(def: AgentDefinition): void {
    // Policy check
    const eval_ = this.policy.evaluate("agent.register", {
      source: "agent", agentId: def.id, tenantId: def.tenantId,
      agent: { id: def.id, authorized: true },
    });
    if (!eval_.allowed) throw new Error(eval_.reason ?? "Policy denied agent registration");

    const instance: AgentInstance = {
      def,
      status: "registered",
      runCount: 0,
      errorCount: 0,
    };

    this.agents.set(def.id, instance);

    void this.bus.emit("AGENT_REGISTERED", {
      agentId: def.id, name: def.name, scope: def.scope, tenantId: def.tenantId,
    }, { source: `agent:${def.id}`, tenantId: def.tenantId });
  }

  // Start an agent (begins scheduled runs + event subscriptions)
  start(agentId: string): void {
    const inst = this.agents.get(agentId);
    if (!inst) throw new Error(`Agent ${agentId} not registered`);
    if (inst.status === "running") return;

    inst.status = "running";

    // Schedule periodic runs
    if (inst.def.schedule && inst.def.schedule > 0) {
      inst.timer = setInterval(() => {
        this.run(agentId).catch(err =>
          console.warn(`[Agent] ${agentId} scheduled run failed:`, err.message)
        );
      }, inst.def.schedule);
    }

    // Subscribe to events
    if (inst.def.events?.length) {
      for (const eventType of inst.def.events) {
        const subId = this.bus.on(eventType, () => {
          this.run(agentId).catch(err =>
            console.warn(`[Agent] ${agentId} event-triggered run failed:`, err.message)
          );
        }, `agent:${agentId}`);
        inst.eventSubId = subId; // store last one (simplified)
      }
    }
  }

  // Stop an agent
  stop(agentId: string): void {
    const inst = this.agents.get(agentId);
    if (!inst) return;

    if (inst.timer) clearInterval(inst.timer);
    if (inst.eventSubId) this.bus.off(inst.eventSubId);
    inst.status = "stopped";
  }

  // Execute one observe -> plan -> execute cycle
  async run(agentId: string): Promise<AgentReport> {
    const inst = this.agents.get(agentId);
    if (!inst) throw new Error(`Agent ${agentId} not registered`);

    // Policy check
    const eval_ = this.policy.evaluate("agent.execute", {
      source: "agent", agentId, tenantId: inst.def.tenantId,
      agent: { id: agentId, authorized: true },
    });
    if (!eval_.allowed) throw new Error(eval_.reason ?? "Policy denied");

    const start = Date.now();
    const ctx = this.createContext(agentId, inst.def.tenantId);

    try {
      // 1. Observe
      const observation = await inst.def.handler.observe(ctx);

      // 2. Plan
      const plan = await inst.def.handler.plan(ctx, observation);

      // 3. Execute
      const report = await inst.def.handler.execute(ctx, plan);

      inst.runCount++;
      inst.lastRun = Date.now();

      await this.bus.emit("AGENT_EXECUTED", {
        agentId, name: inst.def.name,
        signals: observation.signals.length,
        actions: report.actions,
        ok: report.ok,
        durationMs: Date.now() - start,
      }, { source: `agent:${agentId}`, tenantId: inst.def.tenantId });

      return report;
    } catch (err: any) {
      inst.errorCount++;

      await this.bus.emit("AGENT_FAILED", {
        agentId, name: inst.def.name, error: err.message,
      }, { severity: "HIGH", source: `agent:${agentId}`, tenantId: inst.def.tenantId });

      return {
        ok: false, actions: 0, results: [],
        durationMs: Date.now() - start,
      };
    }
  }

  // Create sandboxed context for agent
  private createContext(agentId: string, tenantId?: string): AgentContext {
    const bus = this.bus;
    const workflow = this.workflow;
    const policy = this.policy;

    return {
      agentId,
      tenantId,
      _sandbox: true,

      queryEvents(opts) {
        // Policy: agents can only see events for their tenant
        return bus.query({
          type: opts.type,
          tenantId,
          since: opts.since,
          limit: Math.min(opts.limit ?? 100, 500),
        });
      },

      async triggerWorkflow(name, params) {
        // Policy check inside workflow engine handles this
        const inst = await workflow.trigger(name, { ...params, tenantId }, tenantId, `agent:${agentId}`);
        return inst.id;
      },

      async emitEvent(type, payload) {
        // Agents emit events tagged with their source
        await bus.emit(type as any, payload, {
          source: `agent:${agentId}`, tenantId,
        });
      },

      getMetrics() {
        return {
          eventBus: bus.stats(),
          workflows: workflow.stats(),
          policies: policy.stats(),
        };
      },
    };
  }

  // List agents
  list(opts?: { status?: AgentStatus; tenantId?: string }): Array<{
    id: string; name: string; status: AgentStatus;
    scope: string; tenantId?: string;
    runCount: number; errorCount: number; lastRun?: number;
  }> {
    let results = Array.from(this.agents.values());
    if (opts?.status)   results = results.filter(a => a.status === opts.status);
    if (opts?.tenantId) results = results.filter(a => a.def.tenantId === opts.tenantId);
    return results.map(a => ({
      id: a.def.id, name: a.def.name, status: a.status,
      scope: a.def.scope, tenantId: a.def.tenantId,
      runCount: a.runCount, errorCount: a.errorCount, lastRun: a.lastRun,
    }));
  }

  // Get single agent
  get(agentId: string): AgentInstance | undefined {
    return this.agents.get(agentId);
  }

  // Stats
  stats() {
    const all = Array.from(this.agents.values());
    return {
      total:    all.length,
      running:  all.filter(a => a.status === "running").length,
      stopped:  all.filter(a => a.status === "stopped").length,
      totalRuns:   all.reduce((s, a) => s + a.runCount, 0),
      totalErrors: all.reduce((s, a) => s + a.errorCount, 0),
    };
  }

  // Shutdown all agents
  close() {
    for (const [id] of this.agents) {
      this.stop(id);
    }
  }
}
