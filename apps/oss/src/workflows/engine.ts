// Sovereignly Workflow Engine -- MIT License
//
// DAG-based workflow execution. Each step emits events.
// All workflows are policy-gated and fully auditable.
//
// From WORKFLOWS.md:
//   tenant-onboarding: create tenant -> provision database -> deploy runtime -> start agents
//
// From SYSTEM_BIBLE.md:
//   Event-driven architecture, observability and auditability

import type { EventBus } from "../events/bus.ts";
import type { PolicyEngine } from "../policies/engine.ts";

// -- Types --

export type StepStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type WorkflowStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface WorkflowStep {
  id:           string;
  name:         string;
  handler:      StepHandler;
  dependsOn?:   string[];     // step IDs that must complete first
  retries?:     number;       // max retry attempts (default 0)
  timeoutMs?:   number;       // step timeout (default 30s)
  condition?:   (ctx: WorkflowContext) => boolean;  // skip if returns false
}

export type StepHandler = (ctx: WorkflowContext) => Promise<StepResult>;

export interface StepResult {
  ok:       boolean;
  output?:  Record<string, unknown>;
  error?:   string;
}

export interface WorkflowDefinition {
  name:         string;
  description:  string;
  steps:        WorkflowStep[];
  version:      string;
}

export interface WorkflowContext {
  workflowId:   string;
  tenantId?:    string;
  params:       Record<string, unknown>;
  stepOutputs:  Record<string, unknown>;  // accumulated outputs from completed steps
  startedAt:    number;
}

export interface WorkflowInstance {
  id:           string;
  name:         string;
  status:       WorkflowStatus;
  tenantId?:    string;
  params:       Record<string, unknown>;
  steps:        StepState[];
  startedAt:    number;
  completedAt?: number;
  error?:       string;
}

interface StepState {
  id:           string;
  name:         string;
  status:       StepStatus;
  startedAt?:   number;
  completedAt?: number;
  output?:      Record<string, unknown>;
  error?:       string;
  attempts:     number;
}

// -- Engine --

export class WorkflowEngine {
  private definitions = new Map<string, WorkflowDefinition>();
  private instances   = new Map<string, WorkflowInstance>();
  private running     = new Map<string, AbortController>();

  constructor(
    private bus:    EventBus,
    private policy: PolicyEngine,
  ) {}

  // Register a workflow definition
  register(def: WorkflowDefinition): void {
    this.definitions.set(def.name, def);
  }

  // List registered definitions
  listDefinitions(): WorkflowDefinition[] {
    return Array.from(this.definitions.values());
  }

  // Trigger a workflow
  async trigger(
    name:      string,
    params:    Record<string, unknown> = {},
    tenantId?: string,
    triggeredBy = "system",
  ): Promise<WorkflowInstance> {
    const def = this.definitions.get(name);
    if (!def) throw new Error(`Workflow '${name}' not registered`);

    // Policy check
    const eval_ = this.policy.evaluate("workflow.trigger", {
      tenantId, workflowName: name, triggeredBy,
    });
    if (!eval_.allowed) throw new Error(eval_.reason ?? "Policy denied");

    const id = `wf_${crypto.randomUUID().slice(0, 16)}`;
    const instance: WorkflowInstance = {
      id, name, status: "running", tenantId, params,
      steps: def.steps.map(s => ({
        id: s.id, name: s.name, status: "pending" as StepStatus,
        attempts: 0,
      })),
      startedAt: Date.now(),
    };

    this.instances.set(id, instance);
    const abort = new AbortController();
    this.running.set(id, abort);

    await this.bus.emit("WORKFLOW_STARTED", {
      workflowId: id, name, tenantId, params, triggeredBy,
      steps: def.steps.map(s => s.id),
    }, { source: "workflow-engine", tenantId });

    // Execute asynchronously
    this.execute(def, instance, abort.signal).catch(err => {
      console.warn(`[Workflow] ${id} execution error:`, err.message);
    });

    return instance;
  }

  // Cancel a running workflow
  cancel(workflowId: string): boolean {
    const ctrl = this.running.get(workflowId);
    if (!ctrl) return false;
    ctrl.abort();
    const inst = this.instances.get(workflowId);
    if (inst) {
      inst.status = "cancelled";
      inst.completedAt = Date.now();
    }
    void this.bus.emit("WORKFLOW_FAILED", {
      workflowId, reason: "cancelled",
    }, { source: "workflow-engine", tenantId: inst?.tenantId });
    return true;
  }

  // Get workflow status
  get(id: string): WorkflowInstance | undefined {
    return this.instances.get(id);
  }

  // List all instances
  list(opts?: { status?: WorkflowStatus; tenantId?: string; limit?: number }): WorkflowInstance[] {
    let results = Array.from(this.instances.values());
    if (opts?.status)   results = results.filter(w => w.status === opts.status);
    if (opts?.tenantId) results = results.filter(w => w.tenantId === opts.tenantId);
    results.sort((a, b) => b.startedAt - a.startedAt);
    return results.slice(0, opts?.limit ?? 50);
  }

  // Stats
  stats() {
    const all = Array.from(this.instances.values());
    return {
      definitions: this.definitions.size,
      total:       all.length,
      running:     all.filter(w => w.status === "running").length,
      completed:   all.filter(w => w.status === "completed").length,
      failed:      all.filter(w => w.status === "failed").length,
    };
  }

  // -- Internal execution --

  private async execute(
    def:      WorkflowDefinition,
    instance: WorkflowInstance,
    signal:   AbortSignal,
  ): Promise<void> {
    const ctx: WorkflowContext = {
      workflowId:  instance.id,
      tenantId:    instance.tenantId,
      params:      instance.params,
      stepOutputs: {},
      startedAt:   instance.startedAt,
    };

    const completed = new Set<string>();

    // Topological execution: run steps whose dependencies are met
    while (true) {
      if (signal.aborted) return;

      // Find next runnable steps
      const runnable = def.steps.filter(step => {
        const state = instance.steps.find(s => s.id === step.id)!;
        if (state.status !== "pending") return false;
        // Check dependencies
        if (step.dependsOn?.length) {
          return step.dependsOn.every(dep => completed.has(dep));
        }
        return true;
      });

      if (runnable.length === 0) {
        // No more steps to run
        const anyFailed = instance.steps.some(s => s.status === "failed");
        instance.status = anyFailed ? "failed" : "completed";
        instance.completedAt = Date.now();

        await this.bus.emit(
          anyFailed ? "WORKFLOW_FAILED" : "WORKFLOW_COMPLETED",
          {
            workflowId: instance.id, name: instance.name,
            durationMs: instance.completedAt - instance.startedAt,
            steps: instance.steps.map(s => ({ id: s.id, status: s.status })),
          },
          { source: "workflow-engine", tenantId: instance.tenantId }
        );

        this.running.delete(instance.id);
        return;
      }

      // Execute runnable steps in parallel
      await Promise.all(runnable.map(step =>
        this.executeStep(step, instance, ctx, signal)
          .then(() => completed.add(step.id))
      ));
    }
  }

  private async executeStep(
    step:     WorkflowStep,
    instance: WorkflowInstance,
    ctx:      WorkflowContext,
    signal:   AbortSignal,
  ): Promise<void> {
    const state = instance.steps.find(s => s.id === step.id)!;

    // Condition check
    if (step.condition && !step.condition(ctx)) {
      state.status = "skipped";
      await this.bus.emit("WORKFLOW_STEP_COMPLETED", {
        workflowId: instance.id, stepId: step.id, status: "skipped",
      }, { source: "workflow-engine", tenantId: instance.tenantId });
      return;
    }

    state.status = "running";
    state.startedAt = Date.now();

    const maxAttempts = (step.retries ?? 0) + 1;
    const timeout = step.timeoutMs ?? 30_000;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (signal.aborted) return;
      state.attempts = attempt;

      try {
        const result = await Promise.race([
          step.handler(ctx),
          new Promise<StepResult>((_, reject) =>
            setTimeout(() => reject(new Error("Step timeout")), timeout)
          ),
        ]);

        if (result.ok) {
          state.status = "completed";
          state.completedAt = Date.now();
          state.output = result.output;
          if (result.output) {
            ctx.stepOutputs[step.id] = result.output;
          }

          await this.bus.emit("WORKFLOW_STEP_COMPLETED", {
            workflowId: instance.id, stepId: step.id, stepName: step.name,
            status: "completed", durationMs: state.completedAt - state.startedAt!,
            attempt, output: result.output,
          }, { source: "workflow-engine", tenantId: instance.tenantId });
          return;
        }

        // Step returned ok: false
        if (attempt === maxAttempts) {
          state.status = "failed";
          state.error = result.error ?? "Step returned failure";
          state.completedAt = Date.now();

          await this.bus.emit("WORKFLOW_STEP_COMPLETED", {
            workflowId: instance.id, stepId: step.id, stepName: step.name,
            status: "failed", error: state.error, attempt,
          }, { severity: "HIGH", source: "workflow-engine", tenantId: instance.tenantId });
        }
        // Otherwise retry
      } catch (err: any) {
        if (attempt === maxAttempts) {
          state.status = "failed";
          state.error = err.message;
          state.completedAt = Date.now();

          await this.bus.emit("WORKFLOW_STEP_COMPLETED", {
            workflowId: instance.id, stepId: step.id, stepName: step.name,
            status: "failed", error: err.message, attempt,
          }, { severity: "HIGH", source: "workflow-engine", tenantId: instance.tenantId });
        }
      }
    }
  }

  close() {
    for (const [id, ctrl] of this.running) {
      ctrl.abort();
    }
    this.running.clear();
  }
}
