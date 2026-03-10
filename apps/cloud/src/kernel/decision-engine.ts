// Sovereignly Decision Engine -- BSL License
//
// Takes health signals + policies -> decides actions.
// Rule-based (Phase 4). Upgradeable to ML in Phase 6.

import type { EventBus } from "../../../oss/src/events/bus.ts";
import type { PolicyEngine } from "../../../oss/src/policies/engine.ts";
import type { HealthAnalyzer } from "./health-analyzer.ts";
import type { StateRegistry } from "./state-registry.ts";

export interface Decision {
  id:         string;
  action:     string;
  target:     string;
  reason:     string;
  confidence: number;  // 0-1
  priority:   "low" | "medium" | "high" | "critical";
  approved:   boolean; // policy allowed it
  ts:         number;
}

export class DecisionEngine {
  private decisions: Decision[] = [];
  private maxHistory = 500;
  private interval: ReturnType<typeof setInterval>;

  constructor(
    private bus:     EventBus,
    private policy:  PolicyEngine,
    private health:  HealthAnalyzer,
    private state:   StateRegistry,
    opts?: { intervalMs?: number },
  ) {
    // Evaluate periodically (default 60s, configurable for single-node)
    this.interval = setInterval(() => this.evaluate(), opts?.intervalMs ?? 60_000);
  }

  evaluate(): Decision[] {
    const newDecisions: Decision[] = [];
    const signals = this.health.getSignals();
    const score = this.health.score();

    // Rule 1: Critical health -> recommend scale-up
    if (score.status === "critical") {
      newDecisions.push(this.decide(
        "scale_up", "platform",
        "Platform health critical -- recommend additional capacity",
        0.9, "critical",
      ));
    }

    // Rule 2: Failed machines -> recommend restart
    const failedMachines = this.state.list({ type: "machine", status: "failed" });
    for (const m of failedMachines) {
      newDecisions.push(this.decide(
        "machine_restart", m.id,
        `Machine ${m.id} failed -- recommend restart`,
        0.85, "high",
      ));
    }

    // Rule 3: Degraded tenants -> recommend investigation
    const degradedTenants = this.state.list({ type: "tenant", status: "degraded" });
    for (const t of degradedTenants) {
      newDecisions.push(this.decide(
        "tenant_investigate", t.id,
        `Tenant ${t.id} degraded -- recommend compliance audit`,
        0.7, "medium",
      ));
    }

    // Rule 4: Idle resources -> recommend scale-down
    const activeMachines = this.state.list({ type: "machine", status: "active" });
    const activeWorkflows = this.state.list({ type: "workflow", status: "active" });
    if (activeMachines.length > 2 && activeWorkflows.length === 0) {
      newDecisions.push(this.decide(
        "scale_down", "platform",
        `${activeMachines.length} active machines with 0 workflows -- reduce capacity`,
        0.6, "low",
      ));
    }

    // Store
    this.decisions.push(...newDecisions);
    if (this.decisions.length > this.maxHistory) {
      this.decisions = this.decisions.slice(-this.maxHistory);
    }

    // Emit decisions
    for (const d of newDecisions) {
      void this.bus.emit("CONFIG_CHANGE", {
        event: "decision_made", decisionId: d.id,
        action: d.action, target: d.target, approved: d.approved,
        confidence: d.confidence, priority: d.priority,
      }, { source: "decision-engine", severity: d.priority === "critical" ? "HIGH" : "LOW" });
    }

    return newDecisions;
  }

  private decide(action: string, target: string, reason: string, confidence: number, priority: Decision["priority"]): Decision {
    const eval_ = this.policy.evaluate(`kernel.${action}`, { target });
    return {
      id:         `dec_${crypto.randomUUID().slice(0, 12)}`,
      action, target, reason, confidence, priority,
      approved:   eval_.allowed,
      ts:         Date.now(),
    };
  }

  recent(limit = 20): Decision[] {
    return this.decisions.slice(-limit).reverse();
  }

  stats() {
    return {
      total:     this.decisions.length,
      approved:  this.decisions.filter(d => d.approved).length,
      denied:    this.decisions.filter(d => !d.approved).length,
      byAction:  this.decisions.reduce((acc, d) => { acc[d.action] = (acc[d.action] ?? 0) + 1; return acc; }, {} as Record<string, number>),
    };
  }

  close() { clearInterval(this.interval); }
}
