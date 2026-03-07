// Sovereignly Health Analyzer -- BSL License
//
// Consumes health events. Detects degradation patterns.
// Triggers self-healing workflows via the workflow engine.

import type { EventBus, SovereignEvent } from "../../../oss/src/events/bus.ts";
import type { StateRegistry } from "./state-registry.ts";
import type { WorkflowEngine } from "../../../oss/src/workflows/engine.ts";

interface HealthSignal {
  entityId:  string;
  type:      string;
  severity:  "warning" | "critical";
  count:     number;
  window:    string;
  firstSeen: number;
}

export class HealthAnalyzer {
  private signals: HealthSignal[] = [];
  private anomalyWindow = new Map<string, number[]>(); // entityId -> timestamps
  private healingTriggered = new Set<string>();         // prevent duplicate healing
  private checkInterval: ReturnType<typeof setInterval>;
  private subId: string;

  constructor(
    private bus:      EventBus,
    private state:    StateRegistry,
    private workflow: WorkflowEngine,
  ) {
    // Listen to anomalies and failures
    this.subId = bus.on("*", (e) => this.ingest(e), "health-analyzer");

    // Periodic health sweep every 30s
    this.checkInterval = setInterval(() => this.sweep(), 30_000);
  }

  private ingest(event: SovereignEvent) {
    if (!["ANOMALY", "MACHINE_FAILED", "AGENT_FAILED", "WORKFLOW_FAILED"].includes(event.type)) return;

    const entityId = (event.payload.tenantId ?? event.payload.machineId ?? event.payload.agentId ?? "platform") as string;
    const window = this.anomalyWindow.get(entityId) ?? [];
    window.push(event.ts);
    // Keep last 5 minutes
    const cutoff = Date.now() - 300_000;
    this.anomalyWindow.set(entityId, window.filter(t => t > cutoff));
  }

  private sweep() {
    const now = Date.now();
    const cutoff = now - 300_000;
    this.signals = [];

    for (const [entityId, timestamps] of this.anomalyWindow) {
      const recent = timestamps.filter(t => t > cutoff);
      if (recent.length === 0) {
        this.anomalyWindow.delete(entityId);
        this.healingTriggered.delete(entityId);
        continue;
      }

      if (recent.length >= 5) {
        this.signals.push({
          entityId, type: "repeated_failures", severity: "critical",
          count: recent.length, window: "5m", firstSeen: recent[0],
        });

        // Trigger self-healing if not already triggered
        if (!this.healingTriggered.has(entityId)) {
          this.healingTriggered.add(entityId);
          this.triggerHealing(entityId, recent.length).catch(() => {});
        }
      } else if (recent.length >= 3) {
        this.signals.push({
          entityId, type: "degradation_pattern", severity: "warning",
          count: recent.length, window: "5m", firstSeen: recent[0],
        });
      }
    }
  }

  private async triggerHealing(entityId: string, failCount: number) {
    const entity = this.state.get(entityId);

    await this.bus.emit("CONFIG_CHANGE", {
      event: "self_healing_triggered",
      entityId, entityType: entity?.type ?? "unknown",
      failCount, action: "restart_assessment",
    }, { severity: "HIGH", source: "health-analyzer" });

    // If it's a tenant, trigger compliance audit to assess damage
    if (entity?.type === "tenant") {
      try {
        await this.workflow.trigger("compliance-audit", {
          tenantId: entityId, reason: "self-healing: repeated failures",
        }, entityId, "health-analyzer");
      } catch {}
    }
  }

  // Current health signals
  getSignals(): HealthSignal[] { return this.signals; }

  // Overall health score (0-100)
  score(): { score: number; status: string } {
    const degraded = this.state.list({ status: "degraded" }).length;
    const failed   = this.state.list({ status: "failed" }).length;
    const total    = Math.max(this.state.count(), 1);
    const healthyPct = ((total - degraded - failed * 2) / total) * 100;
    const score = Math.max(0, Math.min(100, Math.round(healthyPct)));
    return {
      score,
      status: score >= 90 ? "healthy" : score >= 70 ? "degraded" : "critical",
    };
  }

  stats() {
    const h = this.score();
    return {
      healthScore:    h.score,
      status:         h.status,
      activeSignals:  this.signals.length,
      healingActive:  this.healingTriggered.size,
      trackedEntities: this.anomalyWindow.size,
    };
  }

  close() {
    clearInterval(this.checkInterval);
    this.bus.off(this.subId);
  }
}
