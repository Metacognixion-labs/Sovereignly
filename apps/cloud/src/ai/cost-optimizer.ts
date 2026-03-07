// Sovereignly Cost Optimizer -- BSL License
//
// Phase 6: Distributed AI Orchestration
//
// Analyzes resource utilization across the cluster and
// recommends cost optimizations:
//   - Consolidate underutilized regions
//   - Right-size compute allocation
//   - Identify idle tenants consuming resources

import type { NodeRegistry } from "../cluster/node-registry.ts";
import type { StateRegistry } from "../kernel/state-registry.ts";

export interface CostInsight {
  id:          string;
  type:        "consolidate" | "right_size" | "idle_resource" | "over_provisioned";
  target:      string;
  message:     string;
  savingsPct:  number;   // estimated savings percentage
  priority:    "low" | "medium" | "high";
  timestamp:   number;
}

export class CostOptimizer {
  private insights: CostInsight[] = [];
  private maxHistory = 200;
  private interval: ReturnType<typeof setInterval>;

  constructor(
    private nodeRegistry: NodeRegistry,
    private stateRegistry: StateRegistry,
  ) {
    // Analyze every 5 minutes
    this.interval = setInterval(() => this.analyze(), 300_000);
  }

  /** Run cost analysis */
  analyze(): CostInsight[] {
    const newInsights: CostInsight[] = [];
    const nodes = this.nodeRegistry.list();
    const healthyCluster = this.nodeRegistry.healthy("cluster");

    // Insight 1: Regions with single low-utilization nodes (consolidation candidates)
    const regionGroups = new Map<string, typeof nodes>();
    for (const n of healthyCluster) {
      const group = regionGroups.get(n.region) ?? [];
      group.push(n);
      regionGroups.set(n.region, group);
    }

    for (const [region, regionNodes] of regionGroups) {
      const avgLoad = regionNodes.reduce((s, n) => s + n.load, 0) / regionNodes.length;
      if (regionNodes.length > 1 && avgLoad < 0.2) {
        newInsights.push({
          id:         `cost_${crypto.randomUUID().slice(0, 8)}`,
          type:       "consolidate",
          target:     region,
          message:    `Region ${region} has ${regionNodes.length} nodes at ${(avgLoad * 100).toFixed(0)}% avg load -- consolidation possible`,
          savingsPct: Math.round((1 - avgLoad) * 30),
          priority:   "medium",
          timestamp:  Date.now(),
        });
      }
    }

    // Insight 2: Over-provisioned cluster (many nodes, very low load)
    if (healthyCluster.length > 3) {
      const globalAvg = healthyCluster.reduce((s, n) => s + n.load, 0) / healthyCluster.length;
      if (globalAvg < 0.15) {
        newInsights.push({
          id:         `cost_${crypto.randomUUID().slice(0, 8)}`,
          type:       "over_provisioned",
          target:     "cluster",
          message:    `Cluster over-provisioned: ${healthyCluster.length} nodes at ${(globalAvg * 100).toFixed(0)}% avg load`,
          savingsPct: Math.round((1 - globalAvg / 0.5) * 40),
          priority:   "high",
          timestamp:  Date.now(),
        });
      }
    }

    // Insight 3: Idle tenants (no events in state registry for a while)
    const tenants = this.stateRegistry.list({ type: "tenant" });
    const now = Date.now();
    for (const t of tenants) {
      if (t.status === "active" && now - t.updatedAt > 7 * 24 * 3600_000) {
        newInsights.push({
          id:         `cost_${crypto.randomUUID().slice(0, 8)}`,
          type:       "idle_resource",
          target:     t.id,
          message:    `Tenant ${t.id} has been idle for >7 days`,
          savingsPct: 5,
          priority:   "low",
          timestamp:  now,
        });
      }
    }

    this.insights.push(...newInsights);
    if (this.insights.length > this.maxHistory) {
      this.insights = this.insights.slice(-this.maxHistory);
    }

    return newInsights;
  }

  recent(limit = 20): CostInsight[] {
    return this.insights.slice(-limit).reverse();
  }

  stats() {
    return {
      total:          this.insights.length,
      byType:         this.insights.reduce((acc, i) => { acc[i.type] = (acc[i.type] ?? 0) + 1; return acc; }, {} as Record<string, number>),
      avgSavingsPct:  this.insights.length > 0 ? Number((this.insights.reduce((s, i) => s + i.savingsPct, 0) / this.insights.length).toFixed(1)) : 0,
    };
  }

  close() { clearInterval(this.interval); }
}
