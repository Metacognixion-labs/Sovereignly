// Sovereignly Cluster Balancer -- BSL License
//
// Phase 6: Distributed AI Orchestration
//
// Monitors cluster load across the network and recommends
// workload rebalancing between regions/nodes.
// Extends the existing DecisionEngine with cross-cluster awareness.

import type { EventBus } from "../../../oss/src/events/bus.ts";
import type { NodeRegistry, SovereignNode } from "../cluster/node-registry.ts";

export interface BalanceRecommendation {
  id:          string;
  type:        "migrate_workload" | "scale_region" | "drain_node";
  fromNode:    string;
  toNode?:     string;
  reason:      string;
  loadDelta:   number;    // expected improvement
  priority:    "low" | "medium" | "high";
  timestamp:   number;
}

const LOAD_HIGH_THRESHOLD = 0.8;
const LOAD_LOW_THRESHOLD  = 0.2;
const IMBALANCE_THRESHOLD = 0.4;  // max difference between nodes before rebalancing

export class ClusterBalancer {
  private recommendations: BalanceRecommendation[] = [];
  private maxHistory = 200;
  private interval: ReturnType<typeof setInterval> | null = null;

  constructor(
    private bus: EventBus,
    private nodeRegistry: NodeRegistry,
    opts?: { enabled?: boolean },
  ) {
    if (opts?.enabled !== false) {
      this.interval = setInterval(() => this.evaluate(), 60_000);
    }
  }

  /** Evaluate cluster balance and generate recommendations */
  evaluate(): BalanceRecommendation[] {
    const newRecs: BalanceRecommendation[] = [];
    const clusterNodes = this.nodeRegistry.healthy("cluster");

    if (clusterNodes.length < 2) return newRecs;

    const loads = clusterNodes.map(n => ({ node: n, load: n.load }));
    loads.sort((a, b) => b.load - a.load);

    const maxLoad = loads[0];
    const minLoad = loads[loads.length - 1];

    // Check for imbalance
    if (maxLoad.load - minLoad.load > IMBALANCE_THRESHOLD) {
      newRecs.push({
        id:        `bal_${crypto.randomUUID().slice(0, 8)}`,
        type:      "migrate_workload",
        fromNode:  maxLoad.node.nodeId,
        toNode:    minLoad.node.nodeId,
        reason:    `Load imbalance: ${maxLoad.node.nodeId} at ${(maxLoad.load * 100).toFixed(0)}%, ${minLoad.node.nodeId} at ${(minLoad.load * 100).toFixed(0)}%`,
        loadDelta: maxLoad.load - minLoad.load,
        priority:  maxLoad.load > 0.9 ? "high" : "medium",
        timestamp: Date.now(),
      });
    }

    // Check for overloaded nodes
    for (const { node } of loads) {
      if (node.load > LOAD_HIGH_THRESHOLD) {
        newRecs.push({
          id:        `bal_${crypto.randomUUID().slice(0, 8)}`,
          type:      "scale_region",
          fromNode:  node.nodeId,
          reason:    `Node ${node.nodeId} overloaded at ${(node.load * 100).toFixed(0)}% -- scale region ${node.region}`,
          loadDelta: node.load - LOAD_HIGH_THRESHOLD,
          priority:  node.load > 0.95 ? "high" : "medium",
          timestamp: Date.now(),
        });
      }
    }

    // Check for underutilized nodes (potential drain candidates)
    const underutilized = loads.filter(l => l.load < LOAD_LOW_THRESHOLD);
    if (underutilized.length > 1 && clusterNodes.length > 3) {
      const drain = underutilized[underutilized.length - 1];
      newRecs.push({
        id:        `bal_${crypto.randomUUID().slice(0, 8)}`,
        type:      "drain_node",
        fromNode:  drain.node.nodeId,
        reason:    `Node ${drain.node.nodeId} underutilized at ${(drain.load * 100).toFixed(0)}% -- candidate for draining`,
        loadDelta: drain.load,
        priority:  "low",
        timestamp: Date.now(),
      });
    }

    // Store and emit
    this.recommendations.push(...newRecs);
    if (this.recommendations.length > this.maxHistory) {
      this.recommendations = this.recommendations.slice(-this.maxHistory);
    }

    for (const rec of newRecs) {
      void this.bus.emit("CONFIG_CHANGE", {
        event: "balance_recommendation",
        ...rec,
      }, { source: "cluster-balancer", severity: rec.priority === "high" ? "HIGH" : "LOW" });
    }

    return newRecs;
  }

  recent(limit = 20): BalanceRecommendation[] {
    return this.recommendations.slice(-limit).reverse();
  }

  stats() {
    return {
      total:          this.recommendations.length,
      byType:         this.recommendations.reduce((acc, r) => { acc[r.type] = (acc[r.type] ?? 0) + 1; return acc; }, {} as Record<string, number>),
      clusterNodes:   this.nodeRegistry.healthy("cluster").length,
      avgLoad:        this.nodeRegistry.stats().avgLoad,
    };
  }

  close() { if (this.interval) clearInterval(this.interval); }
}
