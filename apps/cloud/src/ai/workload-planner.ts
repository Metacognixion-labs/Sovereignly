// Sovereignly Workload Planner -- BSL License
//
// Phase 6: Distributed AI Orchestration
//
// Plans optimal placement of new workloads across the cluster network.
// Considers: latency, data residency, current load, cost, redundancy.
// Extends PlacementEngine with network-level awareness.

import type { NodeRegistry, SovereignNode } from "../cluster/node-registry.ts";
import type { PlacementEngine, PlacementRequest } from "../kernel/placement-engine.ts";

export interface WorkloadPlan {
  id:            string;
  workloadType:  string;
  tenantId?:     string;
  primaryNode:   string;
  primaryRegion: string;
  backupNode?:   string;
  backupRegion?: string;
  score:         number;
  reasoning:     string[];
  timestamp:     number;
}

export class WorkloadPlanner {
  private plans: WorkloadPlan[] = [];
  private maxHistory = 500;

  constructor(
    private nodeRegistry: NodeRegistry,
    private placement: PlacementEngine,
  ) {}

  /** Plan placement for a new workload */
  plan(req: PlacementRequest): WorkloadPlan {
    const reasoning: string[] = [];

    // Step 1: Use placement engine for region selection
    const placementResult = this.placement.place(req);
    reasoning.push(`Region selected: ${placementResult.region} (score: ${placementResult.score})`);
    reasoning.push(`Placement reasoning: ${placementResult.reasoning}`);

    // Step 2: Find best node in that region
    const regionNodes = this.nodeRegistry.healthy("cluster")
      .filter(n => n.region === placementResult.region)
      .sort((a, b) => a.load - b.load);

    let primaryNode: string;
    if (regionNodes.length > 0) {
      primaryNode = regionNodes[0].nodeId;
      reasoning.push(`Primary node: ${primaryNode} (load: ${(regionNodes[0].load * 100).toFixed(0)}%)`);
    } else {
      // Fallback: any healthy cluster node with lowest load
      const anyNode = this.nodeRegistry.healthy("cluster").sort((a, b) => a.load - b.load)[0];
      primaryNode = anyNode?.nodeId ?? "local";
      reasoning.push(`No nodes in ${placementResult.region}, fallback to ${primaryNode}`);
    }

    // Step 3: Select backup node (different region if possible)
    let backupNode: string | undefined;
    let backupRegion: string | undefined;
    if (placementResult.alternatives.length > 0) {
      const altRegion = placementResult.alternatives[0].region;
      const altNodes = this.nodeRegistry.healthy("cluster")
        .filter(n => n.region === altRegion)
        .sort((a, b) => a.load - b.load);
      if (altNodes.length > 0) {
        backupNode = altNodes[0].nodeId;
        backupRegion = altRegion;
        reasoning.push(`Backup: ${backupNode} in ${altRegion}`);
      }
    }

    const plan: WorkloadPlan = {
      id:            `wplan_${crypto.randomUUID().slice(0, 8)}`,
      workloadType:  req.workloadType,
      tenantId:      req.tenantId,
      primaryNode,
      primaryRegion: placementResult.region,
      backupNode,
      backupRegion,
      score:         placementResult.score,
      reasoning,
      timestamp:     Date.now(),
    };

    this.plans.push(plan);
    if (this.plans.length > this.maxHistory) {
      this.plans = this.plans.slice(-this.maxHistory);
    }

    return plan;
  }

  recent(limit = 20): WorkloadPlan[] {
    return this.plans.slice(-limit).reverse();
  }

  stats() {
    return {
      totalPlans:  this.plans.length,
      byWorkload:  this.plans.reduce((acc, p) => { acc[p.workloadType] = (acc[p.workloadType] ?? 0) + 1; return acc; }, {} as Record<string, number>),
    };
  }
}
