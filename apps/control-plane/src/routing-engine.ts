// Sovereignly Control Plane — Routing Engine
// BSL License — MetaCognixion
//
// Routes requests to the optimal cluster/node based on:
//   1. Latency (geo-proximity)
//   2. Tenant residency policy
//   3. Cluster capacity
//   4. Node health

import type { ControlPlaneNodeRegistry, SovereignNode } from "./node-registry.ts";
import type { ClusterManager } from "./cluster-manager.ts";
import type { PolicyAuthority } from "./policy-authority.ts";

export interface RoutingRequest {
  tenantId?:      string;
  sourceRegion?:  string;
  residency?:     string;   // "EU", "US", "ASIA"
  workloadType?:  string;
}

export interface RoutingResult {
  targetNode:    string;
  targetRegion:  string;
  targetCluster: string;
  score:         number;
  reasoning:     string[];
  alternatives:  Array<{ node: string; region: string; score: number }>;
}

// Geo-proximity scoring: lower distance = higher score
const REGION_PROXIMITY: Record<string, Record<string, number>> = {
  "us-east":    { "us-east": 0, "us-west": 30, "europe": 50, "asia": 80, "middle-east": 60, "south-america": 40 },
  "us-west":    { "us-west": 0, "us-east": 30, "asia": 50, "europe": 60, "south-america": 50, "middle-east": 70 },
  "europe":     { "europe": 0, "middle-east": 30, "us-east": 50, "us-west": 60, "asia": 60, "south-america": 70 },
  "asia":       { "asia": 0, "middle-east": 40, "us-west": 50, "europe": 60, "us-east": 80, "south-america": 90 },
  "middle-east": { "middle-east": 0, "europe": 30, "asia": 40, "us-east": 60, "us-west": 70, "south-america": 80 },
  "south-america": { "south-america": 0, "us-east": 40, "us-west": 50, "europe": 70, "middle-east": 80, "asia": 90 },
};

const RESIDENCY_REGIONS: Record<string, string[]> = {
  EU:   ["europe"],
  US:   ["us-east", "us-west"],
  ASIA: ["asia"],
  ME:   ["middle-east"],
  SA:   ["south-america"],
};

export class RoutingEngine {
  constructor(
    private nodeRegistry: ControlPlaneNodeRegistry,
    private clusterManager: ClusterManager,
    private policyAuthority: PolicyAuthority,
  ) {}

  /** Route a request to the optimal node */
  route(req: RoutingRequest): RoutingResult {
    const candidates: Array<{
      node: SovereignNode;
      score: number;
      reasons: string[];
    }> = [];

    const clusterNodes = this.nodeRegistry.list({ role: "cluster", status: "healthy" });

    for (const node of clusterNodes) {
      let score = 50;
      const reasons: string[] = [];

      // 1. Data residency enforcement
      if (req.residency) {
        const allowedRegions = RESIDENCY_REGIONS[req.residency] ?? [];
        if (allowedRegions.length > 0 && !allowedRegions.includes(node.region)) {
          score = 0;
          reasons.push(`excluded: residency ${req.residency} requires ${allowedRegions.join("/")}`);
          candidates.push({ node, score, reasons });
          continue;
        }
        if (allowedRegions.includes(node.region)) {
          score += 20;
          reasons.push("matches residency");
        }
      }

      // 2. Geo-proximity
      if (req.sourceRegion) {
        const proximity = REGION_PROXIMITY[req.sourceRegion]?.[node.region] ?? 50;
        const proximityScore = Math.max(0, 30 - proximity * 0.3);
        score += proximityScore;
        if (proximityScore > 15) reasons.push("geo-proximate");
      }

      // 3. Node load (prefer lighter nodes)
      const loadScore = Math.round((1 - node.load) * 20);
      score += loadScore;
      if (node.load < 0.3) reasons.push("low load");
      else if (node.load > 0.8) reasons.push("high load");

      // 4. Policy check
      const policyResult = this.policyAuthority.evaluate("routing.node", {
        region: node.region,
        tenantId: req.tenantId ?? "",
      });
      if (!policyResult.allowed) {
        score = 0;
        reasons.push(`policy denied: ${policyResult.reason}`);
      }

      candidates.push({ node, score: Math.min(100, score), reasons });
    }

    candidates.sort((a, b) => b.score - a.score);

    if (candidates.length === 0 || candidates[0].score === 0) {
      return {
        targetNode: "none",
        targetRegion: "none",
        targetCluster: "none",
        score: 0,
        reasoning: ["No eligible nodes available"],
        alternatives: [],
      };
    }

    const best = candidates[0];
    return {
      targetNode:    best.node.nodeId,
      targetRegion:  best.node.region,
      targetCluster: best.node.clusterId,
      score:         best.score,
      reasoning:     best.reasons,
      alternatives:  candidates.slice(1, 4).map(c => ({
        node: c.node.nodeId,
        region: c.node.region,
        score: c.score,
      })),
    };
  }

  stats() {
    const nodes = this.nodeRegistry.list({ role: "cluster" });
    const byRegion: Record<string, number> = {};
    for (const n of nodes) {
      byRegion[n.region] = (byRegion[n.region] ?? 0) + 1;
    }
    return {
      eligibleNodes: nodes.filter(n => n.status === "healthy").length,
      totalNodes:    nodes.length,
      regions:       Object.keys(byRegion).length,
      distribution:  byRegion,
    };
  }
}
