// Sovereignly Cluster Topology -- BSL License
//
// Builds a network-level view of the Sovereignly cluster.
// Unlike TopologyEngine (which maps tenants/machines/agents within a node),
// this maps nodes across the network: control planes, clusters, edges.

import type { NodeRegistry, SovereignNode, NodeRole } from "./node-registry.ts";

export interface ClusterNode {
  nodeId:  string;
  region:  string;
  role:    NodeRole;
  status:  string;
  load:    number;
  uptime:  number;
}

export interface ClusterEdge {
  from:     string;
  to:       string;
  relation: "manages" | "peers_with" | "forwards_to";
}

export interface ClusterGraph {
  nodes:     ClusterNode[];
  edges:     ClusterEdge[];
  regions:   string[];
  timestamp: number;
}

export class ClusterTopology {
  constructor(private nodeRegistry: NodeRegistry) {}

  /** Build the full cluster network graph */
  build(): ClusterGraph {
    const allNodes = this.nodeRegistry.list();
    const controlNodes = allNodes.filter(n => n.role === "control");
    const clusterNodes = allNodes.filter(n => n.role === "cluster");
    const edgeNodes = allNodes.filter(n => n.role === "edge");

    const nodes: ClusterNode[] = allNodes.map(n => ({
      nodeId: n.nodeId,
      region: n.region,
      role:   n.role,
      status: n.status,
      load:   n.load,
      uptime: n.uptime,
    }));

    const edges: ClusterEdge[] = [];

    // Control planes manage cluster nodes
    for (const ctrl of controlNodes) {
      for (const cluster of clusterNodes) {
        edges.push({
          from: ctrl.nodeId,
          to: cluster.nodeId,
          relation: "manages",
        });
      }
    }

    // Cluster nodes are peers in the same region
    for (let i = 0; i < clusterNodes.length; i++) {
      for (let j = i + 1; j < clusterNodes.length; j++) {
        if (clusterNodes[i].region === clusterNodes[j].region) {
          edges.push({
            from: clusterNodes[i].nodeId,
            to: clusterNodes[j].nodeId,
            relation: "peers_with",
          });
        }
      }
    }

    // Edge nodes forward to cluster nodes in the same region (or nearest)
    for (const edge of edgeNodes) {
      const sameRegion = clusterNodes.find(c => c.region === edge.region);
      const target = sameRegion ?? clusterNodes[0];
      if (target) {
        edges.push({
          from: edge.nodeId,
          to: target.nodeId,
          relation: "forwards_to",
        });
      }
    }

    return {
      nodes,
      edges,
      regions: this.nodeRegistry.regions(),
      timestamp: Date.now(),
    };
  }

  /** Get nodes in a specific region */
  region(region: string): ClusterNode[] {
    return this.nodeRegistry.list({ region }).map(n => ({
      nodeId: n.nodeId, region: n.region, role: n.role,
      status: n.status, load: n.load, uptime: n.uptime,
    }));
  }

  /** Find the best cluster node for a given region (lowest load, healthy) */
  bestNode(region?: string): ClusterNode | null {
    let candidates = this.nodeRegistry.healthy("cluster");
    if (region) {
      const inRegion = candidates.filter(n => n.region === region);
      if (inRegion.length > 0) candidates = inRegion;
    }
    if (candidates.length === 0) return null;

    candidates.sort((a, b) => a.load - b.load);
    const best = candidates[0];
    return {
      nodeId: best.nodeId, region: best.region, role: best.role,
      status: best.status, load: best.load, uptime: best.uptime,
    };
  }

  /** Stats */
  stats() {
    const graph = this.build();
    return {
      totalNodes:  graph.nodes.length,
      totalEdges:  graph.edges.length,
      regions:     graph.regions.length,
      byRole:      this.nodeRegistry.countByRole(),
      avgLoad:     this.nodeRegistry.stats().avgLoad,
    };
  }
}
