// Sovereignly Topology Engine -- BSL License
//
// Maps the infrastructure graph:
//   tenants -> machines -> regions -> chains
// Provides a unified view of the infrastructure for decision-making.

import type { StateRegistry } from "./state-registry.ts";

export interface TopologyNode {
  id:       string;
  type:     "region" | "machine" | "tenant" | "agent" | "workflow" | "chain";
  label:    string;
  status:   string;
  metadata: Record<string, unknown>;
}

export interface TopologyEdge {
  from:     string;
  to:       string;
  relation: "hosts" | "runs_in" | "belongs_to" | "monitors" | "anchors";
}

export interface TopologyGraph {
  nodes:     TopologyNode[];
  edges:     TopologyEdge[];
  regions:   number;
  machines:  number;
  tenants:   number;
  agents:    number;
  timestamp: number;
}

export class TopologyEngine {
  constructor(private state: StateRegistry) {}

  // Build the full infrastructure graph
  build(): TopologyGraph {
    const nodes: TopologyNode[] = [];
    const edges: TopologyEdge[] = [];
    const regionSet = new Set<string>();

    const entities = this.state.list();

    for (const e of entities) {
      // Add entity node
      nodes.push({
        id: e.id, type: e.type as any, label: (e.metadata.name as string) ?? e.id,
        status: e.status, metadata: { region: e.region, tenantId: e.tenantId },
      });

      // Region nodes
      if (e.region && !regionSet.has(e.region)) {
        regionSet.add(e.region);
        nodes.push({
          id: `region:${e.region}`, type: "region", label: e.region,
          status: "active", metadata: {},
        });
      }

      // Edges
      if (e.region) {
        edges.push({ from: `region:${e.region}`, to: e.id, relation: "hosts" });
      }
      if (e.tenantId && e.type !== "tenant") {
        edges.push({ from: e.tenantId, to: e.id, relation: "runs_in" });
      }
    }

    return {
      nodes, edges,
      regions:  regionSet.size,
      machines: entities.filter(e => e.type === "machine").length,
      tenants:  entities.filter(e => e.type === "tenant").length,
      agents:   entities.filter(e => e.type === "agent").length,
      timestamp: Date.now(),
    };
  }

  // Get neighbors of a node
  neighbors(nodeId: string): { nodes: TopologyNode[]; edges: TopologyEdge[] } {
    const graph = this.build();
    const relatedEdges = graph.edges.filter(e => e.from === nodeId || e.to === nodeId);
    const relatedIds = new Set(relatedEdges.flatMap(e => [e.from, e.to]));
    const relatedNodes = graph.nodes.filter(n => relatedIds.has(n.id));
    return { nodes: relatedNodes, edges: relatedEdges };
  }

  // Summary stats
  stats() {
    const g = this.build();
    return { nodes: g.nodes.length, edges: g.edges.length, regions: g.regions, machines: g.machines, tenants: g.tenants, agents: g.agents };
  }
}
