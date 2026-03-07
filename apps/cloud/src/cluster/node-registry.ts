// Sovereignly Node Registry -- BSL License
//
// Tracks all active Sovereign nodes in the network.
// Nodes register via heartbeat. Stale nodes are marked degraded/offline.
// The registry is the foundation for cluster awareness.

import type { EventBus } from "../../../oss/src/events/bus.ts";

export type NodeRole = "control" | "cluster" | "edge";
export type NodeStatus = "healthy" | "degraded" | "offline";

export interface SovereignNode {
  nodeId:        string;
  region:        string;
  role:          NodeRole;
  version:       string;
  capabilities:  string[];
  status:        NodeStatus;
  load:          number;      // 0-1 (CPU utilization)
  uptime:        number;      // seconds
  lastHeartbeat: number;      // timestamp
  registeredAt:  number;      // timestamp
  metadata:      Record<string, unknown>;
}

export interface HeartbeatPayload {
  nodeId:  string;
  region:  string;
  role?:   NodeRole;
  load:    number;
  uptime:  number;
  version?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
}

const HEARTBEAT_INTERVAL = 30_000;      // expected every 30s
const DEGRADED_THRESHOLD = 90_000;      // 3 missed heartbeats -> degraded
const OFFLINE_THRESHOLD  = 180_000;     // 6 missed heartbeats -> offline

export class NodeRegistry {
  private nodes = new Map<string, SovereignNode>();
  private sweepInterval: ReturnType<typeof setInterval>;

  constructor(private bus: EventBus) {
    // Sweep for stale nodes every 30s
    this.sweepInterval = setInterval(() => this.sweep(), HEARTBEAT_INTERVAL);
  }

  /** Process a heartbeat from a node */
  heartbeat(payload: HeartbeatPayload): SovereignNode {
    const now = Date.now();
    const existing = this.nodes.get(payload.nodeId);

    if (existing) {
      existing.load = payload.load;
      existing.uptime = payload.uptime;
      existing.lastHeartbeat = now;
      existing.status = "healthy";
      if (payload.version) existing.version = payload.version;
      if (payload.capabilities) existing.capabilities = payload.capabilities;
      if (payload.metadata) Object.assign(existing.metadata, payload.metadata);
      return existing;
    }

    // New node registration
    const node: SovereignNode = {
      nodeId:        payload.nodeId,
      region:        payload.region,
      role:          payload.role ?? "cluster",
      version:       payload.version ?? "unknown",
      capabilities:  payload.capabilities ?? [],
      status:        "healthy",
      load:          payload.load,
      uptime:        payload.uptime,
      lastHeartbeat: now,
      registeredAt:  now,
      metadata:      payload.metadata ?? {},
    };
    this.nodes.set(payload.nodeId, node);

    void this.bus.emit("NODE_JOIN", {
      nodeId: node.nodeId, region: node.region, role: node.role,
      version: node.version, capabilities: node.capabilities,
    }, { source: "node-registry" });

    console.log(`[NodeRegistry] Node joined: ${node.nodeId} (${node.role}@${node.region})`);
    return node;
  }

  /** Remove a node explicitly */
  deregister(nodeId: string, reason = "manual"): boolean {
    const node = this.nodes.get(nodeId);
    if (!node) return false;
    this.nodes.delete(nodeId);

    void this.bus.emit("NODE_LEAVE", {
      nodeId, region: node.region, role: node.role, reason,
    }, { source: "node-registry" });

    console.log(`[NodeRegistry] Node left: ${nodeId} (${reason})`);
    return true;
  }

  /** Sweep for stale nodes */
  private sweep() {
    const now = Date.now();
    for (const [nodeId, node] of this.nodes) {
      const age = now - node.lastHeartbeat;

      if (age > OFFLINE_THRESHOLD && node.status !== "offline") {
        node.status = "offline";
        void this.bus.emit("NODE_LEAVE", {
          nodeId, region: node.region, role: node.role,
          reason: "heartbeat_timeout", lastSeen: node.lastHeartbeat,
        }, { source: "node-registry", severity: "HIGH" });
        console.log(`[NodeRegistry] Node offline: ${nodeId} (no heartbeat for ${Math.round(age / 1000)}s)`);
      } else if (age > DEGRADED_THRESHOLD && node.status === "healthy") {
        node.status = "degraded";
        void this.bus.emit("ANOMALY", {
          nodeId, region: node.region,
          reason: "heartbeat_delayed", lastSeen: node.lastHeartbeat,
        }, { source: "node-registry", severity: "MEDIUM" });
      }
    }
  }

  /** Get a specific node */
  get(nodeId: string): SovereignNode | undefined {
    return this.nodes.get(nodeId);
  }

  /** List nodes with optional filters */
  list(opts?: {
    role?:   NodeRole;
    region?: string;
    status?: NodeStatus;
  }): SovereignNode[] {
    let results = Array.from(this.nodes.values());
    if (opts?.role)   results = results.filter(n => n.role === opts.role);
    if (opts?.region) results = results.filter(n => n.region === opts.region);
    if (opts?.status) results = results.filter(n => n.status === opts.status);
    return results;
  }

  /** Get all healthy nodes of a given role */
  healthy(role?: NodeRole): SovereignNode[] {
    return this.list({ role, status: "healthy" });
  }

  /** Count nodes by role */
  countByRole(): Record<NodeRole, number> {
    const result: Record<NodeRole, number> = { control: 0, cluster: 0, edge: 0 };
    for (const node of this.nodes.values()) {
      result[node.role]++;
    }
    return result;
  }

  /** Get regions with active nodes */
  regions(): string[] {
    const regionSet = new Set<string>();
    for (const node of this.nodes.values()) {
      if (node.status !== "offline") regionSet.add(node.region);
    }
    return Array.from(regionSet);
  }

  /** Stats */
  stats() {
    const all = Array.from(this.nodes.values());
    return {
      totalNodes:  all.length,
      healthy:     all.filter(n => n.status === "healthy").length,
      degraded:    all.filter(n => n.status === "degraded").length,
      offline:     all.filter(n => n.status === "offline").length,
      byRole:      this.countByRole(),
      regions:     this.regions(),
      avgLoad:     all.length > 0 ? Number((all.reduce((s, n) => s + n.load, 0) / all.length).toFixed(3)) : 0,
    };
  }

  close() {
    clearInterval(this.sweepInterval);
  }
}
