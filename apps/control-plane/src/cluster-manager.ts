// Sovereignly Control Plane — Cluster Manager
// BSL License — MetaCognixion
//
// Manages the lifecycle of regional clusters.
// Tracks cluster health, capacity, and orchestrates cluster-level operations.

import type { ControlPlaneNodeRegistry, SovereignNode } from "./node-registry.ts";

export type ClusterStatus = "healthy" | "degraded" | "critical" | "offline";

export interface Cluster {
  id:          string;
  region:      string;
  status:      ClusterStatus;
  nodes:       number;
  healthyNodes: number;
  avgLoad:     number;
  totalUptime: number;
  lastUpdate:  number;
}

export class ClusterManager {
  private interval: ReturnType<typeof setInterval>;

  constructor(private nodeRegistry: ControlPlaneNodeRegistry) {
    this.interval = setInterval(() => this.refresh(), 30_000);
  }

  /** Build cluster view from node registry */
  list(): Cluster[] {
    const clusterIds = this.nodeRegistry.clusters();
    return clusterIds.map(id => this.buildCluster(id));
  }

  /** Get a specific cluster */
  get(clusterId: string): Cluster | null {
    const nodes = this.nodeRegistry.list({ clusterId });
    if (nodes.length === 0) return null;
    return this.buildCluster(clusterId);
  }

  /** Get the healthiest cluster in a region */
  bestInRegion(region: string): Cluster | null {
    const clusters = this.list().filter(c => c.region === region);
    if (clusters.length === 0) return null;
    clusters.sort((a, b) => {
      // Prefer healthy, then lowest load
      if (a.status !== b.status) {
        const order: Record<ClusterStatus, number> = { healthy: 0, degraded: 1, critical: 2, offline: 3 };
        return order[a.status] - order[b.status];
      }
      return a.avgLoad - b.avgLoad;
    });
    return clusters[0];
  }

  /** Get all regions with their clusters */
  regionMap(): Record<string, Cluster[]> {
    const map: Record<string, Cluster[]> = {};
    for (const cluster of this.list()) {
      if (!map[cluster.region]) map[cluster.region] = [];
      map[cluster.region].push(cluster);
    }
    return map;
  }

  private buildCluster(clusterId: string): Cluster {
    const nodes = this.nodeRegistry.list({ clusterId });
    const clusterNodes = nodes.filter(n => n.role === "cluster");
    const healthy = clusterNodes.filter(n => n.status === "healthy");
    const avgLoad = clusterNodes.length > 0
      ? clusterNodes.reduce((s, n) => s + n.load, 0) / clusterNodes.length
      : 0;

    let status: ClusterStatus;
    if (clusterNodes.length === 0 || healthy.length === 0) status = "offline";
    else if (healthy.length < clusterNodes.length * 0.5) status = "critical";
    else if (healthy.length < clusterNodes.length) status = "degraded";
    else status = "healthy";

    return {
      id:           clusterId,
      region:       clusterNodes[0]?.region ?? "unknown",
      status,
      nodes:        clusterNodes.length,
      healthyNodes: healthy.length,
      avgLoad:      Number(avgLoad.toFixed(3)),
      totalUptime:  clusterNodes.reduce((s, n) => s + n.uptime, 0),
      lastUpdate:   Date.now(),
    };
  }

  private refresh() {
    // Sweep is handled by node registry; cluster view is derived
  }

  stats() {
    const clusters = this.list();
    return {
      totalClusters: clusters.length,
      healthy:  clusters.filter(c => c.status === "healthy").length,
      degraded: clusters.filter(c => c.status === "degraded").length,
      critical: clusters.filter(c => c.status === "critical").length,
      offline:  clusters.filter(c => c.status === "offline").length,
      regions:  [...new Set(clusters.map(c => c.region))],
    };
  }

  close() { clearInterval(this.interval); }
}
