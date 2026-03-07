// Sovereignly Control Plane — Metrics Aggregator
// BSL License — MetaCognixion
//
// Aggregates metrics from all clusters and nodes.
// Provides a global view of the network's health, throughput, and capacity.

import type { ControlPlaneNodeRegistry } from "./node-registry.ts";
import type { ClusterManager } from "./cluster-manager.ts";

export interface GlobalMetrics {
  timestamp:     number;
  nodes:         NodeMetricsSummary;
  clusters:      ClusterMetricsSummary;
  network:       NetworkMetrics;
}

interface NodeMetricsSummary {
  total:         number;
  healthy:       number;
  degraded:      number;
  offline:       number;
  avgLoad:       number;
  peakLoad:      number;
  totalUptime:   number;
}

interface ClusterMetricsSummary {
  total:         number;
  healthy:       number;
  degraded:      number;
  critical:      number;
  offline:       number;
}

interface NetworkMetrics {
  regions:       number;
  nodesPerRegion: Record<string, number>;
  loadPerRegion:  Record<string, number>;
}

export class MetricsAggregator {
  private history: GlobalMetrics[] = [];
  private maxHistory = 1440; // 24h at 1/min
  private interval: ReturnType<typeof setInterval>;

  constructor(
    private nodeRegistry: ControlPlaneNodeRegistry,
    private clusterManager: ClusterManager,
  ) {
    // Collect every 60 seconds
    this.interval = setInterval(() => this.collect(), 60_000);
  }

  /** Collect a metrics snapshot */
  collect(): GlobalMetrics {
    const allNodes = this.nodeRegistry.list();
    const clusters = this.clusterManager.list();

    const nodesPerRegion: Record<string, number> = {};
    const loadPerRegion: Record<string, { total: number; count: number }> = {};
    let peakLoad = 0;

    for (const node of allNodes) {
      nodesPerRegion[node.region] = (nodesPerRegion[node.region] ?? 0) + 1;
      if (!loadPerRegion[node.region]) loadPerRegion[node.region] = { total: 0, count: 0 };
      loadPerRegion[node.region].total += node.load;
      loadPerRegion[node.region].count++;
      if (node.load > peakLoad) peakLoad = node.load;
    }

    const avgLoadPerRegion: Record<string, number> = {};
    for (const [region, data] of Object.entries(loadPerRegion)) {
      avgLoadPerRegion[region] = Number((data.total / data.count).toFixed(3));
    }

    const metrics: GlobalMetrics = {
      timestamp: Date.now(),
      nodes: {
        total:     allNodes.length,
        healthy:   allNodes.filter(n => n.status === "healthy").length,
        degraded:  allNodes.filter(n => n.status === "degraded").length,
        offline:   allNodes.filter(n => n.status === "offline").length,
        avgLoad:   allNodes.length > 0 ? Number((allNodes.reduce((s, n) => s + n.load, 0) / allNodes.length).toFixed(3)) : 0,
        peakLoad:  Number(peakLoad.toFixed(3)),
        totalUptime: allNodes.reduce((s, n) => s + n.uptime, 0),
      },
      clusters: {
        total:    clusters.length,
        healthy:  clusters.filter(c => c.status === "healthy").length,
        degraded: clusters.filter(c => c.status === "degraded").length,
        critical: clusters.filter(c => c.status === "critical").length,
        offline:  clusters.filter(c => c.status === "offline").length,
      },
      network: {
        regions:        Object.keys(nodesPerRegion).length,
        nodesPerRegion,
        loadPerRegion:  avgLoadPerRegion,
      },
    };

    this.history.push(metrics);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(-this.maxHistory);
    }

    return metrics;
  }

  /** Get the latest metrics snapshot */
  latest(): GlobalMetrics | null {
    return this.history.length > 0 ? this.history[this.history.length - 1] : this.collect();
  }

  /** Get metrics history */
  getHistory(limit = 60): GlobalMetrics[] {
    return this.history.slice(-limit);
  }

  stats() {
    return {
      snapshots:   this.history.length,
      latestLoad:  this.latest()?.nodes.avgLoad ?? 0,
      regions:     this.latest()?.network.regions ?? 0,
    };
  }

  close() { clearInterval(this.interval); }
}
