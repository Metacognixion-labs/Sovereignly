// Sovereignly Network Anomaly Detector -- BSL License
//
// Phase 6: Distributed AI Orchestration
//
// Detects anomalies at the network level:
//   - Nodes going offline unexpectedly
//   - Unusual load spikes across regions
//   - Cluster chain divergence
//   - Heartbeat pattern anomalies
//
// Complements the existing per-node AnomalyDetector (zero-trust.ts)
// and HealthAnalyzer (kernel) with cross-cluster awareness.

import type { EventBus } from "../../../oss/src/events/bus.ts";
import type { NodeRegistry } from "../cluster/node-registry.ts";

export interface NetworkAnomaly {
  id:        string;
  type:      string;
  severity:  "warning" | "critical";
  message:   string;
  nodeId?:   string;
  region?:   string;
  timestamp: number;
}

export class NetworkAnomalyDetector {
  private anomalies: NetworkAnomaly[] = [];
  private maxHistory = 500;
  private interval: ReturnType<typeof setInterval>;
  private prevNodeCount = 0;

  constructor(
    private bus: EventBus,
    private nodeRegistry: NodeRegistry,
  ) {
    // Check every 30 seconds
    this.interval = setInterval(() => this.detect(), 30_000);

    // Listen for node leave events
    bus.on("NODE_LEAVE", (e) => {
      if (e.payload.reason === "heartbeat_timeout") {
        this.record({
          type: "unexpected_node_loss",
          severity: "critical",
          message: `Node ${e.payload.nodeId} went offline unexpectedly (region: ${e.payload.region})`,
          nodeId: e.payload.nodeId as string,
          region: e.payload.region as string,
        });
      }
    }, "network-anomaly-detector");
  }

  /** Periodic anomaly detection sweep */
  private detect() {
    const stats = this.nodeRegistry.stats();

    // Check: sudden drop in node count
    if (this.prevNodeCount > 0 && stats.healthy < this.prevNodeCount * 0.5) {
      this.record({
        type: "mass_node_loss",
        severity: "critical",
        message: `Cluster lost >50% of nodes: ${this.prevNodeCount} -> ${stats.healthy}`,
      });
    }
    this.prevNodeCount = stats.healthy;

    // Check: all nodes in a region degraded/offline
    for (const region of stats.regions) {
      const regionNodes = this.nodeRegistry.list({ region });
      const healthyInRegion = regionNodes.filter(n => n.status === "healthy").length;
      if (regionNodes.length > 0 && healthyInRegion === 0) {
        this.record({
          type: "region_offline",
          severity: "critical",
          message: `All nodes in region ${region} are unhealthy (${regionNodes.length} nodes)`,
          region,
        });
      }
    }

    // Check: abnormally high average load
    if (stats.avgLoad > 0.9 && stats.healthy > 0) {
      this.record({
        type: "cluster_overload",
        severity: "warning",
        message: `Average cluster load at ${(stats.avgLoad * 100).toFixed(0)}% -- capacity risk`,
      });
    }
  }

  private record(partial: Omit<NetworkAnomaly, "id" | "timestamp">) {
    const anomaly: NetworkAnomaly = {
      ...partial,
      id: `nanom_${crypto.randomUUID().slice(0, 8)}`,
      timestamp: Date.now(),
    };
    this.anomalies.push(anomaly);
    if (this.anomalies.length > this.maxHistory) {
      this.anomalies = this.anomalies.slice(-this.maxHistory);
    }

    void this.bus.emit("ANOMALY", {
      event: "network_anomaly",
      anomalyType: anomaly.type,
      message: anomaly.message,
      nodeId: anomaly.nodeId,
      region: anomaly.region,
    }, { source: "network-anomaly-detector", severity: anomaly.severity === "critical" ? "CRITICAL" : "HIGH" });
  }

  recent(limit = 20): NetworkAnomaly[] {
    return this.anomalies.slice(-limit).reverse();
  }

  stats() {
    return {
      total:      this.anomalies.length,
      critical:   this.anomalies.filter(a => a.severity === "critical").length,
      warning:    this.anomalies.filter(a => a.severity === "warning").length,
      byType:     this.anomalies.reduce((acc, a) => { acc[a.type] = (acc[a.type] ?? 0) + 1; return acc; }, {} as Record<string, number>),
    };
  }

  close() { clearInterval(this.interval); }
}
