// Sovereignly Node Heartbeat -- BSL License
//
// Sends periodic heartbeats to the control plane (or peer nodes).
// Also receives heartbeats when this node IS the control plane.
//
// Heartbeat interval: 30 seconds
// Endpoint: POST /_sovereign/control/heartbeat

import type { NodeRegistry, HeartbeatPayload } from "./node-registry.ts";

export interface HeartbeatConfig {
  nodeId:           string;
  region:           string;
  role:             "control" | "cluster" | "edge";
  version:          string;
  capabilities:     string[];
  controlPlaneUrl?: string;   // URL of control plane (if this is NOT the control plane)
  intervalMs?:      number;   // default: 30_000
}

export class NodeHeartbeat {
  private interval: ReturnType<typeof setInterval> | null = null;
  private startTime = Date.now();

  constructor(
    private config: HeartbeatConfig,
    private nodeRegistry: NodeRegistry,
  ) {}

  /** Start sending heartbeats */
  start(): void {
    const ms = this.config.intervalMs ?? 30_000;

    // Register self immediately
    this.sendLocal();

    this.interval = setInterval(() => {
      if (this.config.controlPlaneUrl) {
        this.sendRemote().catch(err => {
          console.warn(`[Heartbeat] Failed to reach control plane: ${err.message}`);
        });
      } else {
        // This IS the control plane -- just update local registry
        this.sendLocal();
      }
    }, ms);
  }

  /** Send heartbeat to local node registry (control plane mode) */
  private sendLocal(): void {
    const payload = this.buildPayload();
    this.nodeRegistry.heartbeat(payload);
  }

  /** Send heartbeat to remote control plane */
  private async sendRemote(): Promise<void> {
    const payload = this.buildPayload();
    const url = `${this.config.controlPlaneUrl}/_sovereign/control/heartbeat`;

    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      throw new Error(`Heartbeat rejected: ${res.status}`);
    }
  }

  private buildPayload(): HeartbeatPayload {
    const uptime = Math.round((Date.now() - this.startTime) / 1000);

    // Approximate CPU load from event loop lag
    let load = 0;
    try {
      const mem = process.memoryUsage();
      load = Number((mem.heapUsed / mem.heapTotal).toFixed(3));
    } catch { load = 0; }

    return {
      nodeId:       this.config.nodeId,
      region:       this.config.region,
      role:         this.config.role,
      load,
      uptime,
      version:      this.config.version,
      capabilities: this.config.capabilities,
    };
  }

  /** Stop sending heartbeats */
  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }
}
