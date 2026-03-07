// Sovereignly Edge Event Forwarder -- BSL License
//
// Forwards events from edge nodes to regional cluster gateways.
// Edge nodes do NOT store tenant chains — they forward everything upstream.
// Buffers events and sends in batches for efficiency.

export interface ForwardedEvent {
  type:      string;
  tenantId?: string;
  payload:   Record<string, unknown>;
  severity?: string;
  sourceEdge: string;
  timestamp:  number;
}

export interface ForwarderConfig {
  clusterUrl:      string;    // upstream cluster gateway URL
  edgeNodeId:      string;
  batchSize?:      number;    // max events per batch (default: 50)
  flushIntervalMs?: number;   // auto-flush interval (default: 5000)
  maxRetries?:     number;    // max retry attempts (default: 3)
}

export class EventForwarder {
  private buffer: ForwardedEvent[] = [];
  private batchSize: number;
  private flushInterval: ReturnType<typeof setInterval>;
  private maxRetries: number;
  private totalForwarded = 0;
  private totalFailed = 0;

  constructor(private config: ForwarderConfig) {
    this.batchSize = config.batchSize ?? 50;
    this.maxRetries = config.maxRetries ?? 3;
    this.flushInterval = setInterval(() => this.flush(), config.flushIntervalMs ?? 5000);
  }

  /** Queue an event for forwarding */
  queue(event: Omit<ForwardedEvent, "sourceEdge" | "timestamp">): void {
    this.buffer.push({
      ...event,
      sourceEdge: this.config.edgeNodeId,
      timestamp:  Date.now(),
    });

    if (this.buffer.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  /** Flush buffered events to the cluster */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const batch = this.buffer.splice(0, this.batchSize);
    let retries = 0;

    while (retries <= this.maxRetries) {
      try {
        const res = await fetch(`${this.config.clusterUrl}/_sovereign/edge/events`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-edge-node": this.config.edgeNodeId,
          },
          body: JSON.stringify({ events: batch }),
          signal: AbortSignal.timeout(10_000),
        });

        if (res.ok) {
          this.totalForwarded += batch.length;
          return;
        }

        if (res.status >= 500) {
          retries++;
          await new Promise(r => setTimeout(r, 1000 * retries));
          continue;
        }

        // Client error — don't retry
        console.warn(`[EventForwarder] Cluster rejected batch: ${res.status}`);
        this.totalFailed += batch.length;
        return;
      } catch (err: any) {
        retries++;
        if (retries > this.maxRetries) {
          console.warn(`[EventForwarder] Failed after ${this.maxRetries} retries: ${err.message}`);
          // Put events back in buffer for next attempt
          this.buffer.unshift(...batch);
          this.totalFailed += batch.length;
          return;
        }
        await new Promise(r => setTimeout(r, 1000 * retries));
      }
    }
  }

  /** Drain all buffered events (for shutdown) */
  async drain(): Promise<void> {
    while (this.buffer.length > 0) {
      await this.flush();
    }
  }

  stats() {
    return {
      buffered:       this.buffer.length,
      totalForwarded: this.totalForwarded,
      totalFailed:    this.totalFailed,
      clusterUrl:     this.config.clusterUrl,
      batchSize:      this.batchSize,
    };
  }

  close() {
    clearInterval(this.flushInterval);
  }
}
