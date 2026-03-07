// Sovereignly Global Anchor -- BSL License
//
// Phase 3: Global Chain Anchoring
//
// Chain hierarchy:
//   Tenant Chain -> Cluster Chain -> Global Root Chain
//
// The Global Anchor aggregates cluster-level Merkle roots
// and publishes a single global root anchor. This creates
// a provable integrity layer spanning the entire network.

import type { EventBus } from "../../../oss/src/events/bus.ts";

export interface ClusterRoot {
  clusterId:   string;
  merkleRoot:  string;
  blockIndex:  number;
  tenantCount: number;
  timestamp:   number;
}

export interface GlobalAnchorRecord {
  id:            string;
  globalRoot:    string;     // Merkle root of all cluster roots
  clusterRoots:  ClusterRoot[];
  blockIndex:    number;
  timestamp:     number;
}

export class GlobalAnchor {
  private clusterRoots = new Map<string, ClusterRoot>();
  private anchors: GlobalAnchorRecord[] = [];
  private blockIndex = 0;
  private maxHistory = 1000;

  constructor(private bus: EventBus) {
    // Listen for cluster root events
    bus.on("CONFIG_CHANGE", (e) => {
      if (e.payload.event === "cluster_root_computed") {
        this.receiveClusterRoot({
          clusterId:   e.payload.clusterId as string,
          merkleRoot:  e.payload.merkleRoot as string,
          blockIndex:  e.payload.blockIndex as number,
          tenantCount: e.payload.tenantCount as number,
          timestamp:   e.ts,
        });
      }
    }, "global-anchor");
  }

  /** Receive a cluster-level Merkle root */
  receiveClusterRoot(root: ClusterRoot): void {
    this.clusterRoots.set(root.clusterId, root);
  }

  /** Compute the global root from all cluster roots */
  async computeGlobalRoot(): Promise<GlobalAnchorRecord | null> {
    const roots = Array.from(this.clusterRoots.values());
    if (roots.length === 0) return null;

    // Build Merkle root over cluster roots
    const leaves = roots
      .sort((a, b) => a.clusterId.localeCompare(b.clusterId))
      .map(r => `${r.clusterId}:${r.merkleRoot}:${r.blockIndex}`);

    // Simple hash-based root (compatible with existing MerkleTree approach)
    const encoder = new TextEncoder();
    let combined = leaves.join("|");
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(combined));
    const globalRoot = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    this.blockIndex++;
    const record: GlobalAnchorRecord = {
      id:           `ganchor_${this.blockIndex}`,
      globalRoot:   `0x${globalRoot}`,
      clusterRoots: [...roots],
      blockIndex:   this.blockIndex,
      timestamp:    Date.now(),
    };

    this.anchors.push(record);
    if (this.anchors.length > this.maxHistory) {
      this.anchors = this.anchors.slice(-this.maxHistory);
    }

    // Emit the global anchor event
    await this.bus.emit("CONFIG_CHANGE", {
      event:          "global_root_anchored",
      globalRoot:     record.globalRoot,
      blockIndex:     record.blockIndex,
      clusterCount:   roots.length,
      totalTenants:   roots.reduce((s, r) => s + r.tenantCount, 0),
    }, { source: "global-anchor", severity: "LOW" });

    console.log(`[GlobalAnchor] Root #${record.blockIndex}: ${record.globalRoot} (${roots.length} clusters)`);
    return record;
  }

  /** Get the latest global anchor */
  latest(): GlobalAnchorRecord | null {
    return this.anchors.length > 0 ? this.anchors[this.anchors.length - 1] : null;
  }

  /** Get anchor history */
  history(limit = 20): GlobalAnchorRecord[] {
    return this.anchors.slice(-limit).reverse();
  }

  /** Get current cluster roots */
  currentClusterRoots(): ClusterRoot[] {
    return Array.from(this.clusterRoots.values());
  }

  /** Stats */
  stats() {
    return {
      totalAnchors:    this.anchors.length,
      currentBlockIdx: this.blockIndex,
      clusterCount:    this.clusterRoots.size,
      clusters:        Array.from(this.clusterRoots.keys()),
      latestRoot:      this.latest()?.globalRoot ?? null,
    };
  }
}
