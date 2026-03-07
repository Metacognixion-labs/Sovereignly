// Sovereignly Cluster Root -- BSL License
//
// Phase 3: Cluster-level chain root computation
//
// Each cluster node computes a Merkle root over all its tenant chain tips.
// This root is then sent to the Global Anchor (on the control plane).
//
// Flow:
//   tenant events -> tenant Merkle root -> cluster Merkle root -> global root anchor

import type { EventBus } from "../../../oss/src/events/bus.ts";
import type { TenantManager } from "../tenants/manager.ts";

export interface ClusterRootResult {
  clusterId:   string;
  merkleRoot:  string;
  blockIndex:  number;
  tenantCount: number;
  timestamp:   number;
}

export class ClusterRootComputer {
  private blockIndex = 0;
  private history: ClusterRootResult[] = [];
  private maxHistory = 500;

  constructor(
    private clusterId: string,
    private bus: EventBus,
    private tenantManager: TenantManager,
  ) {}

  /** Compute the cluster-level Merkle root from all tenant tips */
  async compute(): Promise<ClusterRootResult> {
    const globalRoot = await this.tenantManager.buildGlobalRoot();
    this.blockIndex++;

    const result: ClusterRootResult = {
      clusterId:   this.clusterId,
      merkleRoot:  `0x${globalRoot.root}`,
      blockIndex:  this.blockIndex,
      tenantCount: globalRoot.tenantTips.length,
      timestamp:   Date.now(),
    };

    this.history.push(result);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(-this.maxHistory);
    }

    // Emit cluster root for global anchor to pick up
    await this.bus.emit("CONFIG_CHANGE", {
      event:       "cluster_root_computed",
      clusterId:   result.clusterId,
      merkleRoot:  result.merkleRoot,
      blockIndex:  result.blockIndex,
      tenantCount: result.tenantCount,
    }, { source: "cluster-root" });

    return result;
  }

  /** Latest root */
  latest(): ClusterRootResult | null {
    return this.history.length > 0 ? this.history[this.history.length - 1] : null;
  }

  /** Root history */
  getHistory(limit = 20): ClusterRootResult[] {
    return this.history.slice(-limit).reverse();
  }

  /** Stats */
  stats() {
    return {
      clusterId:      this.clusterId,
      totalRoots:     this.history.length,
      currentBlockIdx: this.blockIndex,
      latestRoot:     this.latest()?.merkleRoot ?? null,
    };
  }
}
