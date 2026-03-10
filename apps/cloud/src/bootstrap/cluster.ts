/**
 * Bootstrap: Cluster Awareness + Global Chain Anchoring + AI Orchestration
 */

import { NodeRegistry }       from "../cluster/node-registry.ts";
import { NodeHeartbeat }      from "../cluster/node-heartbeat.ts";
import { ClusterTopology }    from "../cluster/cluster-topology.ts";
import { GlobalAnchor }       from "../global/global-anchor.ts";
import { ClusterRootComputer } from "../global/cluster-root.ts";
import { ClusterBalancer }          from "../ai/cluster-balancer.ts";
import { WorkloadPlanner }          from "../ai/workload-planner.ts";
import { NetworkAnomalyDetector }   from "../ai/network-anomaly-detector.ts";
import { CostOptimizer }            from "../ai/cost-optimizer.ts";

import type { SovereignChain } from "@sovereignly/oss/security/chain";
import type { EventBus } from "@sovereignly/oss/events/bus";
import type { TenantManager } from "../tenants/manager.ts";
import type { SovereignKernel } from "../kernel/sovereign-kernel.ts";
import type { PlacementEngine } from "../kernel/placement-engine.ts";
import type { StateRegistry } from "../kernel/state-registry.ts";
import type { Config } from "./config.ts";

export function createCluster(
  cfg: Config,
  eventBus: EventBus,
  chain: SovereignChain,
  tenantManager: TenantManager,
  sovereignKernel: SovereignKernel,
  placementEngine: PlacementEngine,
  stateRegistry: StateRegistry,
) {
  // Node registry + topology + heartbeat
  const nodeRegistry    = new NodeRegistry(eventBus);
  const clusterTopology = new ClusterTopology(nodeRegistry);
  const nodeHeartbeat   = new NodeHeartbeat({
    nodeId:          cfg.nodeId,
    region:          cfg.nodeRegion,
    role:            cfg.nodeRole,
    version:         "4.0.0",
    capabilities:    ["chain", "tenants", "workflows", "agents", "ai-kernel"],
    controlPlaneUrl: cfg.controlPlaneUrl,
  }, nodeRegistry);

  nodeHeartbeat.start();
  sovereignKernel.services.register("nodeRegistry", nodeRegistry);
  sovereignKernel.services.register("clusterTopology", clusterTopology);

  // Global chain anchoring
  const globalAnchor        = new GlobalAnchor(eventBus);
  const clusterRootComputer = new ClusterRootComputer(cfg.clusterId, eventBus, tenantManager);

  chain.onBlock(async (block) => {
    if (block.index > 0 && block.index % cfg.globalAnchorInterval === 0) {
      try {
        await clusterRootComputer.compute();
        if (!cfg.controlPlaneUrl) {
          await globalAnchor.computeGlobalRoot();
        }
      } catch (e: any) { console.warn("[GlobalAnchor] Root computation failed:", e.message); }
    }
  });

  sovereignKernel.services.register("globalAnchor", globalAnchor);
  sovereignKernel.services.register("clusterRoot", clusterRootComputer);

  // AI Orchestration (disabled on single-node deployments -- no peers to balance)
  const multiNode = cfg.clusterPeers.length > 0;
  const clusterBalancer        = new ClusterBalancer(eventBus, nodeRegistry, { enabled: multiNode });
  const workloadPlanner        = new WorkloadPlanner(nodeRegistry, placementEngine);
  const networkAnomalyDetector = new NetworkAnomalyDetector(eventBus, nodeRegistry, { enabled: multiNode });
  const costOptimizer          = new CostOptimizer(nodeRegistry, stateRegistry, { enabled: multiNode });

  sovereignKernel.services.register("clusterBalancer", clusterBalancer);
  sovereignKernel.services.register("workloadPlanner", workloadPlanner);
  sovereignKernel.services.register("networkAnomalyDetector", networkAnomalyDetector);
  sovereignKernel.services.register("costOptimizer", costOptimizer);

  return {
    nodeRegistry, clusterTopology, nodeHeartbeat,
    globalAnchor, clusterRootComputer,
    clusterBalancer, workloadPlanner, networkAnomalyDetector, costOptimizer,
  };
}
