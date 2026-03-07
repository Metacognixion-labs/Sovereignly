/**
 * Bootstrap: Kernel subsystems + EventBus + Workflows + Agents
 */

import { platformBus }              from "@sovereignly/oss/events/bus";
import { PolicyEngine }             from "@sovereignly/oss/policies/engine";
import { WorkflowEngine }           from "@sovereignly/oss/workflows/engine";
import { registerBuiltinWorkflows } from "@sovereignly/oss/workflows/builtins";
import { AgentRuntime }             from "@sovereignly/oss/agents/runtime";
import { registerBuiltinAgents }    from "@sovereignly/oss/agents/builtins";

import { StateRegistry }    from "../kernel/state-registry.ts";
import { HealthAnalyzer }   from "../kernel/health-analyzer.ts";
import { DecisionEngine }   from "../kernel/decision-engine.ts";
import { PlacementEngine }  from "../kernel/placement-engine.ts";
import { MigrationEngine }  from "../kernel/migration-engine.ts";
import { TopologyEngine }   from "../kernel/topology-engine.ts";
import { AIOperatingSystem } from "../kernel/ai-os.ts";
import { CognitiveModel }   from "../kernel/cognitive-model.ts";
import { SovereignKernel }  from "../kernel/sovereign-kernel.ts";

import type { SovereignChain } from "@sovereignly/oss/security/chain";
import type { Config } from "./config.ts";

export function createKernel(cfg: Config, chain: SovereignChain) {
  const eventBus       = platformBus;
  const policyEngine   = new PolicyEngine(eventBus);

  const workflowEngine = new WorkflowEngine(eventBus, policyEngine);
  registerBuiltinWorkflows(workflowEngine);
  const agentRuntime   = new AgentRuntime(eventBus, policyEngine, workflowEngine);
  registerBuiltinAgents(agentRuntime);

  const stateRegistry   = new StateRegistry(eventBus);
  const healthAnalyzer  = new HealthAnalyzer(eventBus, stateRegistry, workflowEngine);
  const decisionEngine  = new DecisionEngine(eventBus, policyEngine, healthAnalyzer, stateRegistry);
  const placementEngine = new PlacementEngine(stateRegistry, policyEngine);
  const migrationEngine = new MigrationEngine(eventBus, stateRegistry, workflowEngine, placementEngine);
  const topologyEngine  = new TopologyEngine(stateRegistry);

  const aiOS           = new AIOperatingSystem(eventBus, workflowEngine, policyEngine);
  const cognitiveModel = new CognitiveModel(eventBus, stateRegistry);

  // Modular Kernel
  const sovereignKernel = new SovereignKernel({
    nodeId:  cfg.nodeId,
    region:  cfg.nodeRegion,
    role:    cfg.nodeRole,
    version: "4.0.0",
    dataDir: cfg.dataDir,
  }, eventBus);

  // Register core services
  sovereignKernel.services.register("chain", chain);
  sovereignKernel.services.register("stateRegistry", stateRegistry);
  sovereignKernel.services.register("healthAnalyzer", healthAnalyzer);
  sovereignKernel.services.register("decisionEngine", decisionEngine);
  sovereignKernel.services.register("placementEngine", placementEngine);
  sovereignKernel.services.register("migrationEngine", migrationEngine);
  sovereignKernel.services.register("topologyEngine", topologyEngine);
  sovereignKernel.services.register("workflowEngine", workflowEngine);
  sovereignKernel.services.register("agentRuntime", agentRuntime);
  sovereignKernel.services.register("policyEngine", policyEngine);

  return {
    eventBus, policyEngine, workflowEngine, agentRuntime,
    stateRegistry, healthAnalyzer, decisionEngine,
    placementEngine, migrationEngine, topologyEngine,
    aiOS, cognitiveModel, sovereignKernel,
  };
}
