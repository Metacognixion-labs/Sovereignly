/**
 * Bootstrap: Developer Ecosystem (Plugins, Templates, Gamification)
 */

import { PluginRegistry }     from "@sovereignly/oss/ecosystem/plugins";
import { TemplateRegistry }   from "@sovereignly/oss/ecosystem/templates";
import { GamificationEngine } from "@sovereignly/oss/ecosystem/gamification";
import type { EventBus } from "@sovereignly/oss/events/bus";
import type { PolicyEngine } from "@sovereignly/oss/policies/engine";

export function createEcosystem(eventBus: EventBus, policyEngine: PolicyEngine) {
  const pluginRegistry   = new PluginRegistry(eventBus, policyEngine);
  const templateRegistry = new TemplateRegistry();
  const gamification     = new GamificationEngine(eventBus);

  return { pluginRegistry, templateRegistry, gamification };
}
