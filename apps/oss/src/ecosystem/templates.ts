// Sovereignly Templates -- MIT License
//
// Starter templates for common infrastructure patterns.
// Developers pick a template -> get a pre-configured stack.

import type { PluginManifest } from "./plugins.ts";

export interface Template {
  id:           string;
  name:         string;
  description:  string;
  category:     "saas" | "api" | "data-pipeline" | "compliance" | "marketplace" | "custom";
  plugins:      string[];           // plugin IDs to auto-install
  workflows:    string[];           // workflow names to auto-register
  agents:       string[];           // agent IDs to auto-start
  config:       Record<string, unknown>;
  estimatedSetupMinutes: number;
}

export const BUILTIN_TEMPLATES: Template[] = [
  {
    id:          "tpl_saas_starter",
    name:        "SaaS Starter",
    description: "Multi-tenant SaaS with auth, billing, and compliance audit trails",
    category:    "saas",
    plugins:     [],
    workflows:   ["tenant-onboarding", "compliance-audit"],
    agents:      ["agent_health_monitor", "agent_compliance"],
    config:      { plan: "starter", anchorTier: "starter" },
    estimatedSetupMinutes: 5,
  },
  {
    id:          "tpl_api_platform",
    name:        "API Platform",
    description: "Rate-limited API gateway with usage tracking and webhook delivery",
    category:    "api",
    plugins:     [],
    workflows:   ["tenant-onboarding"],
    agents:      ["agent_health_monitor"],
    config:      { plan: "growth", rateLimitPerMin: 1000 },
    estimatedSetupMinutes: 3,
  },
  {
    id:          "tpl_compliance_vault",
    name:        "Compliance Vault",
    description: "Immutable audit trail with SOC2/ISO27001 reports and omnichain attestation",
    category:    "compliance",
    plugins:     [],
    workflows:   ["compliance-audit"],
    agents:      ["agent_compliance", "agent_health_monitor"],
    config:      { plan: "growth", anchorTier: "growth" },
    estimatedSetupMinutes: 5,
  },
  {
    id:          "tpl_data_pipeline",
    name:        "Data Pipeline",
    description: "Event-driven data processing with audit trails and KV state management",
    category:    "data-pipeline",
    plugins:     [],
    workflows:   ["tenant-onboarding"],
    agents:      ["agent_health_monitor", "agent_cost_optimizer"],
    config:      { plan: "starter", workerPoolSize: 4 },
    estimatedSetupMinutes: 5,
  },
];

export class TemplateRegistry {
  private templates = new Map<string, Template>();

  constructor() {
    for (const t of BUILTIN_TEMPLATES) {
      this.templates.set(t.id, t);
    }
  }

  list(category?: string): Template[] {
    let results = Array.from(this.templates.values());
    if (category) results = results.filter(t => t.category === category);
    return results;
  }

  get(id: string): Template | undefined { return this.templates.get(id); }

  register(template: Omit<Template, "id">): Template {
    const id = `tpl_${crypto.randomUUID().slice(0, 10)}`;
    const full = { ...template, id };
    this.templates.set(id, full);
    return full;
  }

  stats() {
    const all = Array.from(this.templates.values());
    return {
      total: all.length,
      byCategory: all.reduce((acc, t) => { acc[t.category] = (acc[t.category] ?? 0) + 1; return acc; }, {} as Record<string, number>),
    };
  }
}
