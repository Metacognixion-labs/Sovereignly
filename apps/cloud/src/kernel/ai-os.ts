// Sovereignly AI OS Interface -- BSL License
//
// From AI_OS_INTERFACE.md:
//   Natural Language -> Intent Parser -> Task Planner -> Workflow Execution -> Infrastructure Tools
//
// Example commands:
//   "Deploy tenant environment for Acme in Europe"
//   "Scale analytics cluster to 10k users"
//   "Move latency-sensitive workloads closer to Asia"
//
// This is a deterministic intent parser (no LLM required).
// Pattern matching maps natural language to platform operations.

import type { EventBus } from "../../../oss/src/events/bus.ts";
import type { WorkflowEngine } from "../../../oss/src/workflows/engine.ts";
import type { PolicyEngine } from "../../../oss/src/policies/engine.ts";

export interface Intent {
  action:     string;         // "deploy_tenant" | "migrate" | "scale" | "audit" | "status" | "unknown"
  entities:   Record<string, string>;  // extracted entities (name, region, plan, etc.)
  confidence: number;
  raw:        string;
}

export interface TaskPlan {
  intent:     Intent;
  steps:      PlannedStep[];
  approved:   boolean;
  reason?:    string;
}

interface PlannedStep {
  type:       "workflow" | "api_call" | "query";
  action:     string;
  params:     Record<string, unknown>;
}

// ── Intent patterns ──

interface IntentPattern {
  action:  string;
  patterns: RegExp[];
  extract: (match: RegExpMatchArray, raw: string) => Record<string, string>;
}

const INTENT_PATTERNS: IntentPattern[] = [
  {
    action: "deploy_tenant",
    patterns: [
      /deploy\s+(?:tenant\s+)?(?:environment\s+)?(?:for\s+)?(.+?)(?:\s+in\s+(.+))?$/i,
      /create\s+(?:tenant\s+)?(?:for\s+)?(.+?)(?:\s+in\s+(.+))?$/i,
      /onboard\s+(.+?)(?:\s+(?:to|in)\s+(.+))?$/i,
    ],
    extract: (m) => ({
      tenantName: m[1]?.trim() ?? "",
      region:     m[2]?.trim() ?? "",
    }),
  },
  {
    action: "migrate",
    patterns: [
      /move\s+(.+?)\s+(?:to|closer\s+to)\s+(.+)/i,
      /migrate\s+(.+?)\s+to\s+(.+)/i,
    ],
    extract: (m) => ({
      target:   m[1]?.trim() ?? "",
      toRegion: m[2]?.trim() ?? "",
    }),
  },
  {
    action: "scale",
    patterns: [
      /scale\s+(.+?)\s+to\s+(.+)/i,
      /resize\s+(.+?)\s+to\s+(.+)/i,
    ],
    extract: (m) => ({
      target: m[1]?.trim() ?? "",
      size:   m[2]?.trim() ?? "",
    }),
  },
  {
    action: "audit",
    patterns: [
      /(?:run|generate|create)\s+(?:compliance\s+)?(?:audit|report)\s+(?:for\s+)?(.+)/i,
      /(?:soc2|iso\s*27001|hipaa|gdpr)\s+(?:report|audit)\s+(?:for\s+)?(.+)/i,
    ],
    extract: (m) => ({
      target:   m[1]?.trim() ?? "",
      standard: m[0]?.match(/soc2|iso\s*27001|hipaa|gdpr/i)?.[0] ?? "SOC2",
    }),
  },
  {
    action: "status",
    patterns: [
      /(?:show|get|what.s)\s+(?:the\s+)?(?:status|health|state)\s+(?:of\s+)?(.+)?/i,
      /how\s+is\s+(.+?)(?:\s+doing)?$/i,
    ],
    extract: (m) => ({
      target: m[1]?.trim() ?? "platform",
    }),
  },
  {
    action: "teardown",
    patterns: [
      /(?:delete|remove|teardown|decommission)\s+(?:tenant\s+)?(.+)/i,
    ],
    extract: (m) => ({
      target: m[1]?.trim() ?? "",
    }),
  },
];

// ── Region mapping (natural language -> Fly region codes) ──

const REGION_MAP: Record<string, string> = {
  "us": "iad", "usa": "iad", "america": "iad", "virginia": "iad", "east coast": "iad",
  "west coast": "sjc", "california": "sjc", "chicago": "ord",
  "europe": "cdg", "eu": "cdg", "paris": "cdg", "france": "cdg",
  "london": "lhr", "uk": "lhr", "england": "lhr",
  "germany": "fra", "frankfurt": "fra",
  "asia": "nrt", "japan": "nrt", "tokyo": "nrt",
  "singapore": "sin",
  "australia": "syd", "sydney": "syd",
  "brazil": "gru", "south america": "gru",
};

function resolveRegion(input: string): string | undefined {
  const lower = input.toLowerCase();
  for (const [key, code] of Object.entries(REGION_MAP)) {
    if (lower.includes(key)) return code;
  }
  return undefined;
}

// ── AI OS Interface ──

export class AIOperatingSystem {
  constructor(
    private bus:      EventBus,
    private workflow: WorkflowEngine,
    private policy:   PolicyEngine,
  ) {}

  // Parse natural language into structured intent
  parse(input: string): Intent {
    const trimmed = input.trim();

    for (const pattern of INTENT_PATTERNS) {
      for (const regex of pattern.patterns) {
        const match = trimmed.match(regex);
        if (match) {
          return {
            action:     pattern.action,
            entities:   pattern.extract(match, trimmed),
            confidence: 0.85,
            raw:        trimmed,
          };
        }
      }
    }

    return { action: "unknown", entities: {}, confidence: 0, raw: trimmed };
  }

  // Plan execution from intent
  plan(intent: Intent): TaskPlan {
    const steps: PlannedStep[] = [];

    switch (intent.action) {
      case "deploy_tenant": {
        const region = resolveRegion(intent.entities.region ?? "") ?? "iad";
        steps.push({
          type: "workflow", action: "tenant-onboarding",
          params: { tenantName: intent.entities.tenantName, plan: "starter", region, ownerId: "ai-os" },
        });
        break;
      }

      case "migrate": {
        const toRegion = resolveRegion(intent.entities.toRegion ?? "") ?? "cdg";
        steps.push({
          type: "api_call", action: "kernel.migrate",
          params: { tenantId: intent.entities.target, toRegion, reason: "ai-os command" },
        });
        break;
      }

      case "audit": {
        steps.push({
          type: "workflow", action: "compliance-audit",
          params: { tenantId: intent.entities.target, standard: intent.entities.standard },
        });
        break;
      }

      case "teardown": {
        steps.push({
          type: "workflow", action: "tenant-teardown",
          params: { tenantId: intent.entities.target, reason: "ai-os command" },
        });
        break;
      }

      case "status": {
        steps.push({
          type: "query", action: "kernel.state",
          params: { target: intent.entities.target },
        });
        break;
      }

      case "scale": {
        steps.push({
          type: "api_call", action: "kernel.scale",
          params: { target: intent.entities.target, size: intent.entities.size },
        });
        break;
      }

      default:
        return { intent, steps: [], approved: false, reason: "Could not understand the command. Try: deploy, migrate, audit, status, teardown." };
    }

    // Policy gate
    const eval_ = this.policy.evaluate(`ai-os.${intent.action}`, { source: "ai-os" });
    return { intent, steps, approved: eval_.allowed, reason: eval_.allowed ? undefined : eval_.reason };
  }

  // Execute a plan
  async execute(plan: TaskPlan): Promise<{ ok: boolean; results: unknown[] }> {
    if (!plan.approved) return { ok: false, results: [{ error: plan.reason }] };

    const results: unknown[] = [];

    for (const step of plan.steps) {
      try {
        switch (step.type) {
          case "workflow": {
            const inst = await this.workflow.trigger(step.action, step.params, step.params.tenantId as string, "ai-os");
            results.push({ workflow: inst.id, name: step.action, status: inst.status });
            break;
          }
          case "api_call": {
            // Emit as event for kernel to pick up
            await this.bus.emit("CONFIG_CHANGE", {
              event: `ai_os_${step.action}`, ...step.params,
            }, { source: "ai-os" });
            results.push({ action: step.action, status: "dispatched" });
            break;
          }
          case "query": {
            results.push({ action: step.action, status: "query_result_pending" });
            break;
          }
        }
      } catch (err: any) {
        results.push({ action: step.action, error: err.message });
      }
    }

    await this.bus.emit("CONFIG_CHANGE", {
      event: "ai_os_command_executed", command: plan.intent.raw,
      action: plan.intent.action, resultsCount: results.length,
    }, { source: "ai-os" });

    return { ok: true, results };
  }

  // One-shot: parse -> plan -> execute
  async run(input: string): Promise<{ intent: Intent; plan: TaskPlan; results: unknown[] }> {
    const intent = this.parse(input);
    const plan   = this.plan(intent);
    const { results } = await this.execute(plan);
    return { intent, plan, results };
  }
}
