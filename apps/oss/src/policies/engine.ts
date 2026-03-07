// Sovereignly Policy Engine -- MIT License
// Declarative policies that control who can do what, where, when.
// All platform operations pass through policy evaluation before execution.
//
// From SYSTEM_BIBLE.md: "Policy-controlled infrastructure"
// From PLATFORM_PROTOCOL.md: "All operations require authentication and policy validation"

import type { EventBus, SovereignEvent } from "../events/bus.ts";

// -- Policy types --

export type PolicyEffect = "allow" | "deny";
export type PolicyScope = "platform" | "tenant" | "agent" | "workflow";

export interface Policy {
  id:          string;
  name:        string;
  description: string;
  scope:       PolicyScope;
  tenantId?:   string;      // null = platform-wide
  rules:       PolicyRule[];
  effect:      PolicyEffect; // default effect if no rule matches
  priority:    number;       // higher = evaluated first
  active:      boolean;
  createdAt:   number;
}

export interface PolicyRule {
  action:      string;       // e.g. "tenant.create", "agent.execute", "machine.migrate"
  resource?:   string;       // e.g. "tenant:org_abc", "*"
  conditions?: PolicyCondition[];
  effect:      PolicyEffect;
}

export interface PolicyCondition {
  field:    string;          // e.g. "source.role", "tenant.plan", "time.hour"
  operator: "eq" | "neq" | "in" | "gt" | "lt" | "contains";
  value:    unknown;
}

export interface PolicyEvaluation {
  allowed:  boolean;
  policy?:  string;          // which policy decided
  rule?:    string;          // which rule matched
  reason?:  string;
}

// -- Built-in policies --

export const BUILTIN_POLICIES: Omit<Policy, "id" | "createdAt">[] = [
  {
    name: "agent-sandbox",
    description: "Agents cannot bypass policies or execute shell commands",
    scope: "agent",
    rules: [
      { action: "policy.bypass",   effect: "deny" },
      { action: "shell.execute",   effect: "deny" },
      { action: "tenant.access",   effect: "deny",
        conditions: [{ field: "agent.authorized", operator: "eq", value: false }] },
    ],
    effect: "allow",
    priority: 1000,
    active: true,
  },
  {
    name: "tenant-isolation",
    description: "Tenants cannot access other tenants' data",
    scope: "tenant",
    rules: [
      { action: "data.*", effect: "deny",
        conditions: [{ field: "request.tenantId", operator: "neq", value: "$context.tenantId" }] },
    ],
    effect: "allow",
    priority: 900,
    active: true,
  },
  {
    name: "free-tier-limits",
    description: "Free tier resource constraints",
    scope: "tenant",
    rules: [
      { action: "workflow.create", effect: "deny",
        conditions: [{ field: "tenant.plan", operator: "eq", value: "free" },
                     { field: "tenant.workflowCount", operator: "gt", value: 3 }] },
      { action: "agent.register", effect: "deny",
        conditions: [{ field: "tenant.plan", operator: "eq", value: "free" },
                     { field: "tenant.agentCount", operator: "gt", value: 1 }] },
    ],
    effect: "allow",
    priority: 800,
    active: true,
  },
];

// -- Policy Engine --

export class PolicyEngine {
  private policies: Policy[] = [];
  private evaluationCount = 0;
  private denyCount = 0;

  constructor(private bus?: EventBus) {
    // Load built-in policies
    for (const bp of BUILTIN_POLICIES) {
      this.policies.push({
        ...bp,
        id: `pol_${crypto.randomUUID().slice(0, 12)}`,
        createdAt: Date.now(),
      });
    }
  }

  // Register a new policy
  register(policy: Omit<Policy, "id" | "createdAt">): Policy {
    const full: Policy = {
      ...policy,
      id: `pol_${crypto.randomUUID().slice(0, 12)}`,
      createdAt: Date.now(),
    };
    this.policies.push(full);
    this.policies.sort((a, b) => b.priority - a.priority);

    void this.bus?.emit("POLICY_CREATED", {
      policyId: full.id, name: full.name, scope: full.scope,
    }, { source: "policy-engine" });

    return full;
  }

  // Evaluate an action against all policies
  evaluate(
    action:  string,
    context: Record<string, unknown> = {}
  ): PolicyEvaluation {
    this.evaluationCount++;

    // Sort by priority (highest first) and filter active
    const active = this.policies.filter(p => p.active);

    for (const policy of active) {
      // Check scope match
      if (policy.tenantId && policy.tenantId !== context.tenantId) continue;

      for (const rule of policy.rules) {
        // Check action match (supports wildcards like "data.*")
        if (!this.matchAction(action, rule.action)) continue;

        // Check conditions
        if (rule.conditions && !this.checkConditions(rule.conditions, context)) continue;

        // Rule matched
        const allowed = rule.effect === "allow";
        if (!allowed) this.denyCount++;

        void this.bus?.emit("POLICY_EVALUATED", {
          action, allowed, policyId: policy.id, policyName: policy.name,
        }, { severity: allowed ? "LOW" : "MEDIUM", source: "policy-engine" });

        return {
          allowed,
          policy: policy.name,
          rule: rule.action,
          reason: allowed ? undefined : `Denied by policy: ${policy.name}`,
        };
      }
    }

    // No rule matched -- use most restrictive default (deny for agents, allow for others)
    const isAgent = context.source === "agent";
    return {
      allowed: !isAgent,
      reason: isAgent ? "No explicit allow policy for agent action" : undefined,
    };
  }

  // Action matching with wildcards
  private matchAction(actual: string, pattern: string): boolean {
    if (pattern === "*") return true;
    if (pattern === actual) return true;
    if (pattern.endsWith(".*")) {
      return actual.startsWith(pattern.slice(0, -2));
    }
    return false;
  }

  // Evaluate conditions against context
  private checkConditions(conditions: PolicyCondition[], context: Record<string, unknown>): boolean {
    return conditions.every(cond => {
      const actual = this.resolveField(cond.field, context);
      const expected = cond.value === "$context.tenantId" ? context.tenantId : cond.value;

      switch (cond.operator) {
        case "eq":       return actual === expected;
        case "neq":      return actual !== expected;
        case "gt":       return Number(actual) > Number(expected);
        case "lt":       return Number(actual) < Number(expected);
        case "in":       return Array.isArray(expected) && (expected as unknown[]).includes(actual);
        case "contains": return typeof actual === "string" && actual.includes(String(expected));
        default:         return false;
      }
    });
  }

  // Resolve dotted field paths like "tenant.plan"
  private resolveField(field: string, context: Record<string, unknown>): unknown {
    return field.split(".").reduce((obj: any, key) => obj?.[key], context);
  }

  // List policies
  list(scope?: PolicyScope): Policy[] {
    return scope ? this.policies.filter(p => p.scope === scope) : this.policies;
  }

  // Stats
  stats() {
    return {
      total:       this.policies.length,
      active:      this.policies.filter(p => p.active).length,
      evaluations: this.evaluationCount,
      denials:     this.denyCount,
    };
  }
}
