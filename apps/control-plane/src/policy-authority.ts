// Sovereignly Control Plane — Policy Authority
// BSL License — MetaCognixion
//
// Central policy management for the entire Sovereignly network.
// Distributes policies to regional clusters. Enforces global compliance rules.

export type PolicyScope = "global" | "region" | "cluster" | "tenant";
export type PolicyAction = "allow" | "deny" | "audit";

export interface Policy {
  id:          string;
  name:        string;
  scope:       PolicyScope;
  target:      string;     // "*", region name, cluster id, or tenant id
  rules:       PolicyRule[];
  priority:    number;     // higher = evaluated first
  enabled:     boolean;
  createdAt:   number;
  updatedAt:   number;
}

export interface PolicyRule {
  resource:    string;     // e.g. "data.residency", "compute.region", "tenant.plan"
  condition:   string;     // e.g. "region == EU", "plan != free"
  action:      PolicyAction;
  reason?:     string;
}

export interface PolicyEvalResult {
  allowed:   boolean;
  action:    PolicyAction;
  matchedBy: string | null;
  reason?:   string;
}

export class PolicyAuthority {
  private policies: Policy[] = [];

  constructor() {
    this.loadDefaults();
  }

  private loadDefaults() {
    // Default global policies
    this.policies.push({
      id: "pol_data_residency_eu",
      name: "EU Data Residency",
      scope: "global",
      target: "*",
      rules: [{
        resource: "data.residency",
        condition: "tenant.region == EU",
        action: "deny",
        reason: "EU tenant data must remain in EU regions",
      }],
      priority: 100,
      enabled: true,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    this.policies.push({
      id: "pol_mtls_required",
      name: "mTLS Required",
      scope: "global",
      target: "*",
      rules: [{
        resource: "cluster.communication",
        condition: "protocol != mtls",
        action: "deny",
        reason: "All cluster communication must use mTLS",
      }],
      priority: 99,
      enabled: true,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    this.policies.push({
      id: "pol_free_tier_limits",
      name: "Free Tier Restrictions",
      scope: "global",
      target: "*",
      rules: [{
        resource: "tenant.edge_compute",
        condition: "plan == free",
        action: "deny",
        reason: "Edge compute not available on free plan",
      }],
      priority: 50,
      enabled: true,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });
  }

  /** Add a policy */
  create(policy: Omit<Policy, "id" | "createdAt" | "updatedAt">): Policy {
    const full: Policy = {
      ...policy,
      id: `pol_${crypto.randomUUID().slice(0, 12)}`,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    this.policies.push(full);
    this.policies.sort((a, b) => b.priority - a.priority);
    return full;
  }

  /** Update a policy */
  update(id: string, updates: Partial<Pick<Policy, "name" | "rules" | "priority" | "enabled">>): Policy | null {
    const policy = this.policies.find(p => p.id === id);
    if (!policy) return null;
    if (updates.name !== undefined) policy.name = updates.name;
    if (updates.rules !== undefined) policy.rules = updates.rules;
    if (updates.priority !== undefined) policy.priority = updates.priority;
    if (updates.enabled !== undefined) policy.enabled = updates.enabled;
    policy.updatedAt = Date.now();
    this.policies.sort((a, b) => b.priority - a.priority);
    return policy;
  }

  /** Delete a policy */
  delete(id: string): boolean {
    const idx = this.policies.findIndex(p => p.id === id);
    if (idx === -1) return false;
    this.policies.splice(idx, 1);
    return true;
  }

  /** Evaluate a resource action against policies */
  evaluate(resource: string, context: Record<string, string> = {}): PolicyEvalResult {
    for (const policy of this.policies) {
      if (!policy.enabled) continue;

      for (const rule of policy.rules) {
        if (rule.resource === resource || rule.resource === "*") {
          return {
            allowed: rule.action !== "deny",
            action:  rule.action,
            matchedBy: policy.id,
            reason: rule.reason,
          };
        }
      }
    }
    // Default allow
    return { allowed: true, action: "allow", matchedBy: null };
  }

  /** Get policies for a specific scope */
  list(opts?: { scope?: PolicyScope; enabled?: boolean }): Policy[] {
    let result = this.policies;
    if (opts?.scope !== undefined) result = result.filter(p => p.scope === opts.scope);
    if (opts?.enabled !== undefined) result = result.filter(p => p.enabled === opts.enabled);
    return result;
  }

  /** Get policies that apply to a specific cluster */
  forCluster(clusterId: string): Policy[] {
    return this.policies.filter(p =>
      p.enabled && (p.scope === "global" || (p.scope === "cluster" && p.target === clusterId))
    );
  }

  /** Get policies that apply to a specific region */
  forRegion(region: string): Policy[] {
    return this.policies.filter(p =>
      p.enabled && (p.scope === "global" || (p.scope === "region" && p.target === region))
    );
  }

  stats() {
    return {
      total:    this.policies.length,
      enabled:  this.policies.filter(p => p.enabled).length,
      disabled: this.policies.filter(p => !p.enabled).length,
      byScope: {
        global:  this.policies.filter(p => p.scope === "global").length,
        region:  this.policies.filter(p => p.scope === "region").length,
        cluster: this.policies.filter(p => p.scope === "cluster").length,
        tenant:  this.policies.filter(p => p.scope === "tenant").length,
      },
    };
  }
}
