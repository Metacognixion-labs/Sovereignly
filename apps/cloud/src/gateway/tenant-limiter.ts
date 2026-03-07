/**
 * Sovereignly v3.0.1  Per-Tenant Rate Limiter
 *
 * Enforces plan-based rate limits on the SDK event ingest endpoint
 * and tenant API calls. Runs after JWT verification extracts the tenant ID.
 *
 * Plan limits:
 *   free:       100 events/min,  60 API calls/min
 *   starter:   1000 events/min, 300 API calls/min
 *   growth:   10000 events/min, 1000 API calls/min
 *   enterprise: 50000 events/min, 5000 API calls/min
 *
 * Uses the same sliding-window approach as the gateway's global limiter.
 * Keys: "tenant:{tenantId}:events" and "tenant:{tenantId}:api"
 */

import type { TenantPlan } from "../tenants/manager.ts";

//  Plan limits 

export interface PlanRateLimit {
  eventsPerMin: number;
  apiCallsPerMin: number;
}

export const PLAN_RATE_LIMITS: Record<TenantPlan, PlanRateLimit> = {
  free:       { eventsPerMin: 100,   apiCallsPerMin: 60 },
  starter:    { eventsPerMin: 1000,  apiCallsPerMin: 300 },
  growth:     { eventsPerMin: 10000, apiCallsPerMin: 1000 },
  enterprise: { eventsPerMin: 50000, apiCallsPerMin: 5000 },
};

//  Tenant Rate Limiter 

interface Window {
  count: number;
  resetAt: number;
}

export class TenantRateLimiter {
  private windows = new Map<string, Window>();

  check(
    tenantId: string,
    kind: "events" | "api",
    plan: TenantPlan,
    count: number = 1
  ): { ok: boolean; remaining: number; limit: number; resetMs: number } {
    const limits = PLAN_RATE_LIMITS[plan];
    const limit = kind === "events" ? limits.eventsPerMin : limits.apiCallsPerMin;
    const key = `tenant:${tenantId}:${kind}`;
    const now = Date.now();
    const windowMs = 60_000;

    const w = this.windows.get(key);
    if (!w || now > w.resetAt) {
      this.windows.set(key, { count, resetAt: now + windowMs });
      return { ok: true, remaining: limit - count, limit, resetMs: now + windowMs };
    }

    if (w.count + count > limit) {
      return { ok: false, remaining: 0, limit, resetMs: w.resetAt };
    }

    w.count += count;
    return { ok: true, remaining: limit - w.count, limit, resetMs: w.resetAt };
  }

  /** Get current usage for a tenant (for stats endpoint) */
  usage(tenantId: string): { eventsUsed: number; apiUsed: number } {
    const now = Date.now();
    const evW = this.windows.get(`tenant:${tenantId}:events`);
    const apiW = this.windows.get(`tenant:${tenantId}:api`);
    return {
      eventsUsed: evW && now < evW.resetAt ? evW.count : 0,
      apiUsed:    apiW && now < apiW.resetAt ? apiW.count : 0,
    };
  }

  /** Cleanup stale windows */
  gc() {
    const now = Date.now();
    for (const [k, w] of this.windows) {
      if (now > w.resetAt) this.windows.delete(k);
    }
  }

  /** Total active tenants being tracked */
  get activeTenants(): number {
    const seen = new Set<string>();
    for (const key of this.windows.keys()) {
      const tid = key.split(":")[1];
      if (tid) seen.add(tid);
    }
    return seen.size;
  }
}
