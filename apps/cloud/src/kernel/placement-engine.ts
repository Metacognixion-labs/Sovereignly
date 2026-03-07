// Sovereignly Placement Engine -- BSL License
//
// Decides where to run workloads. Inputs: latency requirements,
// data residency policies, cost constraints, current capacity.

import type { StateRegistry } from "./state-registry.ts";
import type { PolicyEngine } from "../../../oss/src/policies/engine.ts";

export interface PlacementRequest {
  tenantId?:     string;
  workloadType:  "tenant" | "workflow" | "agent" | "function";
  requirements: {
    regions?:       string[];   // preferred regions
    minMemoryMB?:   number;
    maxLatencyMs?:  number;
    dataResidency?: string;     // e.g. "EU", "US"
  };
}

export interface PlacementResult {
  region:      string;
  machineId?:  string;
  score:       number;    // 0-100 placement quality
  reasoning:   string;
  alternatives: Array<{ region: string; score: number }>;
}

// Available regions (Fly.io regions)
const REGIONS: Record<string, { name: string; continent: string; latencyTier: number }> = {
  iad: { name: "Ashburn, Virginia",   continent: "NA", latencyTier: 1 },
  ord: { name: "Chicago, Illinois",    continent: "NA", latencyTier: 1 },
  sjc: { name: "San Jose, California", continent: "NA", latencyTier: 1 },
  cdg: { name: "Paris, France",        continent: "EU", latencyTier: 1 },
  lhr: { name: "London, UK",           continent: "EU", latencyTier: 1 },
  fra: { name: "Frankfurt, Germany",   continent: "EU", latencyTier: 1 },
  nrt: { name: "Tokyo, Japan",         continent: "AS", latencyTier: 2 },
  sin: { name: "Singapore",            continent: "AS", latencyTier: 2 },
  syd: { name: "Sydney, Australia",    continent: "OC", latencyTier: 2 },
  gru: { name: "Sao Paulo, Brazil",    continent: "SA", latencyTier: 2 },
};

const RESIDENCY_MAP: Record<string, string[]> = {
  EU: ["cdg", "lhr", "fra"],
  US: ["iad", "ord", "sjc"],
  ASIA: ["nrt", "sin"],
};

export class PlacementEngine {
  constructor(
    private state:  StateRegistry,
    private policy: PolicyEngine,
  ) {}

  place(req: PlacementRequest): PlacementResult {
    const candidates: Array<{ region: string; score: number; reason: string }> = [];

    for (const [code, info] of Object.entries(REGIONS)) {
      let score = 50; // base
      const reasons: string[] = [];

      // Data residency
      if (req.requirements.dataResidency) {
        const allowed = RESIDENCY_MAP[req.requirements.dataResidency] ?? [];
        if (allowed.length > 0 && !allowed.includes(code)) {
          score = 0;
          reasons.push(`excluded: data residency ${req.requirements.dataResidency}`);
          candidates.push({ region: code, score, reason: reasons.join("; ") });
          continue;
        }
        if (allowed.includes(code)) {
          score += 20;
          reasons.push("matches residency");
        }
      }

      // Preferred regions
      if (req.requirements.regions?.includes(code)) {
        score += 25;
        reasons.push("preferred region");
      }

      // Latency tier
      if (info.latencyTier === 1) {
        score += 10;
        reasons.push("tier-1 latency");
      }

      // Current load: prefer regions with fewer active entities
      const regionLoad = this.state.list({ region: code, status: "active" as any }).length;
      if (regionLoad === 0) {
        score += 15;
        reasons.push("empty region");
      } else if (regionLoad < 5) {
        score += 5;
        reasons.push("low load");
      }

      // Policy check
      const eval_ = this.policy.evaluate("placement.region", {
        region: code, tenantId: req.tenantId, continent: info.continent,
      });
      if (!eval_.allowed) {
        score = 0;
        reasons.push(`policy denied: ${eval_.reason}`);
      }

      candidates.push({ region: code, score: Math.min(100, score), reason: reasons.join("; ") });
    }

    candidates.sort((a, b) => b.score - a.score);
    const best = candidates[0];

    return {
      region:       best.region,
      score:        best.score,
      reasoning:    best.reason,
      alternatives: candidates.slice(1, 4).map(c => ({ region: c.region, score: c.score })),
    };
  }

  regions() { return REGIONS; }

  stats() {
    const byRegion: Record<string, number> = {};
    for (const code of Object.keys(REGIONS)) {
      byRegion[code] = this.state.list({ region: code }).length;
    }
    return { regions: Object.keys(REGIONS).length, entityDistribution: byRegion };
  }
}
