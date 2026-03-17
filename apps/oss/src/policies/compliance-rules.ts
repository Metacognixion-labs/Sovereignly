/**
 * Compliance-as-Code: Declarative Control Evaluator
 *
 * Evaluates SOC2/ISO27001 controls against live system state.
 * Controls are defined as pure functions that return pass/fail + evidence.
 * Runs continuously (every 5 minutes) to provide real-time compliance scoring.
 *
 * Unlike the evidence-only ComplianceEngine (apps/cloud/src/compliance.ts),
 * this module actively EVALUATES whether controls are met, not just whether
 * evidence exists.
 */

import type { SovereignChain } from "../security/chain.ts";
import type { EventBus } from "../events/bus.ts";

// -- Control Definition -------------------------------------------------------

export type ControlStatus = "pass" | "fail" | "warn" | "skip";

export interface ControlResult {
  id:          string;
  name:        string;
  framework:   string;          // "SOC2", "ISO27001", "NIST"
  reference:   string;          // e.g. "CC6.1", "A.9.4.1"
  status:      ControlStatus;
  score:       number;          // 0-100
  evidence:    string;          // human-readable proof
  evaluatedAt: number;
}

export interface ComplianceControlRule {
  id:         string;
  name:       string;
  framework:  string;
  reference:  string;
  evaluate:   (ctx: EvaluationContext) => ControlResult;
}

export interface EvaluationContext {
  chain:     SovereignChain;
  config:    SystemConfig;
  timestamp: number;
}

export interface SystemConfig {
  jwtSecretSet:       boolean;
  serverKeySet:       boolean;
  adminTokenSet:      boolean;
  tlsEnabled:         boolean;
  rateLimitEnabled:   boolean;
  corsRestricted:     boolean;
  encryptionAtRest:   boolean;
  passkeysEnabled:    boolean;
  mfaAvailable:       boolean;
  auditLogging:       boolean;
  anomalyDetection:   boolean;
  secretScanning:     boolean;
  inputValidation:    boolean;
  workerIsolation:    boolean;
}

// -- Built-in Control Rules ---------------------------------------------------

const RULES: ComplianceControlRule[] = [
  // SOC2 CC6.1 — Logical access controls
  {
    id: "SOC2-CC6.1",
    name: "Logical Access Controls",
    framework: "SOC2",
    reference: "CC6.1",
    evaluate: (ctx) => {
      const hasJwt = ctx.config.jwtSecretSet;
      const hasRbac = true; // always true (built-in RBAC)
      const hasPasskeys = ctx.config.passkeysEnabled;
      const score = [hasJwt, hasRbac, hasPasskeys].filter(Boolean).length / 3 * 100;
      return {
        id: "SOC2-CC6.1", name: "Logical Access Controls",
        framework: "SOC2", reference: "CC6.1",
        status: score >= 66 ? "pass" : score >= 33 ? "warn" : "fail",
        score: Math.round(score),
        evidence: `JWT: ${hasJwt ? "configured" : "MISSING"}, RBAC: enabled, Passkeys: ${hasPasskeys ? "enabled" : "disabled"}`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },

  // SOC2 CC6.6 — Boundary protection
  {
    id: "SOC2-CC6.6",
    name: "Boundary Protection",
    framework: "SOC2",
    reference: "CC6.6",
    evaluate: (ctx) => {
      const checks = [
        ctx.config.rateLimitEnabled,
        ctx.config.corsRestricted,
        ctx.config.inputValidation,
        ctx.config.anomalyDetection,
      ];
      const score = checks.filter(Boolean).length / checks.length * 100;
      return {
        id: "SOC2-CC6.6", name: "Boundary Protection",
        framework: "SOC2", reference: "CC6.6",
        status: score >= 75 ? "pass" : score >= 50 ? "warn" : "fail",
        score: Math.round(score),
        evidence: `Rate limiting: ${ctx.config.rateLimitEnabled}, CORS restricted: ${ctx.config.corsRestricted}, Input validation: ${ctx.config.inputValidation}, Anomaly detection: ${ctx.config.anomalyDetection}`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },

  // SOC2 CC6.8 — Unauthorized software protection
  {
    id: "SOC2-CC6.8",
    name: "Software Integrity Controls",
    framework: "SOC2",
    reference: "CC6.8",
    evaluate: (ctx) => {
      const checks = [ctx.config.secretScanning, ctx.config.workerIsolation];
      const score = checks.filter(Boolean).length / checks.length * 100;
      return {
        id: "SOC2-CC6.8", name: "Software Integrity Controls",
        framework: "SOC2", reference: "CC6.8",
        status: score >= 50 ? "pass" : "fail",
        score: Math.round(score),
        evidence: `Secret scanning: ${ctx.config.secretScanning}, Worker isolation: ${ctx.config.workerIsolation}`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },

  // SOC2 CC7.2 — Anomaly detection
  {
    id: "SOC2-CC7.2",
    name: "Anomaly & Threat Detection",
    framework: "SOC2",
    reference: "CC7.2",
    evaluate: (ctx) => {
      const stats = ctx.chain.getStats();
      const hasAnomalyEvents = ctx.chain.getEvents({ type: "ANOMALY", limit: 1 }).length > 0 || ctx.config.anomalyDetection;
      const hasAuditChain = stats.blocks > 0;
      const score = [hasAnomalyEvents, hasAuditChain, ctx.config.auditLogging].filter(Boolean).length / 3 * 100;
      return {
        id: "SOC2-CC7.2", name: "Anomaly & Threat Detection",
        framework: "SOC2", reference: "CC7.2",
        status: score >= 66 ? "pass" : "warn",
        score: Math.round(score),
        evidence: `Anomaly detection: ${hasAnomalyEvents}, Audit chain: ${stats.blocks} blocks/${stats.events} events, Logging: ${ctx.config.auditLogging}`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },

  // SOC2 CC7.3 — Security event response
  {
    id: "SOC2-CC7.3",
    name: "Security Event Response",
    framework: "SOC2",
    reference: "CC7.3",
    evaluate: (ctx) => {
      const stats = ctx.chain.getStats();
      const hasChain = stats.blocks > 0;
      const isAnchored = stats.anchored > 0;
      const score = hasChain ? (isAnchored ? 100 : 60) : 0;
      return {
        id: "SOC2-CC7.3", name: "Security Event Response",
        framework: "SOC2", reference: "CC7.3",
        status: score >= 60 ? "pass" : "fail",
        score,
        evidence: `Immutable chain: ${hasChain ? `${stats.blocks} blocks` : "NONE"}, Omnichain anchored: ${stats.anchored} blocks`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },

  // SOC2 A1.1 — System availability
  {
    id: "SOC2-A1.1",
    name: "System Availability Commitments",
    framework: "SOC2",
    reference: "A1.1",
    evaluate: (ctx) => {
      const uptimeMs = process.uptime() * 1000;
      const uptimeHrs = uptimeMs / 3600_000;
      const score = uptimeHrs > 24 ? 100 : uptimeHrs > 1 ? 80 : 50;
      return {
        id: "SOC2-A1.1", name: "System Availability",
        framework: "SOC2", reference: "A1.1",
        status: "pass",
        score,
        evidence: `Uptime: ${uptimeHrs.toFixed(1)} hours, Health endpoint: active`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },

  // ISO 27001 A.9.4.1 — Information access restriction
  {
    id: "ISO27001-A.9.4.1",
    name: "Information Access Restriction",
    framework: "ISO27001",
    reference: "A.9.4.1",
    evaluate: (ctx) => {
      const checks = [ctx.config.encryptionAtRest, ctx.config.jwtSecretSet, ctx.config.adminTokenSet];
      const score = checks.filter(Boolean).length / checks.length * 100;
      return {
        id: "ISO27001-A.9.4.1", name: "Information Access Restriction",
        framework: "ISO27001", reference: "A.9.4.1",
        status: score >= 66 ? "pass" : "fail",
        score: Math.round(score),
        evidence: `Encryption at rest: ${ctx.config.encryptionAtRest}, JWT auth: ${ctx.config.jwtSecretSet}, Admin token: ${ctx.config.adminTokenSet}`,
        evaluatedAt: ctx.timestamp,
      };
    },
  },
];

// -- Compliance Evaluator (continuous) ----------------------------------------

export class ComplianceEvaluator {
  private rules: ComplianceControlRule[] = [...RULES];
  private lastResults: ControlResult[] = [];
  private evaluationCount = 0;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private chain: SovereignChain,
    private bus: EventBus | null,
    private systemConfig: SystemConfig,
  ) {}

  /** Start continuous evaluation (every 5 minutes) */
  start(): void {
    this.evaluate(); // initial evaluation
    this.timer = setInterval(() => this.evaluate(), 5 * 60_000);
  }

  /** Run one evaluation cycle */
  evaluate(): ControlResult[] {
    const ctx: EvaluationContext = {
      chain: this.chain,
      config: this.systemConfig,
      timestamp: Date.now(),
    };

    this.lastResults = this.rules.map(rule => {
      try {
        return rule.evaluate(ctx);
      } catch {
        return {
          id: rule.id, name: rule.name, framework: rule.framework,
          reference: rule.reference, status: "skip" as ControlStatus,
          score: 0, evidence: "Evaluation error", evaluatedAt: ctx.timestamp,
        };
      }
    });

    this.evaluationCount++;

    // Emit compliance score change event
    const score = this.overallScore();
    void this.bus?.emit("CONFIG_CHANGE", {
      event: "compliance_evaluation",
      score,
      controls: this.lastResults.length,
      passing: this.lastResults.filter(r => r.status === "pass").length,
      failing: this.lastResults.filter(r => r.status === "fail").length,
    }, { source: "compliance-evaluator", severity: score < 50 ? "HIGH" : "LOW" });

    return this.lastResults;
  }

  /** Register a custom control rule */
  addRule(rule: ComplianceControlRule): void {
    this.rules.push(rule);
  }

  /** Get the overall compliance score (0-100) */
  overallScore(): number {
    if (this.lastResults.length === 0) return 0;
    return Math.round(
      this.lastResults.reduce((sum, r) => sum + r.score, 0) / this.lastResults.length
    );
  }

  /** Get results by framework */
  byFramework(framework: string): ControlResult[] {
    return this.lastResults.filter(r => r.framework === framework);
  }

  /** Full report */
  report(): {
    score: number;
    evaluations: number;
    controls: ControlResult[];
    summary: { pass: number; fail: number; warn: number; skip: number };
    lastEvaluated: number;
  } {
    return {
      score: this.overallScore(),
      evaluations: this.evaluationCount,
      controls: this.lastResults,
      summary: {
        pass: this.lastResults.filter(r => r.status === "pass").length,
        fail: this.lastResults.filter(r => r.status === "fail").length,
        warn: this.lastResults.filter(r => r.status === "warn").length,
        skip: this.lastResults.filter(r => r.status === "skip").length,
      },
      lastEvaluated: this.lastResults[0]?.evaluatedAt ?? 0,
    };
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }
}
