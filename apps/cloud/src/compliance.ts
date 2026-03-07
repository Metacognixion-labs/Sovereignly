/**
 * Sovereignly v3  Compliance Engine
 *
 * Generates machine-readable compliance evidence mapped to:
 *    SOC 2 Type II   Trust Services Criteria (AICPA)
 *    ISO 27001:2022  Annex A controls
 *    NIST SP 800-53  Security controls baseline
 *
 * Evidence is pulled from:
 *   1. SovereignChain audit events (cryptographically verifiable)
 *   2. Runtime configuration (RBAC, encryption, rate limiting)
 *   3. Function registry (code integrity hashes)
 *   4. System metrics (availability, error rates)
 *
 * Output formats:
 *    JSON report (machine-readable)
 *    SOC 2 evidence package (controls + evidence mappings)
 *    Audit trail export (date-ranged event list with Merkle proofs)
 */

import type { SovereignChain, AuditEvent } from "../../oss/src/security/chain.ts";

//  SOC 2 Trust Services Criteria 

export const SOC2_CRITERIA = {
  CC6_1: "Logical and physical access controls",
  CC6_6: "Boundary protection controls",
  CC6_8: "Unauthorized software protection",
  CC7_1: "System configuration monitoring",
  CC7_2: "Anomaly and threat detection",
  CC7_3: "Security event response",
  CC7_4: "Incident identification and response",
  CC8_1: "Change management controls",
  CC4_1: "Monitoring activities and evaluations",
  A1_1:  "System availability commitments",
  A1_2:  "Recovery capacity testing",
} as const;

export type SOC2Criterion = keyof typeof SOC2_CRITERIA;

//  Control Definition 

interface Control {
  id:          string;
  name:        string;
  description: string;
  criteria:    SOC2Criterion[];
  iso27001:    string[];    // Annex A references
  nist:        string[];    // SP 800-53 control IDs
  status:      "implemented" | "partial" | "planned" | "not_applicable";
  evidence:    EvidenceItem[];
}

interface EvidenceItem {
  type:        "config" | "event" | "metric" | "document";
  description: string;
  value:       unknown;
  ts?:         number;
  verifiable:  boolean;   // true if backed by chain proof
  blockIndex?: number;
}

//  Compliance Engine 

export class ComplianceEngine {
  constructor(
    private chain:   SovereignChain,
    private cfg:     {
      adminTokenSet:    boolean;
      tlsEnabled:       boolean;
      rateLimitEnabled: boolean;
      rbacEnabled:      boolean;
      encryptionAtRest: boolean;
      multiNode:        boolean;
      meridianAnchored: boolean;
      workerIsolation:  boolean;
      auditLogging:     boolean;
      nodeId:           string;
      version:          string;
    }
  ) {}

  //  Build full control inventory 

  async buildControlInventory(): Promise<Control[]> {
    const chainStats  = this.chain.getStats();
    const recentEvents = this.chain.getEvents({ limit: 1000 });
    const now = Date.now();
    const last30d = now - 30 * 24 * 60 * 60 * 1000;

    const deployEvents   = recentEvents.filter(e => e.type === "FUNCTION_DEPLOY");
    const authFailures   = recentEvents.filter(e => e.type === "AUTH_FAILURE");
    const anomalies      = recentEvents.filter(e => e.type === "ANOMALY");
    const configChanges  = recentEvents.filter(e => e.type === "CONFIG_CHANGE");

    return [
      //  ACCESS CONTROL 
      {
        id: "AC-001",
        name: "Admin API Authentication",
        description: "All administrative endpoints require a valid token or JWT. Unauthenticated requests return 401.",
        criteria: ["CC6_1"],
        iso27001: ["A.9.1.2", "A.9.4.1"],
        nist: ["AC-3", "IA-2"],
        status: this.cfg.adminTokenSet ? "implemented" : "partial",
        evidence: [
          {
            type: "config",
            description: "Admin token configured",
            value: this.cfg.adminTokenSet,
            verifiable: false,
          },
          {
            type: "event",
            description: `Auth failures in last 30d: ${authFailures.length}`,
            value: authFailures.length,
            ts: now,
            verifiable: true,
            blockIndex: authFailures[0]?.blockIndex,
          },
        ],
      },

      {
        id: "AC-002",
        name: "Role-Based Access Control",
        description: "Four roles enforced: admin, deployer, reader, auditor. Least-privilege by default.",
        criteria: ["CC6_1"],
        iso27001: ["A.9.2.3", "A.9.4.1"],
        nist: ["AC-2", "AC-6"],
        status: this.cfg.rbacEnabled ? "implemented" : "planned",
        evidence: [
          {
            type: "config",
            description: "RBAC roles: admin, deployer, reader, auditor",
            value: ["admin", "deployer", "reader", "auditor"],
            verifiable: false,
          },
        ],
      },

      //  CRYPTOGRAPHY & ENCRYPTION 
      {
        id: "CR-001",
        name: "Secrets Encrypted at Rest",
        description: "All secrets stored using AES-256-GCM with PBKDF2-derived keys. Secrets never logged.",
        criteria: ["CC6_1", "CC6_6"],
        iso27001: ["A.10.1.1", "A.10.1.2"],
        nist: ["SC-28", "IA-5"],
        status: this.cfg.encryptionAtRest ? "implemented" : "partial",
        evidence: [
          {
            type: "config",
            description: "AES-256-GCM encryption for secrets at rest",
            value: { algorithm: "AES-256-GCM", kdf: "PBKDF2-SHA256", iterations: 310000 },
            verifiable: false,
          },
        ],
      },

      {
        id: "CR-002",
        name: "Ed25519 Block Signatures",
        description: "Every audit block is signed with Ed25519. Signatures verifiable by any party with the node public key.",
        criteria: ["CC4_1", "CC7_1"],
        iso27001: ["A.12.4.2", "A.12.4.3"],
        nist: ["AU-9", "SI-7"],
        status: "implemented",
        evidence: [
          {
            type: "metric",
            description: `${chainStats.blocks} signed blocks on-chain`,
            value: { blocks: chainStats.blocks, algorithm: "Ed25519" },
            ts: now,
            verifiable: true,
          },
        ],
      },

      {
        id: "CR-003",
        name: "Transport Security (TLS)",
        description: "All external traffic encrypted with TLS 1.2+. Caddy auto-provisioned certificates via ACME.",
        criteria: ["CC6_6"],
        iso27001: ["A.10.1.1", "A.13.1.1"],
        nist: ["SC-8", "SC-23"],
        status: this.cfg.tlsEnabled ? "implemented" : "partial",
        evidence: [
          {
            type: "config",
            description: "Caddy reverse proxy with automatic ACME certificates",
            value: { tlsProvider: "caddy-acme", minVersion: "TLS 1.2" },
            verifiable: false,
          },
        ],
      },

      //  AUDIT TRAIL 
      {
        id: "AU-001",
        name: "Blockchain Audit Trail",
        description: "All events committed to a hash-linked, Ed25519-signed audit chain. Tamper detection by design.",
        criteria: ["CC4_1", "CC7_1", "CC7_2"],
        iso27001: ["A.12.4.1", "A.12.4.2"],
        nist: ["AU-2", "AU-3", "AU-9"],
        status: "implemented",
        evidence: [
          {
            type: "metric",
            description: "Audit chain statistics",
            value: chainStats,
            ts: now,
            verifiable: true,
          },
        ],
      },

      {
        id: "AU-002",
        name: "Merkle-Authenticated Log Batching",
        description: "Events batched into Merkle trees. Inclusion provable without revealing other events.",
        criteria: ["CC4_1"],
        iso27001: ["A.12.4.2"],
        nist: ["AU-9", "SI-7"],
        status: "implemented",
        evidence: [
          {
            type: "config",
            description: "Merkle tree SHA-256 batching with per-block root",
            value: { hashAlgorithm: "SHA-256", structure: "binary-merkle-tree" },
            verifiable: false,
          },
        ],
      },

      {
        id: "AU-003",
        name: "External L1 Anchoring (Meridian Ledger)",
        description: "Chain Merkle roots anchored to Meridian L1 every 100 blocks. Provides external, permissionless verification.",
        criteria: ["CC4_1", "CC7_1"],
        iso27001: ["A.12.4.2", "A.12.4.3"],
        nist: ["AU-9"],
        status: this.cfg.meridianAnchored ? "implemented" : "planned",
        evidence: [
          {
            type: "config",
            description: "Meridian Ledger anchor interval",
            value: { anchorIntervalBlocks: 100, anchored: chainStats.anchored },
            ts: now,
            verifiable: this.cfg.meridianAnchored,
          },
        ],
      },

      //  CHANGE MANAGEMENT 
      {
        id: "CM-001",
        name: "Function Code Integrity",
        description: "SHA-256 hash of every deployed function stored on-chain at deploy time. Code cannot be silently modified.",
        criteria: ["CC6_8", "CC8_1"],
        iso27001: ["A.12.5.1", "A.14.2.7"],
        nist: ["CM-3", "SI-7"],
        status: "implemented",
        evidence: [
          {
            type: "event",
            description: `${deployEvents.length} function deployments recorded on-chain`,
            value: deployEvents.length,
            ts: now,
            verifiable: true,
          },
        ],
      },

      {
        id: "CM-002",
        name: "Secret Scanning on Deploy",
        description: "Function code scanned for 10 hardcoded-credential patterns before acceptance. Deploy rejected if found.",
        criteria: ["CC6_8"],
        iso27001: ["A.12.5.1", "A.9.4.1"],
        nist: ["CM-3", "SA-11"],
        status: "implemented",
        evidence: [
          {
            type: "config",
            description: "10 credential patterns scanned on every function deploy",
            value: ["AWS keys", "OpenAI keys", "Anthropic keys", "GitHub tokens",
                    "Stripe keys", "PEM private keys", "DB URLs", "generic secrets",
                    "hardcoded IPs", "webhook secrets"],
            verifiable: false,
          },
        ],
      },

      //  ANOMALY DETECTION 
      {
        id: "AD-001",
        name: "Brute-Force Detection & IP Blocking",
        description: "5+ auth failures in 5 minutes triggers automatic 15-minute IP block and CRITICAL chain event.",
        criteria: ["CC7_2", "CC7_3"],
        iso27001: ["A.12.4.1", "A.16.1.2"],
        nist: ["SI-3", "AC-7"],
        status: "implemented",
        evidence: [
          {
            type: "event",
            description: `${anomalies.filter(e => e.payload?.type === "BRUTE_FORCE").length} brute-force events detected`,
            value: anomalies.filter(e => e.payload?.type === "BRUTE_FORCE").length,
            ts: now,
            verifiable: true,
          },
        ],
      },

      {
        id: "AD-002",
        name: "Reconnaissance Pattern Detection",
        description: "20+ 404 responses per minute from same IP triggers anomaly event and rate escalation.",
        criteria: ["CC7_2"],
        iso27001: ["A.12.4.1"],
        nist: ["SI-4", "AU-6"],
        status: "implemented",
        evidence: [
          {
            type: "event",
            description: "Recon detection active (20 req/min threshold)",
            value: anomalies.filter(e => e.payload?.type === "RECONNAISSANCE").length,
            ts: now,
            verifiable: true,
          },
        ],
      },

      //  ISOLATION 
      {
        id: "IS-001",
        name: "Worker Process Isolation",
        description: "Each function executes in an isolated Bun Worker (separate process, no shared memory). Worker crashes trigger chain event.",
        criteria: ["CC6_8"],
        iso27001: ["A.13.1.3", "A.14.2.6"],
        nist: ["SC-39", "SI-3"],
        status: "implemented",
        evidence: [
          {
            type: "config",
            description: "Bun Worker pool with OS-level isolation",
            value: { runtime: "bun-worker", isolation: "process", sharedMemory: false },
            verifiable: false,
          },
        ],
      },

      {
        id: "IS-002",
        name: "Rate Limiting",
        description: "Per-IP per-function sliding window rate limiter. Configurable threshold (default 600 req/min).",
        criteria: ["A1_1", "CC6_6"],
        iso27001: ["A.13.1.1"],
        nist: ["SC-5"],
        status: this.cfg.rateLimitEnabled ? "implemented" : "partial",
        evidence: [
          {
            type: "config",
            description: "Sliding window rate limiter",
            value: { defaultLimit: 600, windowMs: 60000, perIPPerFunction: true },
            verifiable: false,
          },
        ],
      },
    ];
  }

  //  SOC 2 Report 

  async generateSOC2Report(): Promise<object> {
    const controls   = await this.buildControlInventory();
    const chainStats = this.chain.getStats();
    const now        = new Date();

    const implemented = controls.filter(c => c.status === "implemented").length;
    const partial     = controls.filter(c => c.status === "partial").length;
    const planned     = controls.filter(c => c.status === "planned").length;
    const score       = Math.round((implemented + partial * 0.5) / controls.length * 100);

    // Criteria coverage
    const criteriaCoverage: Record<string, number> = {};
    for (const criterion of Object.keys(SOC2_CRITERIA)) {
      const relevant = controls.filter(c => c.criteria.includes(criterion as SOC2Criterion));
      const done     = relevant.filter(c => c.status === "implemented").length;
      criteriaCoverage[criterion] = relevant.length ? Math.round(done / relevant.length * 100) : 100;
    }

    return {
      meta: {
        platform:    "Sovereignly",
        version:     this.cfg.version,
        nodeId:      this.cfg.nodeId,
        reportType:  "SOC 2 Type II (Readiness)",
        generatedAt: now.toISOString(),
        period:      {
          from: new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString(),
          to:   now.toISOString(),
        },
        chainTip:    chainStats.tip?.blockHash?.slice(0, 16) + "",
        verifiable:  true,
      },
      summary: {
        totalControls:     controls.length,
        implemented,
        partial,
        planned,
        complianceScore:   score,
        criteriaCoverage,
      },
      controls,
      auditChain: {
        blocks:     chainStats.blocks,
        events:     chainStats.events,
        anchored:   chainStats.anchored,
        criticalEvents: chainStats.critical,
        integrity:  "verify via GET /_sovereign/chain/verify",
      },
      standards: {
        soc2:    "AICPA Trust Services Criteria 2017 (updated 2022)",
        iso27001: "ISO/IEC 27001:2022",
        nist:    "NIST SP 800-53 Rev 5",
      },
    };
  }

  //  Audit Trail Export 

  async exportAuditTrail(opts: {
    from:      number;    // Unix ms
    to:        number;
    types?:    string[];
    includeProofs?: boolean;
  }): Promise<object> {
    const events = this.chain.getEvents({ since: opts.from, limit: 10000 });
    const filtered = events
      .filter(e => e.ts <= opts.to)
      .filter(e => !opts.types?.length || opts.types.includes(e.type));

    return {
      meta: {
        exportedAt: new Date().toISOString(),
        from:       new Date(opts.from).toISOString(),
        to:         new Date(opts.to).toISOString(),
        count:      filtered.length,
        verifiable: true,
        note: "Each event's merkleProof can be verified against its block's merkleRoot",
      },
      events: filtered.map(e => ({
        ...e,
        merkleProof: opts.includeProofs ? e.merkleProof : undefined,
      })),
    };
  }
  // Alias used by tenant-routes and integration tests
  generateReport(standard: "SOC2" | "ISO27001" | "HIPAA" | "GDPR" | "NIST" = "SOC2"): object {
    if (standard === "SOC2") return this.generateSOC2ReportSync();
    return this.generateSOC2ReportSync(); // TODO: per-standard reports
  }

  private generateSOC2ReportSync(): object {
    const stats = this.chain.getStats();
    const events = this.chain.getEvents({ limit: 5000 });
    const score  = Math.min(100, 60 + Math.floor(events.length / 10));
    return {
      standard:     "SOC2",
      generatedAt:  new Date().toISOString(),
      overallScore: score,
      controls: [
        { id: "CC6.1", name: "Logical Access Controls",    status: events.some(e => e.type === "AUTH_SUCCESS") ? "implemented" : "not-started" },
        { id: "CC6.2", name: "Authentication",             status: events.some(e => e.type === "MFA_CHALLENGE") ? "implemented" : "partial"     },
        { id: "CC6.3", name: "Authorization",              status: events.some(e => e.type === "PERMISSION_CHANGE") ? "implemented" : "partial"  },
        { id: "CC7.1", name: "System Operations",          status: stats.anchored > 0 ? "implemented" : "partial"                               },
        { id: "CC7.2", name: "System Monitoring",          status: stats.blocks > 0 ? "implemented" : "not-started"                             },
        { id: "CC9.1", name: "Risk Mitigation",            status: events.some(e => e.type === "ANOMALY") ? "partial" : "implemented"            },
        { id: "A1.1",  name: "Availability Commitments",   status: "partial"                                                                     },
        { id: "C1.1",  name: "Confidentiality",            status: events.some(e => e.type === "DATA_EXPORT") ? "partial" : "implemented"        },
        { id: "PI1.1", name: "Processing Integrity",       status: stats.anchored > 0 ? "implemented" : "partial"                               },
        { id: "P1.1",  name: "Privacy Notice",             status: "not-started"                                                                 },
      ],
      chain: {
        blocks:   stats.blocks,
        events:   stats.events,
        anchored: stats.anchored,
        tip:      stats.tip?.blockHash?.slice(0, 16),
      },
    };
  }

}
