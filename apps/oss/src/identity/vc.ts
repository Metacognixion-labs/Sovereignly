/**
 * Sovereignly Verifiable Credentials Module
 *
 * Issues W3C Verifiable Credentials (VC Data Model 2.0) for:
 *   - Compliance attestations (SOC2, ISO27001 control status)
 *   - Audit chain proofs (cryptographically verifiable event inclusion)
 *   - Identity assertions (passkey-authenticated user claims)
 *
 * Supports:
 *   - did:web for issuer identity (resolves via HTTPS)
 *   - Ed25519 proof signatures (same key as chain block signing)
 *   - Portable credentials (JSON-LD compatible)
 *
 * References:
 *   https://www.w3.org/TR/vc-data-model-2.0/
 *   https://www.w3.org/TR/did-core/
 *   https://w3c-ccg.github.io/did-method-web/
 */

import type { Hono } from "hono";
import { sha256, signEd25519 } from "../security/crypto.ts";
import type { SovereignChain } from "../security/chain.ts";

// -- Types --------------------------------------------------------------------

export interface VerifiableCredential {
  "@context":          string[];
  type:                string[];
  id:                  string;
  issuer:              string | { id: string; name: string };
  issuanceDate:        string;
  expirationDate?:     string;
  credentialSubject:   Record<string, unknown>;
  proof:               CredentialProof;
}

interface CredentialProof {
  type:               string;
  created:            string;
  verificationMethod: string;
  proofPurpose:       string;
  proofValue:         string;   // base64url Ed25519 signature
}

export interface VCIssuerConfig {
  domain:       string;     // e.g. "sovereignly.io"
  issuerName:   string;     // e.g. "Sovereignly Cloud"
  privateKey:   Uint8Array; // Ed25519 signing key
  publicKeyHex: string;     // hex-encoded public key for did:web document
}

// -- did:web DID Document Generator -------------------------------------------

export function generateDIDDocument(config: VCIssuerConfig): Record<string, unknown> {
  const did = `did:web:${config.domain}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [{
      id: `${did}#key-1`,
      type: "Ed25519VerificationKey2020",
      controller: did,
      publicKeyMultibase: `z${Buffer.from(config.publicKeyHex, "hex").toString("base64url")}`,
    }],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
    service: [{
      id: `${did}#sovereign-chain`,
      type: "SovereignAuditChain",
      serviceEndpoint: `https://${config.domain}/_sovereign/chain/stats`,
    }],
  };
}

// -- VC Issuer ----------------------------------------------------------------

export class VCIssuer {
  private config: VCIssuerConfig;
  private issuedCount = 0;

  constructor(config: VCIssuerConfig) {
    this.config = config;
  }

  get did(): string {
    return `did:web:${this.config.domain}`;
  }

  /** Issue a compliance attestation VC */
  async issueComplianceVC(opts: {
    subjectId:       string;    // tenant or org ID
    subjectName:     string;
    standard:        string;    // "SOC2", "ISO27001", "NIST"
    score:           number;    // 0-100
    controls:        Array<{ id: string; status: string }>;
    chainProof: {
      blockCount:    number;
      eventCount:    number;
      merkleRoot:    string;
      anchorUID?:    string;    // EAS attestation UID
    };
    validDays?:      number;    // default 90
  }): Promise<VerifiableCredential> {
    const now = new Date();
    const expiry = new Date(now.getTime() + (opts.validDays ?? 90) * 86400_000);
    const vcId = `urn:uuid:${crypto.randomUUID()}`;

    const credential: Omit<VerifiableCredential, "proof"> = {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      type: ["VerifiableCredential", "ComplianceAttestation"],
      id: vcId,
      issuer: { id: this.did, name: this.config.issuerName },
      issuanceDate: now.toISOString(),
      expirationDate: expiry.toISOString(),
      credentialSubject: {
        id: `${this.did}:tenant:${opts.subjectId}`,
        name: opts.subjectName,
        complianceStandard: opts.standard,
        complianceScore: opts.score,
        controlsSummary: {
          total: opts.controls.length,
          implemented: opts.controls.filter(c => c.status === "implemented").length,
          partial: opts.controls.filter(c => c.status === "partial").length,
          missing: opts.controls.filter(c => c.status === "missing" || c.status === "planned").length,
        },
        auditChainProof: {
          blockCount: opts.chainProof.blockCount,
          eventCount: opts.chainProof.eventCount,
          merkleRoot: opts.chainProof.merkleRoot,
          omnichainAnchor: opts.chainProof.anchorUID,
          verifiable: true,
        },
        assessmentDate: now.toISOString(),
      },
    };

    const proof = await this.sign(credential);
    this.issuedCount++;

    return { ...credential, proof };
  }

  /** Issue an audit proof VC (proves a specific event exists in the chain) */
  async issueAuditProofVC(opts: {
    eventId:     string;
    eventType:   string;
    merkleProof: { root: string; leaf: string; proof: Array<{ sibling: string; direction: string }> };
    blockIndex:  number;
    anchorUID?:  string;
  }): Promise<VerifiableCredential> {
    const now = new Date();
    const vcId = `urn:uuid:${crypto.randomUUID()}`;

    const credential: Omit<VerifiableCredential, "proof"> = {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      type: ["VerifiableCredential", "AuditProof"],
      id: vcId,
      issuer: { id: this.did, name: this.config.issuerName },
      issuanceDate: now.toISOString(),
      credentialSubject: {
        eventId: opts.eventId,
        eventType: opts.eventType,
        blockIndex: opts.blockIndex,
        merkleRoot: opts.merkleProof.root,
        merkleLeaf: opts.merkleProof.leaf,
        merkleProofPath: opts.merkleProof.proof,
        omnichainAnchor: opts.anchorUID,
        verificationMethod: "Independent Merkle proof verification",
      },
    };

    const proof = await this.sign(credential);
    this.issuedCount++;

    return { ...credential, proof };
  }

  /** Sign a credential with Ed25519 */
  private async sign(credential: Omit<VerifiableCredential, "proof">): Promise<CredentialProof> {
    const canonicalJson = JSON.stringify(credential, Object.keys(credential).sort());
    const hash = await sha256(canonicalJson);
    const signature = await signEd25519(this.config.privateKey, hash);

    return {
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: `${this.did}#key-1`,
      proofPurpose: "assertionMethod",
      proofValue: signature,
    };
  }

  stats() {
    return {
      issuer: this.did,
      issuedCredentials: this.issuedCount,
    };
  }
}

// -- Route Registration -------------------------------------------------------

export function registerVCRoutes(
  app: Hono,
  issuer: VCIssuer,
  chain: SovereignChain,
  opts: { adminToken?: string }
) {
  // did:web resolution endpoint (/.well-known/did.json)
  app.get("/.well-known/did.json", (c) => {
    return c.json(generateDIDDocument(issuer["config"]));
  });

  // Issue a compliance VC
  app.post("/_sovereign/credentials/compliance", async (c) => {
    const token = c.req.header("x-sovereign-token") ?? "";
    if (!opts.adminToken || token !== opts.adminToken) {
      return c.json({ error: "admin required" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as any;
    const { subjectId, subjectName, standard = "SOC2" } = body;
    if (!subjectId || !subjectName) {
      return c.json({ error: "subjectId and subjectName required" }, 400);
    }

    const stats = chain.getStats();
    const vc = await issuer.issueComplianceVC({
      subjectId,
      subjectName,
      standard,
      score: body.score ?? 75,
      controls: body.controls ?? [],
      chainProof: {
        blockCount: stats.blocks,
        eventCount: stats.events,
        merkleRoot: stats.tip?.merkleRoot ?? "",
        anchorUID: body.anchorUID,
      },
    });

    void chain.emit("CONFIG_CHANGE", {
      event: "vc_issued", type: "ComplianceAttestation", vcId: vc.id, standard,
    }, "LOW");

    return c.json(vc, 201);
  });

  // Stats
  app.get("/_sovereign/credentials/stats", (c) => {
    return c.json(issuer.stats());
  });
}
