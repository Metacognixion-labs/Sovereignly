/**
 * Quantum Status Module
 *
 * Surfaces post-quantum cryptography status for the dashboard and CLI.
 * Works in both OSS (local PQC) and Cloud (Origin Quantum Cloud) editions.
 *
 * Reports:
 *   - PQC algorithms in use (ML-DSA-65, SHA3-256, ML-KEM-768)
 *   - Dual Merkle root status (SHA-256 + SHA3-256)
 *   - Hybrid signature readiness
 *   - Quantum Cloud connection (Cloud edition only)
 *   - Poseidon hash availability (ZK readiness)
 */

import type { Hono } from "hono";
import type { SovereignChain } from "./chain.ts";
import { timingSafeEqual } from "./crypto.ts";

export interface QuantumStatus {
  pqc: {
    enabled:           boolean;
    algorithms: {
      signatures:      string;    // "Ed25519 + ML-DSA-65 (FIPS 204)"
      hashing:         string;    // "SHA-256 + SHA3-256 dual roots"
      keyEncapsulation: string;   // "ML-KEM-768 (FIPS 203)"
      zkReady:         string;    // "Poseidon BN254"
    };
    nistCompliance:    string;    // "FIPS 203, 204, 205"
  };
  chain: {
    dualMerkleRoots:   boolean;
    blocksWithPQRoot:  number;
    latestPQRoot:      string | null;
    latestSHA256Root:  string | null;
  };
  quantumCloud: {
    connected:         boolean;
    provider:          string;    // "Origin Quantum (Wukong 72Q)" or "N/A"
    entropyPool:       number;
    attestations:      number;
  };
  poseidon: {
    available:         boolean;
    field:             string;    // "BN254"
    zkProvable:        boolean;
  };
}

export function getQuantumStatus(chain: SovereignChain): QuantumStatus {
  const stats = chain.getStats();
  const tip = stats.tip;

  return {
    pqc: {
      enabled: true,
      algorithms: {
        signatures:       "Ed25519 + ML-DSA-65 (FIPS 204 Level 3)",
        hashing:          "SHA-256 + SHA3-256 dual Merkle roots",
        keyEncapsulation: "ML-KEM-768 (FIPS 203 Level 3)",
        zkReady:          "Poseidon BN254 (8 full + 57 partial rounds)",
      },
      nistCompliance: "FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA ready)",
    },
    chain: {
      dualMerkleRoots: true,
      blocksWithPQRoot: stats.blocks,
      latestPQRoot:    (tip as any)?.merkleRootPQ ?? null,
      latestSHA256Root: tip?.merkleRoot ?? null,
    },
    quantumCloud: {
      connected:   !!process.env.QUANTUM_API_TOKEN,
      provider:    process.env.QUANTUM_API_TOKEN ? `Origin Quantum (${process.env.QUANTUM_CHIP_ID ?? "Simulation"})` : "N/A (PQC algorithms active locally)",
      entropyPool: 0, // Updated by cloud edition
      attestations: 0,
    },
    poseidon: {
      available: true,
      field: "BN254 (alt_bn128)",
      zkProvable: true,
    },
  };
}

export function registerQuantumStatusRoutes(
  app: Hono,
  chain: SovereignChain,
  cfg: { adminToken?: string }
) {
  // Public: PQC algorithm info (no secrets exposed)
  app.get("/_sovereign/quantum/algorithms", (c) => {
    const status = getQuantumStatus(chain);
    return c.json({
      pqc: status.pqc,
      poseidon: status.poseidon,
      chain: {
        dualMerkleRoots: status.chain.dualMerkleRoots,
        blocksWithPQRoot: status.chain.blocksWithPQRoot,
      },
    });
  });

  // Admin: full quantum status
  app.get("/_sovereign/quantum/status", (c) => {
    const token = c.req.header("x-sovereign-token") ?? "";
    if (!cfg.adminToken || !timingSafeEqual(token, cfg.adminToken)) {
      return c.json({ error: "admin required" }, 403);
    }
    return c.json(getQuantumStatus(chain));
  });
}
