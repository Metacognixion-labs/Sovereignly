/**
 * Sovereignly Cloud — Quantum Integration API Routes
 * Business Source License 1.1 — MetaCognixion
 *
 * Admin endpoints for quantum computing integration:
 *   GET  /_sovereign/quantum/health    → Quantum service health
 *   GET  /_sovereign/quantum/entropy   → Entropy pool status
 *   POST /_sovereign/quantum/random    → Generate quantum random bytes
 *   POST /_sovereign/quantum/attest    → Quantum attestation of Merkle root
 */

import type { Hono }                from "hono";
import type { OriginQuantumCloud }  from "./origin-cloud.ts";
import { timingSafeEqual }          from "../../../oss/src/security/crypto.ts";

export function registerQuantumRoutes(
  app:     Hono,
  quantum: OriginQuantumCloud,
  cfg:     { adminToken?: string },
) {
  const PREFIX = "/_sovereign/quantum";

  function requireAdmin(c: any): boolean {
    const token = c.req.header("x-sovereign-token") ?? "";
    return !!cfg.adminToken && timingSafeEqual(token, cfg.adminToken);
  }

  // ── Health ─────────────────────────────────────────────────────────────

  app.get(`${PREFIX}/health`, async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    return c.json(await quantum.health());
  });

  // ── Entropy Pool Status ────────────────────────────────────────────────

  app.get(`${PREFIX}/entropy`, async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);
    const health = await quantum.health();
    return c.json({
      poolBytes:      health.entropyPoolBytes,
      poolMax:        health.entropyPoolMax,
      poolPercent:    Math.round(health.entropyPoolBytes / health.entropyPoolMax * 100),
      totalCalls:     health.totalQRNGCalls,
      totalFallbacks: health.totalFallbacks,
      fallbackRate:   health.totalQRNGCalls > 0
        ? (health.totalFallbacks / health.totalQRNGCalls * 100).toFixed(1) + "%"
        : "0%",
      lastRefill:     health.lastRefill,
    });
  });

  // ── Generate Quantum Random ────────────────────────────────────────────

  app.post(`${PREFIX}/random`, async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);

    const { numBytes = 32 } = await c.req.json().catch(() => ({}));
    const clamped = Math.min(Math.max(1, numBytes), 1024);

    try {
      const result = await quantum.getRandomBytes(clamped);
      return c.json({
        hex:    result.randomHex,
        source: result.source,
        chip:   result.chip,
        qubits: result.qubits,
        shots:  result.shots,
        bytes:  clamped,
      });
    } catch (e: any) {
      return c.json({ error: e.message }, 500);
    }
  });

  // ── Quantum Attestation ────────────────────────────────────────────────

  app.post(`${PREFIX}/attest`, async (c) => {
    if (!requireAdmin(c)) return c.json({ error: "admin required" }, 403);

    const { merkleRoot, blockIndex, eventCount, orgId = "platform" } = await c.req.json().catch(() => ({}));
    if (!merkleRoot) return c.json({ error: "merkleRoot required" }, 400);

    try {
      const result = await quantum.attestMerkleRoot(merkleRoot, blockIndex ?? 0, eventCount ?? 0, orgId);
      return c.json({
        ok: true,
        fingerprint: result.quantumFingerprint,
        chip:        result.chip,
        qubits:      result.qubits,
        depth:       result.circuitDepth,
        taskId:      result.taskId,
        distributionSize: Object.keys(result.distribution).length,
      });
    } catch (e: any) {
      return c.json({ error: e.message }, 500);
    }
  });
}
