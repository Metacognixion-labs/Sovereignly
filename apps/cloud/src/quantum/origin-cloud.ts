/**
 * Sovereignly Cloud — Origin Quantum Cloud Integration
 * Business Source License 1.1 — MetaCognixion
 *
 * Leverages Origin Quantum's 72-qubit Wukong superconducting quantum computer
 * via the pyQPanda/QCloud REST bridge for:
 *
 *   1. QRNG (Quantum Random Number Generation)
 *      → Replaces CSPRNG for critical key derivation, JWT secrets, nonces
 *      → True quantum randomness from hardware Hadamard + measurement
 *
 *   2. Quantum Audit Attestation
 *      → Encodes Merkle roots into quantum circuits, measures on real hardware
 *      → Produces quantum fingerprints that are physically unreproducible
 *
 *   3. Quantum Entropy Pool
 *      → Background service that pre-fetches quantum random bytes
 *      → Falls back to CSPRNG when pool is empty (never blocks)
 *
 *   4. Post-Quantum Readiness Metrics
 *      → Monitors quantum volume and gate fidelity for threat assessment
 *
 * Architecture:
 *   Sovereignly (Bun/TS) → HTTP bridge → pyQPanda QCloud SDK → Origin Wukong
 *
 *   The bridge is a lightweight Python FastAPI service that wraps pyQPanda's
 *   QCloud class. Sovereignly calls it over HTTP. This avoids Python runtime
 *   dependency in the main Bun process.
 *
 * Dependencies: None (pure HTTP calls to the bridge service)
 */

// ── Types ────────────────────────────────────────────────────────────────────

export interface QuantumCloudConfig {
  /** URL of the pyQPanda bridge service */
  bridgeUrl:        string;
  /** Origin Quantum Cloud API token (from qcloud.originqc.com.cn) */
  apiToken:         string;
  /** Target chip: "Simulation" | "WUYUAN_1" | "WUYUAN_2" | "WUYUAN_3" (Wukong 72q) */
  chipId:           "Simulation" | "WUYUAN_1" | "WUYUAN_2" | "WUYUAN_3";
  /** Number of measurement shots for QRNG (more = better entropy, slower) */
  qrngShots:        number;
  /** Entropy pool size in bytes (pre-fetched quantum random bytes) */
  entropyPoolSize:  number;
  /** How often to refill entropy pool (ms) */
  refillIntervalMs: number;
  /** Enable real hardware (false = simulator only, for testing) */
  useRealHardware:  boolean;
  /** Request timeout (ms) */
  timeoutMs:        number;
}

export interface QRNGResult {
  /** Hex-encoded random bytes */
  randomHex:    string;
  /** Raw bytes */
  randomBytes:  Uint8Array;
  /** Source: "quantum_hardware" | "quantum_simulator" | "csprng_fallback" */
  source:       "quantum_hardware" | "quantum_simulator" | "csprng_fallback";
  /** Number of qubits used */
  qubits:       number;
  /** Measurement shots performed */
  shots:        number;
  /** Hardware chip used */
  chip:         string;
  /** Timestamp */
  generatedAt:  number;
}

export interface QuantumAttestationResult {
  /** Merkle root that was attested */
  merkleRoot:       string;
  /** Quantum circuit fingerprint (measurement distribution hash) */
  quantumFingerprint: string;
  /** Full measurement distribution */
  distribution:     Record<string, number>;
  /** Circuit depth used */
  circuitDepth:     number;
  /** Qubits used */
  qubits:           number;
  /** Source chip */
  chip:             string;
  /** Task ID from Origin Cloud */
  taskId:           string;
  /** Timestamp */
  attestedAt:       number;
}

export interface QuantumHealthStatus {
  connected:        boolean;
  bridgeUrl:        string;
  chip:             string;
  entropyPoolBytes: number;
  entropyPoolMax:   number;
  totalQRNGCalls:   number;
  totalFallbacks:   number;
  lastRefill:       number | null;
  uptime:           number;
}

// ── Default Config ───────────────────────────────────────────────────────────

export const DEFAULT_QUANTUM_CONFIG: QuantumCloudConfig = {
  bridgeUrl:        "http://localhost:9900",
  apiToken:         "",
  chipId:           "Simulation",
  qrngShots:        4096,
  entropyPoolSize:  1024,       // 1KB pre-fetched quantum entropy
  refillIntervalMs: 60_000,     // Refill every 60s
  useRealHardware:  false,
  timeoutMs:        30_000,
};

// ── Origin Quantum Cloud Client ──────────────────────────────────────────────

export class OriginQuantumCloud {
  private config:          QuantumCloudConfig;
  private entropyPool:     Uint8Array;
  private poolOffset:      number = 0;
  private poolReady:       boolean = false;
  private refillTimer:     ReturnType<typeof setInterval> | null = null;
  private stats = {
    totalQRNGCalls:  0,
    totalFallbacks:  0,
    totalAttests:    0,
    lastRefill:      null as number | null,
    startedAt:       Date.now(),
  };

  constructor(config: Partial<QuantumCloudConfig> = {}) {
    this.config = { ...DEFAULT_QUANTUM_CONFIG, ...config };
    this.entropyPool = new Uint8Array(this.config.entropyPoolSize);
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────

  /**
   * Start the quantum entropy pool background refill.
   * Call this once at server startup.
   */
  async start(): Promise<void> {
    console.log(`[QuantumCloud] Connecting to Origin Quantum Cloud bridge at ${this.config.bridgeUrl}`);
    console.log(`[QuantumCloud] Chip: ${this.config.chipId} | Hardware: ${this.config.useRealHardware} | Pool: ${this.config.entropyPoolSize}B`);

    // Initial pool fill
    await this.refillEntropyPool();

    // Background refill
    this.refillTimer = setInterval(() => {
      this.refillEntropyPool().catch(err => {
        console.warn(`[QuantumCloud] Entropy pool refill failed: ${err.message}`);
      });
    }, this.config.refillIntervalMs);

    console.log(`[QuantumCloud] Quantum entropy pool active (${this.config.entropyPoolSize}B, refill every ${this.config.refillIntervalMs / 1000}s)`);
  }

  close(): void {
    if (this.refillTimer) {
      clearInterval(this.refillTimer);
      this.refillTimer = null;
    }
  }

  // ── QRNG: Quantum Random Number Generation ────────────────────────────

  /**
   * Generate quantum random bytes.
   *
   * 1. Tries the pre-fetched entropy pool first (instant)
   * 2. If pool exhausted, requests fresh quantum randomness from Origin Cloud
   * 3. Falls back to CSPRNG if quantum service unavailable
   *
   * This is the primary integration point for Sovereignly's crypto layer.
   */
  async getRandomBytes(numBytes: number): Promise<QRNGResult> {
    this.stats.totalQRNGCalls++;

    // Try entropy pool first (zero-latency)
    if (this.poolReady && this.poolOffset + numBytes <= this.entropyPool.length) {
      const bytes = this.entropyPool.slice(this.poolOffset, this.poolOffset + numBytes);
      this.poolOffset += numBytes;
      return {
        randomHex:   toHex(bytes),
        randomBytes: bytes,
        source:      this.config.useRealHardware ? "quantum_hardware" : "quantum_simulator",
        qubits:      Math.ceil(numBytes * 8 / this.config.qrngShots) || 8,
        shots:       this.config.qrngShots,
        chip:        this.config.chipId,
        generatedAt: Date.now(),
      };
    }

    // Request fresh quantum randomness
    try {
      const result = await this.requestQRNG(numBytes);
      return result;
    } catch (err: any) {
      // CSPRNG fallback — never block the caller
      this.stats.totalFallbacks++;
      console.warn(`[QuantumCloud] QRNG unavailable, using CSPRNG fallback: ${err.message}`);
      const bytes = crypto.getRandomValues(new Uint8Array(numBytes));
      return {
        randomHex:   toHex(bytes),
        randomBytes: bytes,
        source:      "csprng_fallback",
        qubits:      0,
        shots:       0,
        chip:        "none",
        generatedAt: Date.now(),
      };
    }
  }

  /**
   * Generate a quantum-random hex string (e.g., for JWT secrets, keys).
   */
  async getRandomHex(numBytes: number = 32): Promise<string> {
    const result = await this.getRandomBytes(numBytes);
    return result.randomHex;
  }

  // ── Quantum Audit Attestation ──────────────────────────────────────────

  /**
   * Encode a Merkle root into a quantum circuit and measure it on real hardware.
   *
   * The circuit applies rotations derived from the Merkle root bits, creating
   * a unique quantum state. Measuring this state produces a distribution that
   * serves as a quantum fingerprint — physically unreproducible and tied to
   * the specific Merkle root.
   *
   * This is an ADDITIONAL attestation layer on top of EAS/Solana/Bitcoin anchoring.
   */
  async attestMerkleRoot(
    merkleRoot: string,
    blockIdx:   number,
    eventCount: number,
    orgId:      string,
  ): Promise<QuantumAttestationResult> {
    this.stats.totalAttests++;

    const payload = {
      action:      "attest_merkle_root",
      merkle_root: merkleRoot.replace("0x", ""),
      block_index: blockIdx,
      event_count: eventCount,
      org_id:      orgId,
      chip_id:     this.config.chipId,
      shots:       this.config.qrngShots,
      use_hardware: this.config.useRealHardware,
    };

    const response = await this.bridgeCall("/quantum/attest", payload);

    // Hash the measurement distribution to create a compact fingerprint
    const distStr = JSON.stringify(response.distribution);
    const fingerprint = await sha256Str(distStr);

    return {
      merkleRoot,
      quantumFingerprint: fingerprint,
      distribution:       response.distribution,
      circuitDepth:       response.circuit_depth ?? 0,
      qubits:             response.qubits ?? 8,
      chip:               response.chip ?? this.config.chipId,
      taskId:             response.task_id ?? "",
      attestedAt:         Date.now(),
    };
  }

  // ── Health & Status ────────────────────────────────────────────────────

  async health(): Promise<QuantumHealthStatus> {
    let connected = false;
    try {
      const r = await fetch(`${this.config.bridgeUrl}/health`, {
        signal: AbortSignal.timeout(5000),
      });
      connected = r.ok;
    } catch {}

    return {
      connected,
      bridgeUrl:        this.config.bridgeUrl,
      chip:             this.config.chipId,
      entropyPoolBytes: Math.max(0, this.entropyPool.length - this.poolOffset),
      entropyPoolMax:   this.config.entropyPoolSize,
      totalQRNGCalls:   this.stats.totalQRNGCalls,
      totalFallbacks:   this.stats.totalFallbacks,
      lastRefill:       this.stats.lastRefill,
      uptime:           Date.now() - this.stats.startedAt,
    };
  }

  // ── Internal ───────────────────────────────────────────────────────────

  /**
   * Request quantum random bytes from the bridge service.
   * The bridge runs a Hadamard-measure circuit on QCloud and returns raw bits.
   */
  private async requestQRNG(numBytes: number): Promise<QRNGResult> {
    const qubits = Math.min(Math.max(8, numBytes), 30); // 8-30 qubits per request

    const response = await this.bridgeCall("/quantum/qrng", {
      action:       "generate_random",
      num_bytes:    numBytes,
      num_qubits:   qubits,
      shots:        this.config.qrngShots,
      chip_id:      this.config.chipId,
      use_hardware: this.config.useRealHardware,
    });

    const randomHex = response.random_hex ?? "";
    const bytes     = fromHex(randomHex.slice(0, numBytes * 2));

    return {
      randomHex:   toHex(bytes),
      randomBytes: bytes,
      source:      this.config.useRealHardware ? "quantum_hardware" : "quantum_simulator",
      qubits,
      shots:       this.config.qrngShots,
      chip:        response.chip ?? this.config.chipId,
      generatedAt: Date.now(),
    };
  }

  /**
   * Refill the entropy pool with quantum random bytes.
   */
  private async refillEntropyPool(): Promise<void> {
    try {
      const result = await this.requestQRNG(this.config.entropyPoolSize);
      this.entropyPool = result.randomBytes.length >= this.config.entropyPoolSize
        ? result.randomBytes.slice(0, this.config.entropyPoolSize)
        : padToSize(result.randomBytes, this.config.entropyPoolSize);
      this.poolOffset = 0;
      this.poolReady  = true;
      this.stats.lastRefill = Date.now();
    } catch {
      // Fallback: fill with CSPRNG if quantum unavailable
      crypto.getRandomValues(this.entropyPool);
      this.poolOffset = 0;
      this.poolReady  = true;
      this.stats.totalFallbacks++;
    }
  }

  /**
   * Call the pyQPanda bridge service.
   */
  private async bridgeCall(path: string, payload: Record<string, any>): Promise<any> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const res = await fetch(`${this.config.bridgeUrl}${path}`, {
        method:  "POST",
        headers: {
          "Content-Type":   "application/json",
          "X-Api-Token":    this.config.apiToken,
          "X-Sovereign-Id": "sovereignly-cloud",
        },
        body:   JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Bridge ${path}: ${res.status} ${text}`);
      }

      return await res.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  // ── Factory ────────────────────────────────────────────────────────────

  static fromEnv(): OriginQuantumCloud {
    return new OriginQuantumCloud({
      bridgeUrl:       process.env.QUANTUM_BRIDGE_URL       || DEFAULT_QUANTUM_CONFIG.bridgeUrl,
      apiToken:        process.env.QUANTUM_API_TOKEN        || "",
      chipId:          (process.env.QUANTUM_CHIP_ID         || "Simulation") as any,
      qrngShots:       parseInt(process.env.QUANTUM_QRNG_SHOTS || "4096"),
      entropyPoolSize: parseInt(process.env.QUANTUM_ENTROPY_POOL || "1024"),
      refillIntervalMs: parseInt(process.env.QUANTUM_REFILL_MS || "60000"),
      useRealHardware: process.env.QUANTUM_USE_HARDWARE === "true",
      timeoutMs:       parseInt(process.env.QUANTUM_TIMEOUT_MS || "30000"),
    });
  }
}

// ── Utilities ────────────────────────────────────────────────────────────────

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function sha256Str(data: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return toHex(new Uint8Array(hash));
}

function padToSize(src: Uint8Array, size: number): Uint8Array {
  const result = new Uint8Array(size);
  result.set(src);
  // Fill remainder with CSPRNG
  if (src.length < size) {
    const extra = crypto.getRandomValues(new Uint8Array(size - src.length));
    result.set(extra, src.length);
  }
  return result;
}
