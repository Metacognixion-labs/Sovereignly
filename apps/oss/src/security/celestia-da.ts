/**
 * Celestia Data Availability Anchor
 *
 * Submits audit data blobs to Celestia for data availability proofs.
 * Unlike hash-only anchoring (EAS), this stores the FULL event batch
 * on Celestia, enabling anyone to reconstruct the audit trail.
 *
 * Architecture:
 *   1. Serialize event batch → CBOR/JSON blob
 *   2. Submit to Celestia light node via REST API
 *   3. Get back: height, namespace, commitment, share proof
 *   4. Store receipt for verification
 *
 * Celestia provides:
 *   - Data availability sampling (DAS) — light nodes verify without downloading all data
 *   - Namespace-partitioned blobs — each tenant gets isolated namespace
 *   - 30-day retention (sufficient for audit bridge to permanent storage)
 *
 * Integration:
 *   - Extends OmnichainAnchor as an optional 7th chain
 *   - Tier: enterprise+ (requires Celestia light node or API provider)
 *
 * References:
 *   https://docs.celestia.org/developers/submit-data
 *   https://docs.celestia.org/developers/node-api
 */

export interface CelestiaConfig {
  /** Celestia light node REST API URL (e.g. http://localhost:26659) */
  apiUrl:       string;
  /** Auth token for Celestia node API */
  authToken?:   string;
  /** Namespace for this Sovereignly instance (10 bytes, hex-encoded) */
  namespace:    string;
  /** Whether to submit full event data or just merkle roots */
  fullBlobs:    boolean;
}

export interface CelestiaReceipt {
  height:       number;         // Celestia block height
  namespace:    string;         // namespace ID
  commitment:   string;         // blob commitment hash
  shareVersion: number;
  submittedAt:  number;         // Unix ms
  blobSize:     number;         // bytes
  dataHash?:    string;         // SHA-256 of submitted data
}

export interface AuditBlob {
  version:      string;         // "sovereign-v3"
  orgId:        string;
  blockIndex:   number;
  merkleRoot:   string;
  eventCount:   number;
  events?:      Array<{         // included when fullBlobs=true
    id:         string;
    type:       string;
    ts:         number;
    severity:   string;
    payloadHash: string;        // SHA-256 of payload (not payload itself)
  }>;
  timestamp:    number;
}

// -- Celestia DA Client -------------------------------------------------------

export class CelestiaDAClient {
  private config: CelestiaConfig;
  private submitCount = 0;
  private totalBytesSubmitted = 0;

  constructor(config: CelestiaConfig) {
    this.config = config;
    // Validate namespace (must be 10 bytes = 20 hex chars)
    const ns = config.namespace.replace("0x", "");
    if (ns.length !== 20) {
      throw new Error(`Celestia namespace must be 10 bytes (20 hex chars), got ${ns.length}`);
    }
  }

  /**
   * Submit an audit blob to Celestia.
   * Returns a receipt with height and commitment for verification.
   */
  async submitBlob(blob: AuditBlob): Promise<CelestiaReceipt> {
    const data = JSON.stringify(blob);
    const dataBytes = new TextEncoder().encode(data);
    const b64Data = btoa(String.fromCharCode(...dataBytes));

    // Celestia blob.Submit RPC
    const response = await fetch(`${this.config.apiUrl}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.config.authToken ? { "Authorization": `Bearer ${this.config.authToken}` } : {}),
      },
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "blob.Submit",
        params: [
          [{
            namespace: this.config.namespace,
            data: b64Data,
            share_version: 0,
            commitment: "", // server computes
          }],
          0.002, // gas price
        ],
      }),
      signal: AbortSignal.timeout(30_000),
    });

    const result = await response.json() as {
      result?: number;  // block height
      error?: { message: string; code?: number };
    };

    if (result.error) {
      throw new Error(`Celestia submit failed: ${result.error.message}`);
    }

    const height = result.result ?? 0;

    // Get the blob commitment for verification
    const commitment = await this.getCommitment(height);

    const receipt: CelestiaReceipt = {
      height,
      namespace: this.config.namespace,
      commitment,
      shareVersion: 0,
      submittedAt: Date.now(),
      blobSize: dataBytes.length,
      dataHash: await sha256Hex(data),
    };

    this.submitCount++;
    this.totalBytesSubmitted += dataBytes.length;

    return receipt;
  }

  /** Verify a blob exists at the given height */
  async verifyBlob(height: number): Promise<{
    exists: boolean;
    blobs?: Array<{ namespace: string; data: string; commitment: string }>;
  }> {
    try {
      const response = await fetch(`${this.config.apiUrl}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(this.config.authToken ? { "Authorization": `Bearer ${this.config.authToken}` } : {}),
        },
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "blob.GetAll",
          params: [height, [this.config.namespace]],
        }),
        signal: AbortSignal.timeout(15_000),
      });

      const result = await response.json() as { result?: any[]; error?: any };
      if (result.error || !result.result) return { exists: false };

      return {
        exists: result.result.length > 0,
        blobs: result.result,
      };
    } catch {
      return { exists: false };
    }
  }

  private async getCommitment(height: number): Promise<string> {
    try {
      const response = await fetch(`${this.config.apiUrl}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(this.config.authToken ? { "Authorization": `Bearer ${this.config.authToken}` } : {}),
        },
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "blob.GetAll",
          params: [height, [this.config.namespace]],
        }),
        signal: AbortSignal.timeout(10_000),
      });
      const result = await response.json() as { result?: Array<{ commitment: string }> };
      return result.result?.[0]?.commitment ?? "";
    } catch {
      return "";
    }
  }

  /** Build an audit blob from chain data */
  buildBlob(opts: {
    orgId:      string;
    blockIndex: number;
    merkleRoot: string;
    eventCount: number;
    events?:    Array<{ id: string; type: string; ts: number; severity: string; payloadHash: string }>;
  }): AuditBlob {
    return {
      version: "sovereign-v3",
      orgId: opts.orgId,
      blockIndex: opts.blockIndex,
      merkleRoot: opts.merkleRoot,
      eventCount: opts.eventCount,
      events: this.config.fullBlobs ? opts.events : undefined,
      timestamp: Date.now(),
    };
  }

  stats() {
    return {
      enabled: true,
      submits: this.submitCount,
      totalBytes: this.totalBytesSubmitted,
      namespace: this.config.namespace,
      fullBlobs: this.config.fullBlobs,
    };
  }
}

// Helper
async function sha256Hex(data: string): Promise<string> {
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data))
  );
  return Array.from(hash).map(b => b.toString(16).padStart(2, "0")).join("");
}
