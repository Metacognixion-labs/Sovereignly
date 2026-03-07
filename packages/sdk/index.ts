/**
 * @metacognixion/chain-sdk
 *
 * The SovereignChain Protocol SDK.
 * Embed cryptographically-verifiable compliance into ANY application.
 * Zero infrastructure migration required.
 *
 * Install: npm install @metacognixion/chain-sdk
 *
 * Works in: Node.js, Bun, Deno, Cloudflare Workers, Next.js, any TypeScript/JS runtime
 *
 * ---
 *
 * This is the Stripe analogy:
 *   You don't switch banks to use Stripe.
 *   You don't switch clouds to use SovereignChain.
 *   You install the SDK. Events start flowing. SOC2 evidence is live.
 *
 * ---
 *
 * PRICING MODEL (Cloud-hosted SovereignChain endpoint):
 *   Free:       10,000 events/mo  -- OSS projects
 *   Starter:    $49/mo  -- 1M events/mo,  SOC2 report
 *   Growth:     $149/mo -- 10M events/mo, SOC2 + ISO27001
 *   Enterprise: Custom  -- Unlimited, dedicated chain, omnichain attestation
 *
 * Self-hosted: Run your own SovereignChain node. This SDK works with both.
 */

// --- Event types (extensible) -------------------------------------------------

export type StandardEventType =
  // Identity & access
  | "AUTH_SUCCESS" | "AUTH_FAILURE" | "MFA_CHALLENGE" | "SESSION_START" | "SESSION_END"
  | "PASSWORD_RESET" | "ACCOUNT_LOCKED" | "PERMISSION_CHANGE" | "ROLE_CHANGE"
  // Data operations
  | "DATA_CREATE" | "DATA_READ" | "DATA_UPDATE" | "DATA_DELETE" | "DATA_EXPORT"
  | "DATA_IMPORT" | "BULK_OPERATION" | "PII_ACCESS" | "SENSITIVE_ACCESS"
  // System changes
  | "CONFIG_CHANGE" | "SECRET_ROTATION" | "DEPLOY" | "ROLLBACK" | "FEATURE_FLAG"
  | "INFRASTRUCTURE_CHANGE" | "CERTIFICATE_ROTATION"
  // Security events
  | "ANOMALY" | "RATE_LIMIT_HIT" | "VULNERABILITY_SCAN" | "INTRUSION_DETECTED"
  | "SECRET_EXPOSED" | "UNAUTHORIZED_ACCESS"
  // Compliance
  | "AUDIT_LOG_ACCESS" | "COMPLIANCE_REPORT_GENERATED" | "GDPR_REQUEST"
  | "DATA_RETENTION_APPLIED" | "CONSENT_CHANGE"
  // Custom
  | (string & {});

export type EventSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ChainEvent {
  type:      StandardEventType;
  payload:   Record<string, unknown>;
  severity?: EventSeverity;
  actor?:    string;    // user ID or service identifier
  resource?: string;    // affected resource
  ip?:       string;
  tags?:     string[];
}

export interface ChainEventResult {
  eventId:   string;
  blockHint: number;    // approximate block number (exact once sealed)
  timestamp: number;
  chainTip?: string;    // current chain tip hash
}

export interface ComplianceReport {
  orgId:       string;
  type:        "SOC2" | "ISO27001" | "HIPAA" | "GDPR" | "NIST";
  period:      { from: string; to: string };
  score:       number;    // 0-100
  controls:    ControlStatus[];
  chainProof:  ChainProof;
  generatedAt: string;
}

export interface ControlStatus {
  id:          string;    // e.g. "CC6.1"
  name:        string;
  status:      "implemented" | "partial" | "missing";
  evidence:    EvidenceItem[];
}

export interface EvidenceItem {
  type:       "event_count" | "merkle_proof" | "anchor_tx" | "config";
  label:      string;
  value:      string | number;
  verifiable: boolean;
  proofUrl?:  string;    // etherscan / meridian explorer link
}

export interface ChainProof {
  chainTip:        string;
  blockCount:      number;
  eventCount:      number;
  meridianAnchor?: string;    // tx hash
  omnichainAttestation?: string;  // EAS/Base attestation UID -- external verifiability
  ethereumAnchor?: string;         // @deprecated -- use omnichainAttestation
  anchoredAt?:     string;
  verifyUrl?:      string;
}

// --- SDK Configuration ---------------------------------------------------------

export interface SovereignChainConfig {
  /** Your org ID from the SovereignCloud dashboard */
  orgId: string;

  /** API key (sk_live_xxx or sk_test_xxx) */
  apiKey: string;

  /**
   * Chain endpoint.
   * Cloud: "https://chain.metacognixion.com" (default)
   * Self-hosted: "http://localhost:8787"
   */
  endpoint?: string;

  /**
   * Batch events before sending (reduces latency impact on hot paths).
   * default: 50 events OR 5 seconds, whichever first
   */
  batchSize?: number;
  batchTimeoutMs?: number;

  /**
   * If true, emit() is fire-and-forget (non-blocking).
   * Failures are queued and retried. default: true
   */
  async?: boolean;

  /**
   * Override fetch implementation (for testing or edge runtimes).
   */
  fetch?: typeof globalThis.fetch;

  /** Called on unrecoverable errors. default: console.error */
  onError?: (err: Error) => void;
}

// --- SDK Client ---------------------------------------------------------------

export class SovereignChain {
  private cfg:     Required<SovereignChainConfig>;
  private queue:   ChainEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private flushing = false;
  private closed   = false;

  constructor(config: SovereignChainConfig) {
    this.cfg = {
      endpoint:       "https://chain.metacognixion.com",
      batchSize:      50,
      batchTimeoutMs: 5000,
      async:          true,
      fetch:          globalThis.fetch,
      onError:        (e) => console.error("[SovereignChain]", e.message),
      ...config,
    };
  }

  // -- Primary API ---------------------------------------------------------------

  /**
   * Record an audit event on SovereignChain.
   *
   * @example
   * await chain.emit('AUTH_SUCCESS', { userId, ip, method: 'passkey' });
   * await chain.emit('DATA_EXPORT', { userId, table: 'users', rows: 1500 });
   * chain.emit('CONFIG_CHANGE', { key: 'rate_limit', from: 100, to: 200 }); // fire-and-forget
   */
  emit(
    type:     StandardEventType,
    payload:  Record<string, unknown> = {},
    severity: EventSeverity = "LOW",
    opts?: { actor?: string; resource?: string; ip?: string; tags?: string[]; sync?: boolean }
  ): Promise<ChainEventResult> | void {
    const event: ChainEvent = { type, payload, severity, ...opts };

    if (this.cfg.async && !opts?.sync) {
      this.enqueue(event);
      return;
    }

    return this.sendImmediate([event]).then(r => r[0]);
  }

  /**
   * Emit multiple events atomically (same block).
   */
  async emitBatch(events: ChainEvent[]): Promise<ChainEventResult[]> {
    return this.sendImmediate(events);
  }

  /**
   * Generate a compliance report for a given standard and time period.
   *
   * @example
   * const report = await chain.complianceReport({
   *   type: 'SOC2',
   *   from: '2025-01-01',
   *   to:   '2025-12-31',
   * });
   */
  async complianceReport(opts: {
    type:    ComplianceReport["type"];
    from?:   string;    // ISO date
    to?:     string;    // ISO date
    proofs?: boolean;   // include Merkle proofs
  }): Promise<ComplianceReport> {
    const res = await this.request("/v1/compliance/report", {
      method: "POST",
      body: JSON.stringify({
        orgId:  this.cfg.orgId,
        type:   opts.type,
        from:   opts.from ?? new Date(Date.now() - 90 * 86400_000).toISOString(),
        to:     opts.to   ?? new Date().toISOString(),
        proofs: opts.proofs ?? false,
      }),
    });
    return res as ComplianceReport;
  }

  /**
   * Export raw audit events with optional Merkle proofs.
   */
  async exportEvents(opts: {
    from?:       string;
    to?:         string;
    types?:      StandardEventType[];
    severity?:   EventSeverity;
    limit?:      number;
    withProofs?: boolean;
  }) {
    return this.request("/v1/events/export", {
      method: "POST",
      body: JSON.stringify({ orgId: this.cfg.orgId, ...opts }),
    });
  }

  /**
   * Get current chain status and proof of integrity.
   */
  async status(): Promise<{
    blockCount:      number;
    eventCount:      number;
    chainTip:        string;
    meridianAnchor?: string;
    ethereumAnchor?: string;
    healthy:         boolean;
  }> {
    return this.request(`/v1/orgs/${this.cfg.orgId}/status`);
  }

  /**
   * Verify a specific event's inclusion in the chain.
   * Returns a Merkle proof that can be independently verified.
   */
  async verifyEvent(eventId: string): Promise<{
    exists:  boolean;
    proof?:  { root: string; path: string[]; index: number };
    anchor?: {
      chains:   string[];                    // e.g. ["eas-base", "solana"]
      receipts: Array<{
        chain:   string;
        txHash?: string;
        uid?:    string;
        url?:    string;
      }>;
      schemaUID?: string;
      verifyAt?:  string;                    // easscan.org URL
    };
  }> {
    return this.request(`/v1/events/${eventId}/proof?orgId=${this.cfg.orgId}`);
  }

  /**
   * Get anchor info -- schema UID, verification URLs, chains available for this org.
   */
  async anchorInfo(): Promise<{
    schema:  string;
    uid:     string;
    viewers: string[];
    chains:  Record<string, { desc: string; url: string }>;
  }> {
    return this.request(`/chain/anchor/schema`);
  }

  // -- Internal batch management ------------------------------------------------

  private enqueue(event: ChainEvent): void {
    if (this.closed) {
      this.cfg.onError(new Error("Chain SDK closed -- event dropped"));
      return;
    }

    this.queue.push(event);

    if (this.queue.length >= this.cfg.batchSize) {
      this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.cfg.batchTimeoutMs);
    }
  }

  private async flush(): Promise<void> {
    if (this.flushing || this.queue.length === 0) return;
    if (this.flushTimer) { clearTimeout(this.flushTimer); this.flushTimer = null; }

    const batch = this.queue.splice(0, this.cfg.batchSize);
    this.flushing = true;

    try {
      await this.sendImmediate(batch);
    } catch (err: any) {
      // Re-queue on failure (max 3 retries, then drop with onError)
      if ((batch[0] as any).__retries < 3) {
        batch.forEach(e => { (e as any).__retries = ((e as any).__retries ?? 0) + 1; });
        this.queue.unshift(...batch);
      } else {
        this.cfg.onError(new Error(`Dropping ${batch.length} events after 3 retries: ${err.message}`));
      }
    } finally {
      this.flushing = false;
    }
  }

  private async sendImmediate(events: ChainEvent[]): Promise<ChainEventResult[]> {
    const res = await this.request("/v1/events", {
      method: "POST",
      body: JSON.stringify({ orgId: this.cfg.orgId, events }),
    });
    return (res as any).results ?? events.map((_: any, i: number) => ({
      eventId:   `${Date.now()}-${i}`,
      blockHint: 0,
      timestamp: Date.now(),
    }));
  }

  private async request(path: string, init?: RequestInit): Promise<unknown> {
    const url = `${this.cfg.endpoint}${path}`;
    const res = await this.cfg.fetch(url, {
      ...init,
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${this.cfg.apiKey}`,
        "X-Org-Id":      this.cfg.orgId,
        "X-SDK-Version": "3.0.1",
        ...(init?.headers ?? {}),
      },
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`SovereignChain API ${res.status}: ${body}`);
    }

    return res.json();
  }

  // -- Lifecycle -----------------------------------------------------------------

  /**
   * Flush pending events and shut down.
   * Call in process.on('beforeExit') or similar.
   */
  async close(): Promise<void> {
    this.closed = true;
    if (this.flushTimer) clearTimeout(this.flushTimer);
    if (this.queue.length > 0) await this.flush();
  }
}

// --- Framework integrations ---------------------------------------------------

/**
 * Express / Hono / Fastify middleware.
 * Automatically logs every HTTP request to SovereignChain.
 *
 * @example
 * app.use(sovereignMiddleware(chain, { logBodies: false }));
 */
export function sovereignMiddleware(
  chain: SovereignChain,
  opts: { logBodies?: boolean; skipPaths?: string[] } = {}
) {
  return async (req: any, res: any, next: any) => {
    const start = Date.now();
    const skip  = opts.skipPaths?.some(p => req.path?.startsWith(p));

    next?.();

    if (!skip) {
      chain.emit("DATA_READ", {
        method:   req.method,
        path:     req.path ?? req.url,
        status:   res.statusCode ?? 200,
        ms:       Date.now() - start,
        ip:       req.headers?.["x-real-ip"] ?? req.ip,
        ua:       req.headers?.["user-agent"],
      }, "LOW");
    }
  };
}

/**
 * Next.js API route wrapper.
 *
 * @example
 * export const GET = withChain(chain, async (req) => {
 *   return Response.json({ ok: true });
 * });
 */
export function withChain(
  chain:   SovereignChain,
  handler: (req: Request) => Promise<Response>
): (req: Request) => Promise<Response> {
  return async (req: Request) => {
    const start = Date.now();
    try {
      const res = await handler(req);
      chain.emit("DATA_READ", {
        method: req.method,
        url:    req.url,
        status: res.status,
        ms:     Date.now() - start,
      }, "LOW");
      return res;
    } catch (err: any) {
      chain.emit("ANOMALY", {
        method: req.method,
        url:    req.url,
        error:  err.message,
        ms:     Date.now() - start,
      }, "HIGH");
      throw err;
    }
  };
}

// --- Default export ------------------------------------------------------------

// --- Next.js API route wrapper ------------------------------------------------

/**
 * Wrap a Next.js API route handler with automatic chain logging.
 *
 * @example
 * // pages/api/users.ts  (Pages Router)
 * import { chain } from '../../lib/chain'
 * export default chain.withNextjs(async (req, res) => {
 *   res.json({ users: await getUsers() })
 * })
 *
 * @example
 * // app/api/users/route.ts  (App Router)
 * import { chain } from '../../lib/chain'
 * export const GET = chain.withNextjsApp(async (req) => {
 *   return Response.json({ users: await getUsers() })
 * })
 */
declare global {
  // Minimal Next.js types inline to avoid @types/node dependency
  interface NextApiRequest  { method?: string; url?: string; headers: Record<string, string | string[] | undefined>; }
  interface NextApiResponse { status(code: number): NextApiResponse; json(data: unknown): void; send(data: unknown): void; }
}

type NextHandler = (req: NextApiRequest, res: NextApiResponse) => Promise<void> | void;
type NextAppHandler = (req: Request, ctx?: unknown) => Promise<Response>;

SovereignChain.prototype.withNextjs = function(this: SovereignChain, handler: NextHandler): NextHandler {
  const chain = this;
  return async function(req: NextApiRequest, res: NextApiResponse) {
    const start = Date.now();
    let statusCode = 200;

    // Intercept res.status() to capture code
    const origStatus = res.status.bind(res);
    res.status = (code: number) => { statusCode = code; return origStatus(code); };

    try {
      await handler(req, res);
      chain.emit("DATA_READ", {
        method:   req.method ?? "GET",
        path:     req.url ?? "/",
        status:   statusCode,
        durationMs: Date.now() - start,
      }, "LOW");
    } catch (err: any) {
      chain.emit("ANOMALY", {
        method: req.method, path: req.url,
        error: err.message, stack: err.stack?.split("\n")[0],
      }, "HIGH");
      throw err;
    }
  };
};

SovereignChain.prototype.withNextjsApp = function(this: SovereignChain, handler: NextAppHandler): NextAppHandler {
  const chain = this;
  return async function(req: Request, ctx?: unknown): Promise<Response> {
    const start = Date.now();
    try {
      const res = await handler(req, ctx);
      chain.emit("DATA_READ", {
        method: req.method, path: new URL(req.url).pathname,
        status: res.status, durationMs: Date.now() - start,
      }, "LOW");
      return res;
    } catch (err: any) {
      chain.emit("ANOMALY", { method: req.method, error: err.message }, "HIGH");
      throw err;
    }
  };
};

// Augment the prototype interface
declare module "./index" {
  interface SovereignChain {
    withNextjs(handler: NextHandler): NextHandler;
    withNextjsApp(handler: NextAppHandler): NextAppHandler;
  }
}

export default SovereignChain;
