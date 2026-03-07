/**
 * Sovereignly v4.0.0  Webhook Delivery
 *
 * Pushes events to tenant-registered webhook URLs.
 * Critical for SOC2 evidence trails  auditors need to receive
 * anchor completions, security anomalies, and compliance events
 * in their own systems.
 *
 * Design:
 *   - Webhooks stored in tenant KV: webhook:{id}  { url, events, secret }
 *   - Delivery is fire-and-forget with retry queue (3 attempts, exponential backoff)
 *   - Payloads signed with HMAC-SHA256 (tenant can verify authenticity)
 *   - Failed deliveries logged to tenant chain as ANOMALY
 *
 * Webhook payload format:
 *   {
 *     event:     "anchor_completed" | "anomaly_detected" | "compliance_report" | "tenant_event",
 *     timestamp: 1709654400000,
 *     tenantId:  "org_abc123",
 *     data:      { ... event-specific payload ... },
 *     signature: "sha256=<hmac of body with webhook secret>"
 *   }
 */

import { hmac256 } from "../../../oss/src/security/crypto.ts";
import type { SovereignKV } from "../../../oss/src/kv/index.ts";
import type { SovereignChain } from "../../../oss/src/security/chain.ts";

//  Types 

export interface WebhookConfig {
  id:     string;         // wh_<uuid>
  url:    string;         // https://customer-system.com/webhooks/sovereign
  events: WebhookEvent[]; // which events to send
  secret: string;         // HMAC signing secret (customer-generated)
  active: boolean;
  createdAt: number;
}

export type WebhookEvent =
  | "anchor_completed"     // omnichain attestation succeeded
  | "anchor_failed"        // omnichain attestation error
  | "anomaly_detected"     // brute-force, recon, etc
  | "compliance_report"    // SOC2/ISO report generated
  | "tenant_event"         // any tenant chain event (high-volume)
  | "plan_changed"         // upgrade/downgrade
  | "*";                   // all events

export interface WebhookPayload {
  event:     WebhookEvent;
  timestamp: number;
  tenantId:  string;
  data:      Record<string, unknown>;
}

interface DeliveryResult {
  webhookId: string;
  url:       string;
  status:    number | "error";
  durationMs: number;
  attempt:   number;
}

//  Retry queue 

interface RetryItem {
  webhook: WebhookConfig;
  payload: WebhookPayload;
  attempt: number;
  nextRetryAt: number;
}

//  WebhookManager 

export class WebhookManager {
  private retryQueue: RetryItem[] = [];
  private retryTimer: ReturnType<typeof setInterval> | null = null;
  private deliveryCount = 0;
  private failureCount = 0;

  constructor(
    private chain?: SovereignChain,
  ) {
    // Process retry queue every 30 seconds
    this.retryTimer = setInterval(() => this.processRetries(), 30_000);
  }

  //  CRUD (webhooks stored in tenant KV) 

  async register(kv: SovereignKV, config: Omit<WebhookConfig, "id" | "createdAt">): Promise<WebhookConfig> {
    const id = `wh_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const webhook: WebhookConfig = {
      ...config,
      id,
      createdAt: Date.now(),
    };
    await kv.set(`webhook:${id}`, JSON.stringify(webhook));
    return webhook;
  }

  async list(kv: SovereignKV): Promise<WebhookConfig[]> {
    const keys = await kv.list("webhook:");
    const results: WebhookConfig[] = [];
    for (const key of keys) {
      const val = await kv.get(key);
      if (val) {
        try { results.push(JSON.parse(val)); } catch {}
      }
    }
    return results;
  }

  async get(kv: SovereignKV, id: string): Promise<WebhookConfig | null> {
    const val = await kv.get(`webhook:${id}`);
    if (!val) return null;
    try { return JSON.parse(val); } catch { return null; }
  }

  async delete(kv: SovereignKV, id: string): Promise<boolean> {
    await kv.delete(`webhook:${id}`);
    return true;
  }

  //  Dispatch 

  async dispatch(
    kv: SovereignKV,
    tenantId: string,
    event: WebhookEvent,
    data: Record<string, unknown>,
  ): Promise<DeliveryResult[]> {
    const webhooks = await this.list(kv);
    const matching = webhooks.filter(w =>
      w.active && (w.events.includes(event) || w.events.includes("*"))
    );

    if (matching.length === 0) return [];

    const payload: WebhookPayload = {
      event,
      timestamp: Date.now(),
      tenantId,
      data,
    };

    const results = await Promise.all(
      matching.map(w => this.deliver(w, payload, 1))
    );

    return results;
  }

  //  Single delivery 

  private async deliver(
    webhook: WebhookConfig,
    payload: WebhookPayload,
    attempt: number,
  ): Promise<DeliveryResult> {
    const body = JSON.stringify(payload);
    const signature = await hmac256(webhook.secret, body);
    const start = Date.now();

    try {
      const res = await fetch(webhook.url, {
        method: "POST",
        headers: {
          "Content-Type":         "application/json",
          "X-Sovereign-Event":    payload.event,
          "X-Sovereign-Signature": `sha256=${signature}`,
          "X-Sovereign-Timestamp": String(payload.timestamp),
          "X-Sovereign-Delivery":  crypto.randomUUID(),
          "User-Agent":           "Sovereignly/4.0.0",
        },
        body,
        signal: AbortSignal.timeout(10_000),
      });

      this.deliveryCount++;
      const durationMs = Date.now() - start;

      if (!res.ok && attempt < 3) {
        this.scheduleRetry(webhook, payload, attempt);
      }

      if (!res.ok) this.failureCount++;

      return {
        webhookId:  webhook.id,
        url:        webhook.url,
        status:     res.status,
        durationMs,
        attempt,
      };
    } catch (err: any) {
      this.failureCount++;
      const durationMs = Date.now() - start;

      if (attempt < 3) {
        this.scheduleRetry(webhook, payload, attempt);
      } else {
        // Log final failure to chain
        void this.chain?.emit("ANOMALY", {
          type:      "WEBHOOK_DELIVERY_FAILED",
          webhookId: webhook.id,
          url:       webhook.url,
          event:     payload.event,
          attempts:  attempt,
          error:     err.message,
        }, "MEDIUM");
      }

      return {
        webhookId:  webhook.id,
        url:        webhook.url,
        status:     "error",
        durationMs,
        attempt,
      };
    }
  }

  //  Retry logic 

  private scheduleRetry(webhook: WebhookConfig, payload: WebhookPayload, attempt: number) {
    // Exponential backoff: 10s, 60s, 300s
    const delays = [10_000, 60_000, 300_000];
    const delay = delays[attempt - 1] ?? 300_000;

    this.retryQueue.push({
      webhook,
      payload,
      attempt: attempt + 1,
      nextRetryAt: Date.now() + delay,
    });
  }

  private async processRetries() {
    const now = Date.now();
    const due = this.retryQueue.filter(r => now >= r.nextRetryAt);
    this.retryQueue = this.retryQueue.filter(r => now < r.nextRetryAt);

    for (const item of due) {
      await this.deliver(item.webhook, item.payload, item.attempt);
    }
  }

  //  Stats 

  stats() {
    return {
      delivered:    this.deliveryCount,
      failed:       this.failureCount,
      retryPending: this.retryQueue.length,
      successRate:  this.deliveryCount > 0
        ? ((this.deliveryCount - this.failureCount) / this.deliveryCount * 100).toFixed(1) + "%"
        : "N/A",
    };
  }

  close() {
    if (this.retryTimer) clearInterval(this.retryTimer);
  }
}
