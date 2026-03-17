/**
 * Sovereignly CAEP/SSF Receiver
 *
 * Implements OpenID Shared Signals Framework (SSF) 1.0 and
 * Continuous Access Evaluation Profile (CAEP) 1.0 receiver.
 *
 * Accepts security event tokens (SETs) from identity providers
 * (Okta, Google, Microsoft Entra ID, etc.) and takes automated action:
 *   - session-revoked → revoke all JWTs for the subject
 *   - credential-change → force re-authentication
 *   - token-claims-change → refresh claims on next request
 *   - assurance-level-change → adjust access level
 *
 * Endpoint: POST /_sovereign/auth/caep/events
 * Discovery: GET /.well-known/ssf-configuration
 *
 * References:
 *   https://openid.net/specs/openid-sharedsignals-framework-1_0.html
 *   https://openid.net/specs/openid-caep-1_0.html
 */

import type { Hono } from "hono";
import { revokeToken } from "../security/zero-trust.ts";
import type { SovereignChain } from "../security/chain.ts";
import { hmac256, timingSafeEqual } from "../security/crypto.ts";

// -- CAEP Event Types (from OpenID CAEP 1.0) --

export type CAEPEventType =
  | "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  | "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
  | "https://schemas.openid.net/secevent/caep/event-type/credential-change"
  | "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
  | "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
  | "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
  | "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

// -- SET (Security Event Token) structure --

interface SecurityEventToken {
  iss:    string;     // issuer (IdP)
  iat:    number;     // issued at (seconds)
  jti:    string;     // unique event ID
  aud:    string;     // audience (us)
  events: Record<string, {
    subject?: {
      format:     string;   // "email", "iss_sub", "opaque"
      email?:     string;
      iss?:       string;
      sub?:       string;
    };
    reason_admin?:  { en: string };
    reason_user?:   { en: string };
    initiating_entity?: string;
    event_timestamp?: number;
  }>;
}

// -- Transmitter Registry (known IdPs that send us signals) --

interface SSFTransmitter {
  id:           string;
  issuer:       string;     // IdP issuer URL
  sharedSecret: string;     // HMAC verification key
  active:       boolean;
  registeredAt: number;
}

// -- CAEP Receiver --

export class CAEPReceiver {
  private transmitters = new Map<string, SSFTransmitter>();
  private processedEvents = new Set<string>(); // dedup by jti
  private eventCount = 0;

  constructor(
    private chain: SovereignChain | null,
    private onSubjectRevoked?: (subject: string) => void,
  ) {}

  /** Register a trusted transmitter (IdP) */
  registerTransmitter(issuer: string, sharedSecret: string): string {
    const id = `ssf_${crypto.randomUUID().slice(0, 12)}`;
    this.transmitters.set(issuer, {
      id,
      issuer,
      sharedSecret,
      active: true,
      registeredAt: Date.now(),
    });
    return id;
  }

  /** Process an incoming SET (Security Event Token) */
  async processEvent(rawBody: string, signature?: string): Promise<{
    ok: boolean;
    processed: string[];
    errors: string[];
  }> {
    const processed: string[] = [];
    const errors: string[] = [];

    let set: SecurityEventToken;
    try {
      set = JSON.parse(rawBody);
    } catch {
      return { ok: false, processed, errors: ["invalid JSON"] };
    }

    // Validate issuer
    const transmitter = this.transmitters.get(set.iss);
    if (!transmitter || !transmitter.active) {
      return { ok: false, processed, errors: [`unknown issuer: ${set.iss}`] };
    }

    // Verify HMAC signature if provided
    if (signature) {
      const expected = await hmac256(transmitter.sharedSecret, rawBody);
      if (!timingSafeEqual(signature, expected)) {
        return { ok: false, processed, errors: ["invalid signature"] };
      }
    }

    // Dedup by jti
    if (this.processedEvents.has(set.jti)) {
      return { ok: true, processed: [], errors: ["duplicate event"] };
    }
    this.processedEvents.add(set.jti);
    // Bound dedup set
    if (this.processedEvents.size > 50_000) {
      const first = this.processedEvents.values().next().value;
      if (first) this.processedEvents.delete(first);
    }

    // Process each event in the SET
    for (const [eventType, eventData] of Object.entries(set.events)) {
      try {
        await this.handleEvent(eventType as CAEPEventType, eventData, set);
        processed.push(eventType);
        this.eventCount++;
      } catch (err: any) {
        errors.push(`${eventType}: ${err.message}`);
      }
    }

    return { ok: errors.length === 0, processed, errors };
  }

  private async handleEvent(
    type: CAEPEventType,
    data: SecurityEventToken["events"][string],
    set: SecurityEventToken
  ): Promise<void> {
    const subject = data.subject?.email ?? data.subject?.sub ?? "unknown";
    const reason = data.reason_admin?.en ?? data.reason_user?.en ?? "CAEP signal";

    switch (type) {
      case "https://schemas.openid.net/secevent/caep/event-type/session-revoked":
        // Revoke all active JWTs for this subject
        revokeToken(`caep:${subject}`); // revoke by subject pattern
        this.onSubjectRevoked?.(subject);
        void this.chain?.emit("SESSION_END", {
          event: "caep_session_revoked", subject, reason, issuer: set.iss,
        }, "HIGH");
        break;

      case "https://schemas.openid.net/secevent/caep/event-type/credential-change":
        // Force re-authentication
        revokeToken(`caep:${subject}`);
        void this.chain?.emit("AUTH_FAILURE", {
          event: "caep_credential_change", subject, reason, issuer: set.iss,
          initiator: data.initiating_entity ?? "unknown",
        }, "MEDIUM");
        break;

      case "https://schemas.openid.net/secevent/caep/event-type/token-claims-change":
        void this.chain?.emit("CONFIG_CHANGE", {
          event: "caep_claims_change", subject, reason, issuer: set.iss,
        }, "LOW");
        break;

      case "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change":
        void this.chain?.emit("CONFIG_CHANGE", {
          event: "caep_assurance_change", subject, reason, issuer: set.iss,
        }, "MEDIUM");
        break;

      case "https://schemas.openid.net/secevent/risc/event-type/account-disabled":
        revokeToken(`caep:${subject}`);
        this.onSubjectRevoked?.(subject);
        void this.chain?.emit("AUTH_FAILURE", {
          event: "risc_account_disabled", subject, reason, issuer: set.iss,
        }, "HIGH");
        break;

      case "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required":
        void this.chain?.emit("AUTH_FAILURE", {
          event: "risc_credential_change_required", subject, reason, issuer: set.iss,
        }, "HIGH");
        break;

      default:
        void this.chain?.emit("CONFIG_CHANGE", {
          event: "caep_unknown", type, subject, issuer: set.iss,
        }, "LOW");
    }
  }

  stats() {
    return {
      transmitters: this.transmitters.size,
      processedEvents: this.eventCount,
      deduplicatedSize: this.processedEvents.size,
    };
  }
}

// -- Route Registration --

export function registerCAEPRoutes(
  app: Hono,
  receiver: CAEPReceiver,
  opts: { adminToken?: string; appUrl: string }
) {
  // SSF Discovery endpoint (required by spec)
  app.get("/.well-known/ssf-configuration", (c) => {
    return c.json({
      issuer: opts.appUrl,
      jwks_uri: `${opts.appUrl}/.well-known/jwks.json`,
      delivery_methods_supported: ["https://schemas.openid.net/secevent/risc/delivery-method/push"],
      configuration_endpoint: `${opts.appUrl}/_sovereign/auth/caep/configure`,
      status_endpoint: `${opts.appUrl}/_sovereign/auth/caep/status`,
      add_subject_endpoint: `${opts.appUrl}/_sovereign/auth/caep/subjects`,
    });
  });

  // Receive CAEP/SSF events (push delivery)
  app.post("/_sovereign/auth/caep/events", async (c) => {
    const signature = c.req.header("x-ssf-signature") ?? c.req.header("x-hub-signature-256") ?? undefined;
    const rawBody = await c.req.text();

    const result = await receiver.processEvent(rawBody, signature);

    if (!result.ok) {
      return c.json({ error: "event processing failed", details: result.errors }, 400);
    }

    // SSF spec: return 202 Accepted
    return c.json({
      ok: true,
      processed: result.processed,
    }, 202);
  });

  // Stats
  app.get("/_sovereign/auth/caep/status", (c) => {
    return c.json(receiver.stats());
  });
}
