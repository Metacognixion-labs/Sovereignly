/**
 * Sovereignly v4.0 — Intent Guard
 *
 * AI/LLM prompt injection prevention and intent validation.
 * Ensures that natural language commands are safe before execution.
 *
 * Protections:
 *   1. Confidence gating     — reject low-confidence intents
 *   2. Destructive action protection — require high confidence for dangerous ops
 *   3. Rate limiting         — max intent executions per user per minute
 *   4. Param schema validation — type-check extracted parameters
 *   5. Canary token detection — detect prompt extraction attempts
 *   6. Structured output enforcement — validate LLM outputs against schemas
 */

import { inputShield } from "./input-shield.ts";

// ── Types ───────────────────────────────────────────────────────────────────

export interface IntentValidation {
  allowed:    boolean;
  reason?:    string;
  sanitized?: Record<string, string>;
}

export interface IntentGuardConfig {
  minConfidence:          number;  // Minimum confidence to execute (default: 0.7)
  destructiveConfidence:  number;  // Required confidence for destructive actions (default: 0.95)
  maxIntentsPerMinute:    number;  // Rate limit per user (default: 10)
}

interface RateEntry {
  count: number;
  windowStart: number;
}

// ── Destructive Actions ─────────────────────────────────────────────────────

const DESTRUCTIVE_ACTIONS = new Set([
  "teardown",
  "delete",
  "remove",
  "decommission",
  "drop",
  "reset",
  "purge",
  "wipe",
]);

// ── Param Schemas ───────────────────────────────────────────────────────────

type ParamType = "string" | "number" | "region" | "identifier";

const PARAM_SCHEMAS: Record<string, Record<string, ParamType>> = {
  deploy_tenant: { tenantName: "identifier", region: "region" },
  migrate:       { target: "identifier", toRegion: "region" },
  scale:         { target: "identifier", size: "string" },
  audit:         { target: "identifier", standard: "string" },
  status:        { target: "string" },
  teardown:      { target: "identifier" },
};

// Valid identifier: alphanumeric, hyphens, underscores, dots. No spaces or specials.
const IDENTIFIER_RE = /^[a-zA-Z0-9_\-\.]{1,128}$/;
// Valid region: known short codes or natural language words
const REGION_RE = /^[a-zA-Z0-9\-\s]{1,64}$/;

function validateParam(value: string, type: ParamType): boolean {
  switch (type) {
    case "identifier": return IDENTIFIER_RE.test(value);
    case "region":     return REGION_RE.test(value);
    case "number":     return /^\d+(\.\d+)?$/.test(value);
    case "string":     return value.length <= 512;
  }
}

// ── Prompt Injection Patterns ───────────────────────────────────────────────

const PROMPT_INJECTION_PATTERNS = [
  // Direct instruction override attempts
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?above/i,
  /disregard\s+(all\s+)?previous/i,
  /forget\s+(everything|all|your)\s+(previous|prior|above)/i,

  // System prompt extraction
  /what\s+(is|are)\s+your\s+(system\s+)?instructions/i,
  /show\s+me\s+your\s+(system\s+)?prompt/i,
  /repeat\s+(your\s+)?instructions/i,
  /print\s+your\s+(system\s+)?prompt/i,

  // Role play exploitation
  /you\s+are\s+now\s+(?:a\s+)?(?:different|new|unrestricted)/i,
  /pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|new)/i,
  /act\s+as\s+(?:a\s+)?(?:unrestricted|jailbroken|DAN)/i,

  // Token smuggling
  /\[SYSTEM\]/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /<\|im_start\|>/i,
  /\[\/INST\]/i,

  // Encoding evasion
  /base64\s*[:=]\s*[A-Za-z0-9+/]{20,}/i,
  /hex\s*[:=]\s*[0-9a-f]{20,}/i,
];

// ── IntentGuard ─────────────────────────────────────────────────────────────

export class IntentGuard {
  private readonly config: IntentGuardConfig;
  private readonly rateLimits = new Map<string, RateEntry>();
  private readonly canaries: string[] = [];
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor(config?: Partial<IntentGuardConfig>) {
    this.config = {
      minConfidence:         config?.minConfidence ?? 0.7,
      destructiveConfidence: config?.destructiveConfidence ?? 0.95,
      maxIntentsPerMinute:   config?.maxIntentsPerMinute ?? 10,
    };

    // Generate canary tokens (unique per instance)
    for (let i = 0; i < 3; i++) {
      this.canaries.push(`SVRN_CANARY_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`);
    }

    // Cleanup stale rate limit entries every 5 minutes
    this.cleanupTimer = setInterval(() => this.cleanupRateLimits(), 5 * 60 * 1000);
  }

  /**
   * Validate an intent before execution.
   * Checks confidence, rate limits, input safety, and param schemas.
   */
  validate(
    action:     string,
    confidence: number,
    entities:   Record<string, string>,
    userId:     string,
    rawInput:   string,
  ): IntentValidation {
    // 1. Rate limit check
    if (!this.checkRateLimit(userId)) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: max ${this.config.maxIntentsPerMinute} intents per minute`,
      };
    }

    // 2. Prompt injection scan on raw input
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
      if (pattern.test(rawInput)) {
        return {
          allowed: false,
          reason: `Prompt injection detected: ${pattern.source.slice(0, 40)}...`,
        };
      }
    }

    // 3. Input shield scan on raw input
    const inputScan = inputShield.detectInjection(rawInput);
    if (!inputScan.safe) {
      return {
        allowed: false,
        reason: `Input injection detected: ${inputScan.threats.map(t => t.type).join(", ")}`,
      };
    }

    // 4. Confidence threshold
    if (confidence < this.config.minConfidence) {
      return {
        allowed: false,
        reason: `Confidence too low: ${confidence.toFixed(2)} < ${this.config.minConfidence}`,
      };
    }

    // 5. Destructive action requires higher confidence
    if (DESTRUCTIVE_ACTIONS.has(action) && confidence < this.config.destructiveConfidence) {
      return {
        allowed: false,
        reason: `Destructive action '${action}' requires confidence >= ${this.config.destructiveConfidence}, got ${confidence.toFixed(2)}`,
      };
    }

    // 6. Param schema validation
    const schema = PARAM_SCHEMAS[action];
    const sanitized: Record<string, string> = {};

    if (schema) {
      for (const [param, type] of Object.entries(schema)) {
        const value = entities[param];
        if (value != null && value !== "") {
          // Strip Unicode smuggling first
          const clean = inputShield.stripUnicodeSmugglers(value);
          if (!validateParam(clean, type)) {
            return {
              allowed: false,
              reason: `Invalid parameter '${param}': failed ${type} validation`,
            };
          }
          sanitized[param] = clean;
        }
      }
    }

    // Record the rate limit hit
    this.recordRateLimit(userId);

    return { allowed: true, sanitized: Object.keys(sanitized).length > 0 ? sanitized : undefined };
  }

  /**
   * Check if text contains canary tokens (prompt extraction detection).
   */
  checkCanaries(text: string): boolean {
    return this.canaries.some(c => text.includes(c));
  }

  /** Get canary tokens (to embed in system prompts) */
  getCanaries(): string[] {
    return [...this.canaries];
  }

  /**
   * Validate structured LLM output against expected shape.
   * Rejects free-form text when structured output is expected.
   */
  validateStructuredOutput<T>(
    output: unknown,
    validator: (val: unknown) => val is T,
  ): { valid: boolean; value?: T; reason?: string } {
    if (output == null) {
      return { valid: false, reason: "Output is null/undefined" };
    }

    if (typeof output === "string") {
      // Try to parse as JSON
      try {
        const parsed = JSON.parse(output);
        if (validator(parsed)) {
          return { valid: true, value: parsed };
        }
        return { valid: false, reason: "Parsed JSON does not match expected schema" };
      } catch {
        return { valid: false, reason: "Expected structured JSON output, got free-form text" };
      }
    }

    if (validator(output)) {
      return { valid: true, value: output };
    }

    return { valid: false, reason: "Output does not match expected schema" };
  }

  // ── Rate Limiting ─────────────────────────────────────────────────────

  private checkRateLimit(userId: string): boolean {
    const now = Date.now();
    const entry = this.rateLimits.get(userId);

    if (!entry || now - entry.windowStart > 60_000) {
      return true;  // New window or expired
    }

    return entry.count < this.config.maxIntentsPerMinute;
  }

  private recordRateLimit(userId: string): void {
    const now = Date.now();
    const entry = this.rateLimits.get(userId);

    if (!entry || now - entry.windowStart > 60_000) {
      this.rateLimits.set(userId, { count: 1, windowStart: now });
    } else {
      entry.count++;
    }
  }

  private cleanupRateLimits(): void {
    const now = Date.now();
    for (const [key, entry] of this.rateLimits) {
      if (now - entry.windowStart > 120_000) {
        this.rateLimits.delete(key);
      }
    }
  }

  close(): void {
    clearInterval(this.cleanupTimer);
  }
}
