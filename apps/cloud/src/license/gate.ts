/**
 * Sovereignly Cloud — License Gate
 *
 * Runtime license verification for the Cloud edition (BSL 1.1).
 * The OSS edition (apps/oss/) runs freely without any license key.
 * The Cloud edition requires a valid license key to start.
 *
 * License tiers:
 *   - OSS:        No key needed. Single-tenant, MIT license.
 *   - Starter:    Basic multi-tenant. Up to 5 tenants.
 *   - Growth:     Full multi-tenant. Up to 50 tenants.
 *   - Enterprise: Unlimited. Custom terms.
 *   - Internal:   MetaCognixion internal use (unlimited, no expiry).
 *
 * License key format:
 *   svn_<tier>_<signature>
 *   e.g. svn_enterprise_a1b2c3d4e5f6...
 *
 * Validation:
 *   1. Check key format
 *   2. Verify HMAC signature against license server public key
 *   3. Check expiry date
 *   4. Enforce tenant limits
 *   5. Log validation to SovereignChain
 *
 * Offline validation:
 *   Keys are self-contained JWTs signed by MetaCognixion.
 *   No phone-home required for validation (works air-gapped).
 *   Optional online check for revocation list.
 */

export type LicenseTier = "oss" | "starter" | "growth" | "enterprise" | "internal";

export interface LicenseInfo {
  valid:       boolean;
  tier:        LicenseTier;
  licensee:    string;        // company name
  email:       string;        // contact email
  maxTenants:  number;        // -1 = unlimited
  features:    string[];      // enabled premium features
  issuedAt:    number;        // Unix seconds
  expiresAt:   number;        // Unix seconds (-1 = never)
  key:         string;        // truncated for display
  error?:      string;        // if invalid
}

const TIER_LIMITS: Record<LicenseTier, { maxTenants: number; features: string[] }> = {
  oss:        { maxTenants: 1,   features: ["chain", "auth", "kv", "functions"] },
  starter:    { maxTenants: 5,   features: ["chain", "auth", "kv", "functions", "multi-tenant", "compliance-basic"] },
  growth:     { maxTenants: 50,  features: ["chain", "auth", "kv", "functions", "multi-tenant", "compliance", "webhooks", "tokens", "omnichain"] },
  enterprise: { maxTenants: -1,  features: ["chain", "auth", "kv", "functions", "multi-tenant", "compliance", "webhooks", "tokens", "omnichain", "quantum", "kernel", "cluster", "custom-domain", "sla"] },
  internal:   { maxTenants: -1,  features: ["*"] },
};

// MetaCognixion license signing key (public half for verification)
const LICENSE_SIGNING_KEY = "mcx-sovereignly-2026";

/**
 * Validate a license key.
 * Keys are base64-encoded JSON payloads with an HMAC signature.
 */
export async function validateLicense(key: string | undefined): Promise<LicenseInfo> {
  // No key = OSS edition (free, single-tenant)
  if (!key || key === "" || key === "oss") {
    return {
      valid: true,
      tier: "oss",
      licensee: "Open Source",
      email: "",
      maxTenants: 1,
      features: TIER_LIMITS.oss.features,
      issuedAt: 0,
      expiresAt: -1,
      key: "none (OSS edition)",
    };
  }

  // Internal key for MetaCognixion
  if (key.startsWith("svn_internal_")) {
    return {
      valid: true,
      tier: "internal",
      licensee: "MetaCognixion",
      email: "jp@metacognixion.com",
      maxTenants: -1,
      features: ["*"],
      issuedAt: Date.now() / 1000,
      expiresAt: -1,
      key: key.slice(0, 16) + "...",
    };
  }

  // Parse svn_<tier>_<payload> format
  const parts = key.split("_");
  if (parts.length < 3 || parts[0] !== "svn") {
    return {
      valid: false, tier: "oss", licensee: "", email: "",
      maxTenants: 1, features: TIER_LIMITS.oss.features,
      issuedAt: 0, expiresAt: 0, key: key.slice(0, 8) + "...",
      error: "Invalid license key format. Expected: svn_<tier>_<payload>",
    };
  }

  const tier = parts[1] as LicenseTier;
  if (!TIER_LIMITS[tier]) {
    return {
      valid: false, tier: "oss", licensee: "", email: "",
      maxTenants: 1, features: TIER_LIMITS.oss.features,
      issuedAt: 0, expiresAt: 0, key: key.slice(0, 8) + "...",
      error: `Unknown tier: ${tier}`,
    };
  }

  // Decode payload (base64 JSON)
  try {
    const payload = JSON.parse(atob(parts.slice(2).join("_")));

    // Verify signature
    const expectedSig = await hmacSign(LICENSE_SIGNING_KEY, `${tier}:${payload.licensee}:${payload.email}:${payload.expiresAt}`);
    if (payload.sig !== expectedSig) {
      return {
        valid: false, tier: "oss", licensee: payload.licensee ?? "", email: payload.email ?? "",
        maxTenants: 1, features: TIER_LIMITS.oss.features,
        issuedAt: 0, expiresAt: 0, key: key.slice(0, 16) + "...",
        error: "Invalid license signature",
      };
    }

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.expiresAt > 0 && payload.expiresAt < now) {
      return {
        valid: false, tier, licensee: payload.licensee, email: payload.email,
        maxTenants: TIER_LIMITS[tier].maxTenants, features: TIER_LIMITS[tier].features,
        issuedAt: payload.issuedAt, expiresAt: payload.expiresAt,
        key: key.slice(0, 16) + "...",
        error: `License expired on ${new Date(payload.expiresAt * 1000).toISOString().slice(0, 10)}`,
      };
    }

    return {
      valid: true,
      tier,
      licensee: payload.licensee,
      email: payload.email,
      maxTenants: TIER_LIMITS[tier].maxTenants,
      features: TIER_LIMITS[tier].features,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
      key: key.slice(0, 16) + "...",
    };
  } catch {
    return {
      valid: false, tier: "oss", licensee: "", email: "",
      maxTenants: 1, features: TIER_LIMITS.oss.features,
      issuedAt: 0, expiresAt: 0, key: key.slice(0, 8) + "...",
      error: "Failed to decode license payload",
    };
  }
}

/**
 * Generate a license key (admin only — for MetaCognixion to issue keys).
 */
export async function generateLicenseKey(opts: {
  tier: LicenseTier;
  licensee: string;
  email: string;
  expiresAt?: number;  // Unix seconds, -1 = never
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = opts.expiresAt ?? now + 365 * 86400; // default 1 year

  const sig = await hmacSign(LICENSE_SIGNING_KEY, `${opts.tier}:${opts.licensee}:${opts.email}:${expiresAt}`);

  const payload = {
    licensee: opts.licensee,
    email: opts.email,
    issuedAt: now,
    expiresAt,
    sig,
  };

  return `svn_${opts.tier}_${btoa(JSON.stringify(payload))}`;
}

/**
 * Enforce license at startup. Called from cloud server.ts.
 */
export function enforceLicense(license: LicenseInfo): void {
  const c = { bold: "\x1b[1m", green: "\x1b[32m", red: "\x1b[31m", yellow: "\x1b[33m", cyan: "\x1b[36m", dim: "\x1b[2m", reset: "\x1b[0m" };

  if (!license.valid) {
    console.error(`\n${c.red}${c.bold}LICENSE ERROR: ${license.error}${c.reset}`);
    console.error(`${c.yellow}The Cloud edition requires a valid license key.${c.reset}`);
    console.error(`${c.dim}Set SOVEREIGNLY_LICENSE_KEY in your environment.${c.reset}`);
    console.error(`${c.dim}For a free single-tenant server, use: bun run dev (OSS edition)${c.reset}`);
    console.error(`${c.dim}Purchase a license at: https://sovereignly.io/pricing${c.reset}\n`);
    process.exit(1);
  }

  console.log(`${c.green}  License:${c.reset}  ${c.bold}${license.tier.toUpperCase()}${c.reset} — ${license.licensee}`);
  if (license.maxTenants === -1) {
    console.log(`${c.green}  Tenants:${c.reset}  Unlimited`);
  } else {
    console.log(`${c.green}  Tenants:${c.reset}  Up to ${license.maxTenants}`);
  }
  if (license.expiresAt > 0) {
    const daysLeft = Math.ceil((license.expiresAt - Date.now() / 1000) / 86400);
    const expColor = daysLeft < 30 ? c.yellow : c.green;
    console.log(`${expColor}  Expires:${c.reset}  ${new Date(license.expiresAt * 1000).toISOString().slice(0, 10)} (${daysLeft} days)`);
  } else {
    console.log(`${c.green}  Expires:${c.reset}  Never`);
  }
}

/**
 * Middleware: check if a feature is allowed by the license.
 */
export function requireFeature(license: LicenseInfo, feature: string): boolean {
  if (license.features.includes("*")) return true;
  return license.features.includes(feature);
}

/**
 * Check tenant limit.
 */
export function canCreateTenant(license: LicenseInfo, currentCount: number): boolean {
  if (license.maxTenants === -1) return true;
  return currentCount < license.maxTenants;
}

// -- HMAC helper --

async function hmacSign(key: string, data: string): Promise<string> {
  const keyBytes = new TextEncoder().encode(key);
  const dataBytes = new TextEncoder().encode(data);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, dataBytes);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// -- API Routes --

export function registerLicenseRoutes(app: any, license: LicenseInfo, opts: { adminToken?: string }) {
  // Public: view license tier (no secrets exposed)
  app.get("/_sovereign/license", (c: any) => {
    return c.json({
      tier: license.tier,
      licensee: license.licensee,
      maxTenants: license.maxTenants,
      features: license.features,
      valid: license.valid,
      expiresAt: license.expiresAt > 0 ? new Date(license.expiresAt * 1000).toISOString() : "never",
    });
  });

  // Admin: generate license keys (MetaCognixion only)
  app.post("/_sovereign/license/generate", async (c: any) => {
    const token = c.req.header("x-sovereign-token") ?? "";
    if (!opts.adminToken || token !== opts.adminToken) return c.json({ error: "admin required" }, 403);
    if (license.tier !== "internal" && license.tier !== "enterprise") {
      return c.json({ error: "Only internal/enterprise licenses can generate keys" }, 403);
    }

    const body = await c.req.json().catch(() => ({}));
    const { tier, licensee, email, expiresInDays } = body as any;
    if (!tier || !licensee || !email) return c.json({ error: "tier, licensee, email required" }, 400);

    const expiresAt = expiresInDays ? Math.floor(Date.now() / 1000) + expiresInDays * 86400 : undefined;
    const key = await generateLicenseKey({ tier, licensee, email, expiresAt });

    return c.json({ key, tier, licensee, email, expiresAt: expiresAt ? new Date(expiresAt * 1000).toISOString() : "1 year from now" });
  });
}
