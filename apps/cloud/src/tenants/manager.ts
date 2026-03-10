/**
 * Sovereignly v3  TenantManager
 *
 * Per-tenant isolation. Every tenant gets:
 *   data/tenants/{tenantId}/chain.db      isolated audit chain
 *   data/tenants/{tenantId}/kv.db         isolated KV store
 *   data/tenants/{tenantId}/storage/      isolated file storage
 *   data/tenants/{tenantId}/passkeys.db   isolated credential store
 *   data/tenants/{tenantId}/users.db      isolated user records
 *
 * All event content encrypted with per-tenant AES-256-GCM key.
 * Server operators see encrypted blobs, not event payloads.
 *
 * Global:
 *   data/global/tenants.db    tenant registry (unencrypted metadata only)
 *   data/global/anchor.db     root-of-roots for Ethereum anchoring
 *
 * Ethereum anchor payload every 1000 global blocks:
 *   keccak256(merkle([tenant_A_tip, tenant_B_tip, ...]))
 *    proves all tenants' chain state at a point in time
 *    anyone can verify without trusting the operator
 */

import { Database }  from "bun:sqlite";
import { mkdir, rm } from "node:fs/promises";
import { join, existsSync } from "node:path";
import { encryptAES, decryptAES, sha256 } from "../../../oss/src/security/crypto.ts";
import { SovereignChain }   from "../../../oss/src/security/chain.ts";
import { OmnichainAnchor }  from "../../../oss/src/security/omnichain-anchor.ts";
import type { AnchorTier } from "../../../oss/src/security/omnichain-anchor.ts";
import { SovereignKV }      from "../../../oss/src/kv/index.ts";
import { PasskeyEngine }    from "../../../oss/src/auth/passkeys.ts";

//  Types 

export type TenantPlan = "free" | "starter" | "growth" | "enterprise";
export type TenantStatus = "active" | "suspended" | "pending" | "cancelled";

export interface Tenant {
  id:            string;    // org_xxxxxxxxxxxxxxxx
  name:          string;
  slug:          string;    // url-safe name
  plan:          TenantPlan;
  status:        TenantStatus;
  ownerId:       string;    // user ID of the account owner
  domain?:       string;    // custom domain
  // Billing
  stripeCustomerId?: string;
  stripeSubId?:      string;
  // Limits (derived from plan)
  limits: {
    eventsPerMonth: number;
    functionsMax:   number;
    storageGB:      number;
    kvKeysMax:      number;
    seatsMax:       number;
  };
  // Metadata
  createdAt: number;
  updatedAt: number;
}

export interface TenantContext {
  tenant:   Tenant;
  chain:    SovereignChain;
  kv:       SovereignKV;
  passkeys: PasskeyEngine;
  dataDir:  string;
}

//  Plan limits 

const PLAN_LIMITS: Record<TenantPlan, Tenant["limits"]> = {
  free: {
    eventsPerMonth: 10_000,
    functionsMax:   3,
    storageGB:      0.5,
    kvKeysMax:      1_000,
    seatsMax:       1,
  },
  starter: {
    eventsPerMonth: 1_000_000,
    functionsMax:   20,
    storageGB:      20,
    kvKeysMax:      100_000,
    seatsMax:       3,
  },
  growth: {
    eventsPerMonth: 10_000_000,
    functionsMax:   100,
    storageGB:      100,
    kvKeysMax:      1_000_000,
    seatsMax:       10,
  },
  enterprise: {
    eventsPerMonth: Infinity,
    functionsMax:   Infinity,
    storageGB:      Infinity,
    kvKeysMax:      Infinity,
    seatsMax:       Infinity,
  },
};

//  TenantManager 

export class TenantManager {
  private registry:  Database;
  private baseDir:   string;
  private nodeId:    string;
  private serverKey: string;          // master server secret for key derivation
  private contexts   = new Map<string, TenantContext>();
  private encKey:    string;           // derived from serverKey, stable
  private omniAnchor: OmnichainAnchor | null;

  constructor(opts: {
    dataDir:   string;
    nodeId:    string;
    serverKey: string;   // from SOVEREIGN_SERVER_KEY env  never changes
    omniAnchor?: OmnichainAnchor;
  }) {
    this.baseDir   = opts.dataDir;
    this.nodeId    = opts.nodeId;
    this.serverKey = opts.serverKey;
    this.encKey    = opts.serverKey;  // used for tenant key derivation
    this.omniAnchor = opts.omniAnchor ?? null;

    const globalDir = join(opts.dataDir, "global");
    // mkdir sync equivalent for constructor
    try { require("node:fs").mkdirSync(globalDir, { recursive: true }); } catch {}
    this.registry  = new Database(join(globalDir, "tenants.db"));
    this.initSchema();
  }

  private initSchema() {
    this.registry.run("PRAGMA journal_mode = WAL");
    this.registry.run(`
      CREATE TABLE IF NOT EXISTS tenants (
        id                  TEXT PRIMARY KEY,
        name                TEXT NOT NULL,
        slug                TEXT UNIQUE NOT NULL,
        plan                TEXT NOT NULL DEFAULT 'free',
        status              TEXT NOT NULL DEFAULT 'active',
        owner_id            TEXT NOT NULL,
        domain              TEXT,
        stripe_customer_id  TEXT,
        stripe_sub_id       TEXT,
        enc_key_hash        TEXT NOT NULL,  -- sha256 of derived tenant key (proof without exposing key)
        created_at          INTEGER NOT NULL,
        updated_at          INTEGER NOT NULL
      )
    `);
    this.registry.run("CREATE INDEX IF NOT EXISTS idx_tenants_slug    ON tenants(slug)");
    this.registry.run("CREATE INDEX IF NOT EXISTS idx_tenants_owner   ON tenants(owner_id)");
    this.registry.run("CREATE INDEX IF NOT EXISTS idx_tenants_stripe  ON tenants(stripe_customer_id)");
  }

  //  Tenant lifecycle 

  async provision(opts: {
    name:    string;
    ownerId: string;
    plan?:   TenantPlan;
    domain?: string;
  }): Promise<Tenant> {
    const id       = `org_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const slug     = opts.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 32)
                       + "-" + id.slice(-6);
    const plan     = opts.plan ?? "free";
    const now      = Date.now();
    const encKey   = await this.deriveTenantKey(id);
    const keyHash  = await sha256(encKey);

    // Create tenant directory structure
    const tenantDir = join(this.baseDir, "tenants", id);
    await mkdir(join(tenantDir, "storage"), { recursive: true });

    // Register in global registry
    this.registry.prepare(`
      INSERT INTO tenants
        (id, name, slug, plan, status, owner_id, domain, enc_key_hash, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
    `).run(id, opts.name, slug, plan, opts.ownerId, opts.domain ?? null, keyHash, now, now);

    const tenant: Tenant = {
      id, name: opts.name, slug, plan,
      status: "active", ownerId: opts.ownerId,
      domain: opts.domain, limits: PLAN_LIMITS[plan],
      createdAt: now, updatedAt: now,
    };

    // Boot the tenant context (initialize its databases)
    await this.bootTenant(tenant, encKey);

    // Emit provisioning event to tenant's own chain
    const ctx = this.contexts.get(id)!;
    await ctx.chain.emit("CONFIG_CHANGE", {
      event:   "tenant_provisioned",
      tenantId: id, plan, ownerId: opts.ownerId,
    }, "LOW");

    console.log(`[TenantManager]  Provisioned tenant ${id} (${opts.name}) on ${plan}`);
    return tenant;
  }

  async get(tenantId: string): Promise<TenantContext | null> {
    // Return cached context if already booted
    if (this.contexts.has(tenantId)) return this.contexts.get(tenantId)!;

    // Load from registry
    const row = this.registry.prepare(
      "SELECT * FROM tenants WHERE id = ? AND status != 'cancelled'"
    ).get(tenantId) as any;
    if (!row) return null;

    const tenant = this.rowToTenant(row);
    const encKey = await this.deriveTenantKey(tenantId);
    await this.bootTenant(tenant, encKey);

    return this.contexts.get(tenantId) ?? null;
  }

  async getBySlug(slug: string): Promise<TenantContext | null> {
    const row = this.registry.prepare(
      "SELECT * FROM tenants WHERE slug = ? AND status = 'active'"
    ).get(slug) as any;
    if (!row) return null;
    return this.get(row.id);
  }

  /** Look up tenant metadata by owner email */
  getTenantByOwner(ownerEmail: string): Tenant | null {
    const row = this.registry.prepare(
      "SELECT * FROM tenants WHERE owner_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1"
    ).get(ownerEmail) as any;
    if (!row) return null;
    return this.rowToTenant(row);
  }

  async suspend(tenantId: string, reason: string): Promise<void> {
    this.registry.prepare(
      "UPDATE tenants SET status = 'suspended', updated_at = ? WHERE id = ?"
    ).run(Date.now(), tenantId);

    const ctx = this.contexts.get(tenantId);
    if (ctx) {
      await ctx.chain.emit("CONFIG_CHANGE", { event: "tenant_suspended", reason }, "HIGH");
      await ctx.chain.flush();
      ctx.chain.close();
      this.contexts.delete(tenantId);
    }
  }

  async upgrade(tenantId: string, plan: TenantPlan, stripeData?: {
    customerId: string;
    subId:      string;
  }): Promise<Tenant> {
    const now = Date.now();
    this.registry.prepare(`
      UPDATE tenants SET
        plan = ?, stripe_customer_id = ?, stripe_sub_id = ?, updated_at = ?
      WHERE id = ?
    `).run(
      plan,
      stripeData?.customerId ?? null,
      stripeData?.subId ?? null,
      now, tenantId
    );

    const ctx = await this.get(tenantId);
    if (ctx) {
      await ctx.chain.emit("CONFIG_CHANGE", {
        event: "plan_upgraded", plan, tenantId,
      }, "LOW");
    }

    return this.getTenantMeta(tenantId)!;
  }

  //  Boot / teardown 

  private async bootTenant(tenant: Tenant, encKey: string): Promise<void> {
    const tenantDir = join(this.baseDir, "tenants", tenant.id);
    await mkdir(join(tenantDir, "storage"), { recursive: true });

    // Per-tenant anchor: clone the platform omniAnchor config, override tier with tenant's plan
    // TenantPlan and AnchorTier use identical string values: free/starter/growth/enterprise
    const tenantAnchor = this.omniAnchor
      ? OmnichainAnchor.fromEnvWithTier(tenant.plan as AnchorTier)
      : undefined;

    const chain = new SovereignChain({
      dataDir:      tenantDir,
      nodeId:       `${this.nodeId}:${tenant.id}`,
      encKey,
      omniAnchor:   tenantAnchor,
      anchorOrgId:  tenant.id,
      anchorInterval: 100,           // anchor per-tenant chain every 100 blocks
    });
    await chain.init();

    const kv = new SovereignKV({
      dataDir: tenantDir,
      encKey,
    });
    await kv.init();

    const passkeys = new PasskeyEngine({
      dataDir:  tenantDir,
      rpId:     tenant.domain ?? "app.sovereignly.io",
      rpName:   tenant.name,
      origin:   tenant.domain ? `https://${tenant.domain}` : "https://app.sovereignly.io",
    });

    this.contexts.set(tenant.id, {
      tenant, chain, kv, passkeys, dataDir: tenantDir,
    });
  }

  //  Aggregate root for omnichain anchoring 

  /**
   * Build the root-of-roots: Merkle tree of all active tenant chain tips.
   * This is what gets attested omnichain (EAS/Base + Arbitrum + Solana) every GLOBAL_ANCHOR_INTERVAL blocks.
   * Proves the state of ALL tenants at a single point in time.
   */
  async buildGlobalRoot(): Promise<{
    root:       string;
    tenantTips: Array<{ tenantId: string; tip: string; blockCount: number }>;
    timestamp:  number;
  }> {
    const tenantTips: Array<{ tenantId: string; tip: string; blockCount: number }> = [];

    for (const [tenantId, ctx] of this.contexts) {
      const stats = ctx.chain.getStats();
      if (stats.tip) {
        tenantTips.push({
          tenantId,
          tip:        stats.tip.blockHash,
          blockCount: stats.blocks,
        });
      }
    }

    // Build Merkle root over all tenant tips
    const { MerkleTree } = await import("../security/crypto.ts");
    const leaves = tenantTips.map(t => `${t.tenantId}:${t.tip}`);
    const tree   = new MerkleTree(leaves);
    const root   = await tree.root();

    return { root, tenantTips, timestamp: Date.now() };
  }

  //  Query helpers 

  listTenants(opts: { plan?: TenantPlan; status?: TenantStatus } = {}): Tenant[] {
    const clauses: string[] = [];
    const params:  any[]    = [];
    if (opts.plan)   { clauses.push("plan = ?");   params.push(opts.plan); }
    if (opts.status) { clauses.push("status = ?"); params.push(opts.status); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows  = this.registry.prepare(
      `SELECT * FROM tenants ${where} ORDER BY created_at DESC`
    ).all(...params) as any[];
    return rows.map(r => this.rowToTenant(r));
  }

  getTenantMeta(tenantId: string): Tenant | null {
    const row = this.registry.prepare(
      "SELECT * FROM tenants WHERE id = ?"
    ).get(tenantId) as any;
    return row ? this.rowToTenant(row) : null;
  }

  getActiveCount(): number {
    return (this.registry.prepare(
      "SELECT COUNT(*) AS n FROM tenants WHERE status = 'active'"
    ).get() as any).n;
  }

  getPlanBreakdown(): Record<TenantPlan, number> {
    const rows = this.registry.prepare(
      "SELECT plan, COUNT(*) AS n FROM tenants WHERE status='active' GROUP BY plan"
    ).all() as any[];
    const result: any = { free: 0, starter: 0, growth: 0, enterprise: 0 };
    for (const r of rows) result[r.plan] = r.n;
    return result;
  }

  getMRR(): number {
    const plan = this.getPlanBreakdown();
    return plan.starter * 49 + plan.growth * 149 + plan.enterprise * 2000;
  }

  //  Key derivation 

  private async deriveTenantKey(tenantId: string): Promise<string> {
    // HKDF-style: HMAC(serverKey, tenantId)  tenant-specific key
    // This means: rotating serverKey rotates ALL tenant keys (planned rotation)
    //             each tenant key is independent (compromise one  compromise all)
    const key  = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(this.serverKey),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sig  = await crypto.subtle.sign(
      "HMAC", key, new TextEncoder().encode(`tenant-encryption:${tenantId}`)
    );
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  //  Helpers 

  private rowToTenant(row: any): Tenant {
    return {
      id:               row.id,
      name:             row.name,
      slug:             row.slug,
      plan:             row.plan,
      status:           row.status,
      ownerId:          row.owner_id,
      domain:           row.domain,
      stripeCustomerId: row.stripe_customer_id,
      stripeSubId:      row.stripe_sub_id,
      limits:           PLAN_LIMITS[row.plan as TenantPlan],
      createdAt:        row.created_at,
      updatedAt:        row.updated_at,
    };
  }

  async closeAll(): Promise<void> {
    for (const [, ctx] of this.contexts) {
      await ctx.chain.flush();
      ctx.chain.close();
    }
    this.contexts.clear();
    this.registry.close();
  }
}
