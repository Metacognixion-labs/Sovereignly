#!/usr/bin/env bun
/**
 * Sovereignly  CLI Admin Bootstrap
 *
 * Creates the first admin account directly, bypassing email verification.
 * Run via: fly ssh console -C "bun run deploy/admin-bootstrap.ts --email admin@company.com"
 *
 * Or locally: bun run deploy/admin-bootstrap.ts --email admin@company.com --name "Acme Corp"
 */

import { Database } from "bun:sqlite";
import { join }     from "node:path";
import { mkdirSync, existsSync } from "node:fs";

// Parse args
const args = process.argv.slice(2);
const getArg = (name: string): string | undefined => {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 ? args[idx + 1] : undefined;
};

const email = getArg("email");
const name  = getArg("name") ?? "Admin";
const dataDir = getArg("data-dir") ?? "./data";

if (!email) {
  console.error(`
  Sovereignly Admin Bootstrap

  Usage:
    bun run deploy/admin-bootstrap.ts --email admin@company.com [--name "Org Name"] [--data-dir ./data]

  Options:
    --email     Admin email (required)
    --name      Organization name (default: "Admin")
    --data-dir  Data directory (default: ./data)

  Examples:
    fly ssh console -C "bun run deploy/admin-bootstrap.ts --email jp@metacognixion.com"
    bun run deploy/admin-bootstrap.ts --email admin@acme.com --name "Acme Corp"
  `);
  process.exit(1);
}

const normalized = email.trim().toLowerCase();
const globalDir = join(dataDir, "global");

// Ensure dirs exist
try { mkdirSync(globalDir, { recursive: true }); } catch {}

// Open registry
const registry = new Database(join(globalDir, "tenants.db"));
registry.run("PRAGMA journal_mode = WAL");
registry.run(`
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
    enc_key_hash        TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
  )
`);

// Check if admin already exists
const existing = registry.prepare(
  "SELECT * FROM tenants WHERE owner_id = ? AND status = 'active'"
).get(normalized) as any;

if (existing) {
  console.log(`\n  Admin tenant already exists for ${normalized}`);
  console.log(`  Tenant ID: ${existing.id}`);
  console.log(`  Name: ${existing.name}`);
  console.log(`  Plan: ${existing.plan}`);
  console.log(`  Created: ${new Date(existing.created_at).toISOString()}\n`);

  // Generate JWT
  const jwtSecret = process.env.JWT_SECRET ?? process.env.SOVEREIGN_SERVER_KEY ?? "dev-secret";
  const token = await generateJWT(normalized, existing.id, jwtSecret);
  console.log(`  Fresh JWT (30-day):`);
  console.log(`  ${token}\n`);
  process.exit(0);
}

// Provision admin tenant
const id = `org_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 32) + "-" + id.slice(-6);
const now = Date.now();

// Derive enc key hash
const keyMaterial = new TextEncoder().encode(process.env.SOVEREIGN_SERVER_KEY ?? "dev-key");
const hmacKey = await crypto.subtle.importKey("raw", keyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
const sig = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(`tenant-encryption:${id}`));
const encKey = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
const keyHashBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(encKey));
const keyHash = Array.from(new Uint8Array(keyHashBytes)).map(b => b.toString(16).padStart(2, "0")).join("");

// Create tenant data dir
const tenantDir = join(dataDir, "tenants", id, "storage");
try { mkdirSync(tenantDir, { recursive: true }); } catch {}

// Insert into registry
registry.prepare(`
  INSERT INTO tenants (id, name, slug, plan, status, owner_id, enc_key_hash, created_at, updated_at)
  VALUES (?, ?, ?, 'enterprise', 'active', ?, ?, ?, ?)
`).run(id, name, slug, normalized, keyHash, now, now);

// Generate JWT
const jwtSecret = process.env.JWT_SECRET ?? process.env.SOVEREIGN_SERVER_KEY ?? "dev-secret";
const token = await generateJWT(normalized, id, jwtSecret);

console.log(`
${"═".repeat(60)}
  ADMIN BOOTSTRAP COMPLETE

  Email:     ${normalized}
  Tenant ID: ${id}
  Name:      ${name}
  Plan:      enterprise
  Slug:      ${slug}

  JWT Token (30-day, owner role):
  ${token}

  To use:
    curl -H "Authorization: Bearer ${token}" https://sovereignly.fly.dev/_sovereign/me
${"═".repeat(60)}
`);

registry.close();

// ── JWT helper ────────────────────────────────────────────────────────────────

async function generateJWT(sub: string, tid: string, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = { sub, tid, role: "owner", iat: now, exp: now + 86400 * 30, jti: crypto.randomUUID() };
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })).replace(/=/g, "");
  const body = btoa(JSON.stringify(payload)).replace(/=/g, "");
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBytes = await crypto.subtle.sign("HMAC", keyMaterial, new TextEncoder().encode(`${header}.${body}`));
  const sigHex = Array.from(new Uint8Array(sigBytes)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `${header}.${body}.${btoa(sigHex).replace(/=/g, "")}`;
}
