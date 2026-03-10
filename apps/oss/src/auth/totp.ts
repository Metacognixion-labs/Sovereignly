/**
 * Sovereignly  TOTP + Backup Codes
 *
 * RFC 6238 TOTP implementation using Web Crypto API (zero external deps).
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 *
 * Features:
 *   - TOTP secret generation (160-bit, base32-encoded)
 *   - TOTP verification with ±1 window tolerance (clock skew)
 *   - Backup code generation (10 codes, "xxxx-xxxx" format)
 *   - Backup codes stored as SHA-256 hashes (one-time use)
 *   - Secrets encrypted at rest with AES-256-GCM
 */

import { Database } from "bun:sqlite";
import { join }     from "node:path";
import { sha256, encryptAES, decryptAES } from "../security/crypto.ts";

// ── Base32 (RFC 4648) ─────────────────────────────────────────────────────────

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

export function base32Decode(str: string): Uint8Array {
  const cleaned = str.replace(/[= ]/g, "").toUpperCase();
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const c of cleaned) {
    const idx = B32_ALPHABET.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

// ── TOTP Core ─────────────────────────────────────────────────────────────────

const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // ±1 period

async function hmacSha1(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return new Uint8Array(sig);
}

function intToBytes(n: number): Uint8Array {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(4, n, false); // big-endian, low 32 bits
  return new Uint8Array(buf);
}

export async function generateTOTP(secret: Uint8Array, timeStep?: number): Promise<string> {
  const t = timeStep ?? Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  const hmac = await hmacSha1(secret, intToBytes(t));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % (10 ** TOTP_DIGITS);
  return String(code).padStart(TOTP_DIGITS, "0");
}

export async function verifyTOTP(secret: Uint8Array, code: string): Promise<boolean> {
  const t = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  const cleaned = code.trim();
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const expected = await generateTOTP(secret, t + i);
    // Constant-time comparison
    if (expected.length !== cleaned.length) continue;
    let diff = 0;
    for (let j = 0; j < expected.length; j++) {
      diff |= expected.charCodeAt(j) ^ cleaned.charCodeAt(j);
    }
    if (diff === 0) return true;
  }
  return false;
}

// ── Backup Codes ──────────────────────────────────────────────────────────────

export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const bytes = crypto.getRandomValues(new Uint8Array(4));
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    codes.push(hex.slice(0, 4) + "-" + hex.slice(4, 8));
  }
  return codes;
}

// ── TOTP Service (persistence layer) ──────────────────────────────────────────

export class TOTPService {
  private db: Database;
  private encPassword: string;

  constructor(opts: { dataDir: string; encPassword: string }) {
    this.encPassword = opts.encPassword;
    this.db = new Database(join(opts.dataDir, "auth.db"));
    this.db.run("PRAGMA journal_mode = WAL");

    this.db.run(`
      CREATE TABLE IF NOT EXISTS totp_secrets (
        user_id           TEXT PRIMARY KEY,
        secret_encrypted  TEXT NOT NULL,
        enabled           INTEGER DEFAULT 0,
        created_at        INTEGER NOT NULL
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS backup_codes (
        id         TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL,
        code_hash  TEXT NOT NULL,
        used       INTEGER DEFAULT 0,
        used_at    INTEGER,
        created_at INTEGER NOT NULL
      )
    `);
    this.db.run("CREATE INDEX IF NOT EXISTS idx_backup_user ON backup_codes(user_id)");
  }

  /** Generate a new TOTP secret for a user. Returns the secret + otpauth URI. Does NOT enable yet. */
  async setup(userId: string, email: string): Promise<{
    secret: string;
    otpauthUri: string;
  }> {
    // Generate 20-byte (160-bit) secret
    const secretBytes = crypto.getRandomValues(new Uint8Array(20));
    const secret = base32Encode(secretBytes);
    const otpauthUri = `otpauth://totp/Sovereignly:${encodeURIComponent(email)}?secret=${secret}&issuer=Sovereignly&digits=6&period=30`;

    // Encrypt and store (not enabled until confirmed)
    const encrypted = await encryptAES(secret, this.encPassword);
    this.db.prepare(`
      INSERT OR REPLACE INTO totp_secrets (user_id, secret_encrypted, enabled, created_at)
      VALUES (?, ?, 0, ?)
    `).run(userId, encrypted, Date.now());

    return { secret, otpauthUri };
  }

  /** Confirm TOTP setup by verifying a code. Enables TOTP and generates backup codes. */
  async confirm(userId: string, code: string): Promise<{
    ok: boolean;
    backupCodes?: string[];
    error?: string;
  }> {
    const row = this.db.prepare(
      "SELECT secret_encrypted FROM totp_secrets WHERE user_id=?"
    ).get(userId) as any;
    if (!row) return { ok: false, error: "No TOTP setup in progress" };

    const secret = await decryptAES(row.secret_encrypted, this.encPassword);
    const secretBytes = base32Decode(secret);
    const valid = await verifyTOTP(secretBytes, code);
    if (!valid) return { ok: false, error: "Invalid code. Make sure your authenticator is synced." };

    // Enable TOTP
    this.db.prepare("UPDATE totp_secrets SET enabled=1 WHERE user_id=?").run(userId);

    // Generate backup codes
    const backupCodes = generateBackupCodes(10);
    // Remove old backup codes
    this.db.prepare("DELETE FROM backup_codes WHERE user_id=?").run(userId);
    // Store hashes
    for (const bc of backupCodes) {
      const hash = await sha256(userId + ":" + bc.toLowerCase());
      this.db.prepare(
        "INSERT INTO backup_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)"
      ).run(crypto.randomUUID(), userId, hash, Date.now());
    }

    return { ok: true, backupCodes };
  }

  /** Verify a TOTP code for login. */
  async verify(userId: string, code: string): Promise<boolean> {
    const row = this.db.prepare(
      "SELECT secret_encrypted, enabled FROM totp_secrets WHERE user_id=?"
    ).get(userId) as any;
    if (!row || !row.enabled) return false;

    const secret = await decryptAES(row.secret_encrypted, this.encPassword);
    const secretBytes = base32Decode(secret);
    return verifyTOTP(secretBytes, code);
  }

  /** Check if TOTP is enabled for a user. */
  isEnabled(userId: string): boolean {
    const row = this.db.prepare(
      "SELECT enabled FROM totp_secrets WHERE user_id=?"
    ).get(userId) as any;
    return row?.enabled === 1;
  }

  /** Verify and consume a backup code. Returns true if valid. */
  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const hash = await sha256(userId + ":" + code.trim().toLowerCase());
    const row = this.db.prepare(
      "SELECT id FROM backup_codes WHERE user_id=? AND code_hash=? AND used=0 LIMIT 1"
    ).get(userId, hash) as any;
    if (!row) return false;

    this.db.prepare("UPDATE backup_codes SET used=1, used_at=? WHERE id=?")
      .run(Date.now(), row.id);
    return true;
  }

  /** Regenerate backup codes (requires valid TOTP code first). */
  async regenerateBackupCodes(userId: string, totpCode: string): Promise<{
    ok: boolean;
    backupCodes?: string[];
    error?: string;
  }> {
    const valid = await this.verify(userId, totpCode);
    if (!valid) return { ok: false, error: "Invalid TOTP code" };

    // Invalidate old codes
    this.db.prepare("DELETE FROM backup_codes WHERE user_id=?").run(userId);

    // Generate new codes
    const backupCodes = generateBackupCodes(10);
    for (const bc of backupCodes) {
      const hash = await sha256(userId + ":" + bc.toLowerCase());
      this.db.prepare(
        "INSERT INTO backup_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)"
      ).run(crypto.randomUUID(), userId, hash, Date.now());
    }

    return { ok: true, backupCodes };
  }

  /** Get count of remaining unused backup codes. */
  remainingBackupCodes(userId: string): number {
    const row = this.db.prepare(
      "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id=? AND used=0"
    ).get(userId) as any;
    return row?.n ?? 0;
  }

  /** Disable TOTP for a user. */
  async disable(userId: string, code: string): Promise<{ ok: boolean; error?: string }> {
    const valid = await this.verify(userId, code);
    if (!valid) return { ok: false, error: "Invalid TOTP code" };

    this.db.prepare("DELETE FROM totp_secrets WHERE user_id=?").run(userId);
    this.db.prepare("DELETE FROM backup_codes WHERE user_id=?").run(userId);
    return { ok: true };
  }

  close() { this.db.close(); }
}
