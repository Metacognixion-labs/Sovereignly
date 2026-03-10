/**
 * Sovereignly  Magic Link / Verification Code Service
 *
 * Two-step email verification for signin and signup:
 *   1. requestCode(email) → generates 6-digit code, sends via email
 *   2. verifyCode(email, code) → validates code, returns success
 *
 * Security:
 *   - Codes stored as SHA-256 hashes (DB leak doesn't expose codes)
 *   - 10-minute TTL per code
 *   - Max 3 active codes per email
 *   - Max 5 code requests per email per 15 minutes
 *   - One-time use (marked used after verification)
 */

import { Database } from "bun:sqlite";
import { join }     from "node:path";
import { sha256 }   from "../security/crypto.ts";
import type { EmailTransport } from "./email-transport.ts";

const CODE_TTL_MS       = 10 * 60 * 1000;  // 10 minutes
const MAX_ACTIVE_CODES  = 3;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;  // 15 minutes
const RATE_LIMIT_MAX    = 5;

export class MagicLinkService {
  private db: Database;
  private email: EmailTransport;
  private rateLimits = new Map<string, number[]>();

  constructor(opts: { dataDir: string; emailTransport: EmailTransport }) {
    this.email = opts.emailTransport;
    const fs = require("node:fs");
    try { fs.mkdirSync(opts.dataDir, { recursive: true }); } catch {}
    this.db = new Database(join(opts.dataDir, "auth.db"));
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run(`
      CREATE TABLE IF NOT EXISTS magic_codes (
        id          TEXT PRIMARY KEY,
        email       TEXT NOT NULL,
        code_hash   TEXT NOT NULL,
        purpose     TEXT NOT NULL DEFAULT 'signin',
        expires_at  INTEGER NOT NULL,
        used        INTEGER DEFAULT 0,
        created_at  INTEGER NOT NULL
      )
    `);
    this.db.run("CREATE INDEX IF NOT EXISTS idx_magic_email ON magic_codes(email)");

    // Cleanup expired codes every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  async requestCode(email: string, purpose: "signin" | "signup" = "signin"): Promise<{ ok: boolean; error?: string }> {
    const normalized = email.trim().toLowerCase();

    // Rate limit
    const now = Date.now();
    const attempts = (this.rateLimits.get(normalized) ?? []).filter(t => t > now - RATE_LIMIT_WINDOW);
    if (attempts.length >= RATE_LIMIT_MAX) {
      return { ok: false, error: "Too many code requests. Try again in a few minutes." };
    }
    attempts.push(now);
    this.rateLimits.set(normalized, attempts);

    // Invalidate old active codes for this email beyond limit
    const active = this.db.prepare(
      "SELECT COUNT(*) AS n FROM magic_codes WHERE email=? AND used=0 AND expires_at>?"
    ).get(normalized, now) as any;
    if (active.n >= MAX_ACTIVE_CODES) {
      this.db.prepare(
        "UPDATE magic_codes SET used=1 WHERE email=? AND used=0"
      ).run(normalized);
    }

    // Generate 6-digit code
    const codeNum = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
    const code = String(codeNum).padStart(6, "0");
    const codeHash = await sha256(normalized + ":" + code);

    this.db.prepare(`
      INSERT INTO magic_codes (id, email, code_hash, purpose, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), normalized, codeHash, purpose, now + CODE_TTL_MS, now);

    // Send email
    const purposeLabel = purpose === "signin" ? "sign in" : "verify your email";
    await this.email.send(
      normalized,
      `${code} — Your Sovereignly verification code`,
      this.buildEmailHtml(code, purposeLabel),
      `Your Sovereignly verification code is: ${code}\n\nThis code expires in 10 minutes. If you didn't request this, ignore this email.`,
    );

    return { ok: true };
  }

  async verifyCode(email: string, code: string, purpose: "signin" | "signup" = "signin"): Promise<{ valid: boolean; error?: string }> {
    const normalized = email.trim().toLowerCase();
    const codeClean = code.trim().replace(/\s/g, "");

    if (!/^\d{6}$/.test(codeClean)) {
      return { valid: false, error: "Code must be 6 digits" };
    }

    const codeHash = await sha256(normalized + ":" + codeClean);
    const now = Date.now();

    const row = this.db.prepare(
      "SELECT id FROM magic_codes WHERE email=? AND code_hash=? AND purpose=? AND used=0 AND expires_at>? LIMIT 1"
    ).get(normalized, codeHash, purpose, now) as any;

    if (!row) {
      return { valid: false, error: "Invalid or expired code" };
    }

    // Mark as used
    this.db.prepare("UPDATE magic_codes SET used=1 WHERE id=?").run(row.id);
    return { valid: true };
  }

  private cleanup() {
    const cutoff = Date.now() - CODE_TTL_MS * 2;
    this.db.prepare("DELETE FROM magic_codes WHERE created_at < ?").run(cutoff);
    // Cleanup rate limits
    const now = Date.now();
    for (const [email, times] of this.rateLimits) {
      const valid = times.filter(t => t > now - RATE_LIMIT_WINDOW);
      if (valid.length === 0) this.rateLimits.delete(email);
      else this.rateLimits.set(email, valid);
    }
  }

  private buildEmailHtml(code: string, purpose: string): string {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#050a10;font-family:'Segoe UI',system-ui,sans-serif">
<div style="max-width:480px;margin:0 auto;padding:40px 20px">
  <div style="text-align:center;margin-bottom:32px">
    <div style="font-size:14px;font-weight:700;letter-spacing:.15em;color:#0df23b">SOVEREIGNLY</div>
    <div style="font-size:11px;color:#64748b;margin-top:4px">cryptographically proven infrastructure</div>
  </div>
  <div style="background:#111b2a;border:1px solid #1e293b;border-radius:12px;padding:32px;text-align:center">
    <p style="color:#94a3b8;font-size:14px;margin:0 0 24px">Your code to ${purpose}:</p>
    <div style="font-size:36px;font-weight:700;letter-spacing:.3em;color:#f0f2f5;font-family:monospace;background:#0d151f;border:1px solid #1e293b;border-radius:8px;padding:16px;display:inline-block">${code}</div>
    <p style="color:#64748b;font-size:12px;margin:24px 0 0">Expires in 10 minutes. If you didn't request this, ignore this email.</p>
  </div>
</div>
</body></html>`;
  }

  close() { this.db.close(); }
}
