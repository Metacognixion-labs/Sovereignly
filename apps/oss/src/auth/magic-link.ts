/**
 * Sovereignly  Magic Link Authentication (Claude.ai-style)
 *
 * Email contains:
 *   1. A clickable magic link URL (primary — one-click sign in)
 *   2. A 6-digit code (fallback — manual entry)
 *
 * Flow (magic link):
 *   User clicks link → GET /_sovereign/auth/magic?token=xxx
 *   Server verifies token → issues JWT → redirects to dashboard
 *
 * Flow (code fallback):
 *   User enters 6-digit code on the signin page
 *   POST /_sovereign/signin/verify { email, code }
 *
 * Security:
 *   - Magic link tokens are HMAC-SHA256 signed (tamper-proof)
 *   - Codes stored as SHA-256 hashes
 *   - 10-minute TTL, one-time use
 *   - Max 5 requests per email per 15 minutes
 */

import { Database } from "bun:sqlite";
import { join }     from "node:path";
import { sha256, hmac256, hmac256Verify } from "../security/crypto.ts";
import type { EmailTransport } from "./email-transport.ts";

const CODE_TTL_MS       = 10 * 60 * 1000;  // 10 minutes
const MAX_ACTIVE_CODES  = 3;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;  // 15 minutes
const RATE_LIMIT_MAX    = 5;

export class MagicLinkService {
  private db: Database;
  private email: EmailTransport;
  private signingKey: string;
  private appUrl: string;
  private rateLimits = new Map<string, number[]>();

  constructor(opts: {
    dataDir: string;
    emailTransport: EmailTransport;
    signingKey: string;
    appUrl: string;
  }) {
    this.email = opts.emailTransport;
    this.signingKey = opts.signingKey;
    this.appUrl = opts.appUrl.replace(/\/$/, "");
    const fs = require("node:fs");
    try { fs.mkdirSync(opts.dataDir, { recursive: true }); } catch {}
    this.db = new Database(join(opts.dataDir, "auth.db"));
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run(`
      CREATE TABLE IF NOT EXISTS magic_codes (
        id          TEXT PRIMARY KEY,
        email       TEXT NOT NULL,
        code_hash   TEXT NOT NULL,
        token       TEXT NOT NULL,
        purpose     TEXT NOT NULL DEFAULT 'signin',
        expires_at  INTEGER NOT NULL,
        used        INTEGER DEFAULT 0,
        created_at  INTEGER NOT NULL
      )
    `);
    this.db.run("CREATE INDEX IF NOT EXISTS idx_magic_email ON magic_codes(email)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_magic_token ON magic_codes(token)");

    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  /**
   * Send a magic link + code to the email address.
   * Returns the code ID (for internal tracking).
   */
  async requestCode(
    email: string,
    purpose: "signin" | "signup" = "signin"
  ): Promise<{ ok: boolean; error?: string }> {
    const normalized = email.trim().toLowerCase();

    // Rate limit
    const now = Date.now();
    const attempts = (this.rateLimits.get(normalized) ?? []).filter(t => t > now - RATE_LIMIT_WINDOW);
    if (attempts.length >= RATE_LIMIT_MAX) {
      return { ok: false, error: "Too many requests. Try again in a few minutes." };
    }
    attempts.push(now);
    this.rateLimits.set(normalized, attempts);

    // Invalidate old active codes
    const active = this.db.prepare(
      "SELECT COUNT(*) AS n FROM magic_codes WHERE email=? AND used=0 AND expires_at>?"
    ).get(normalized, now) as any;
    if (active.n >= MAX_ACTIVE_CODES) {
      this.db.prepare("UPDATE magic_codes SET used=1 WHERE email=? AND used=0").run(normalized);
    }

    // Generate 6-digit code
    const codeNum = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
    const code = String(codeNum).padStart(6, "0");
    const codeHash = await sha256(normalized + ":" + code);

    // Generate signed magic link token
    const tokenId = crypto.randomUUID();
    const expiresAt = now + CODE_TTL_MS;
    const payload = `${tokenId}:${normalized}:${purpose}:${expiresAt}`;
    const signature = await hmac256(this.signingKey, payload);
    const magicToken = btoa(JSON.stringify({ id: tokenId, sig: signature })).replace(/=/g, "");

    this.db.prepare(`
      INSERT INTO magic_codes (id, email, code_hash, token, purpose, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(tokenId, normalized, codeHash, magicToken, purpose, expiresAt, now);

    // Build magic link URL
    const magicUrl = `${this.appUrl}/_sovereign/auth/magic?token=${encodeURIComponent(magicToken)}&email=${encodeURIComponent(normalized)}&purpose=${purpose}`;

    // Send email
    const purposeLabel = purpose === "signin" ? "sign in to" : "verify your account on";
    await this.email.send(
      normalized,
      `Sign in to Sovereignly`,
      this.buildEmailHtml(magicUrl, code, purposeLabel),
      `Click this link to ${purposeLabel} Sovereignly:\n\n${magicUrl}\n\nOr enter this code: ${code}\n\nExpires in 10 minutes. If you didn't request this, ignore this email.`,
    );

    return { ok: true };
  }

  /** Verify a 6-digit code (manual entry fallback). */
  async verifyCode(
    email: string,
    code: string,
    purpose: "signin" | "signup" = "signin"
  ): Promise<{ valid: boolean; error?: string }> {
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

    if (!row) return { valid: false, error: "Invalid or expired code" };

    this.db.prepare("UPDATE magic_codes SET used=1 WHERE id=?").run(row.id);
    return { valid: true };
  }

  /** Verify a magic link token (one-click sign in). */
  async verifyMagicToken(
    token: string,
    email: string,
    purpose: "signin" | "signup" = "signin"
  ): Promise<{ valid: boolean; error?: string }> {
    const normalized = email.trim().toLowerCase();

    // Decode token
    let parsed: { id: string; sig: string };
    try {
      parsed = JSON.parse(atob(token + "==".slice((4 - token.length % 4) % 4)));
    } catch {
      return { valid: false, error: "Invalid token" };
    }

    const now = Date.now();

    // Look up in DB
    const row = this.db.prepare(
      "SELECT id, email, purpose, expires_at FROM magic_codes WHERE id=? AND token=? AND used=0 LIMIT 1"
    ).get(parsed.id, token) as any;

    if (!row) return { valid: false, error: "Invalid or expired link" };
    if (row.expires_at < now) return { valid: false, error: "Link has expired" };
    if (row.email !== normalized) return { valid: false, error: "Email mismatch" };
    if (row.purpose !== purpose) return { valid: false, error: "Purpose mismatch" };

    // Verify HMAC signature
    const payload = `${parsed.id}:${row.email}:${row.purpose}:${row.expires_at}`;
    const sigValid = await hmac256Verify(this.signingKey, payload, parsed.sig);
    if (!sigValid) return { valid: false, error: "Invalid signature" };

    // Mark used
    this.db.prepare("UPDATE magic_codes SET used=1 WHERE id=?").run(row.id);
    return { valid: true };
  }

  private cleanup() {
    const cutoff = Date.now() - CODE_TTL_MS * 2;
    this.db.prepare("DELETE FROM magic_codes WHERE created_at < ?").run(cutoff);
    const now = Date.now();
    for (const [email, times] of this.rateLimits) {
      const valid = times.filter(t => t > now - RATE_LIMIT_WINDOW);
      if (valid.length === 0) this.rateLimits.delete(email);
      else this.rateLimits.set(email, valid);
    }
  }

  /** Claude.ai-style email: big green button + code fallback */
  private buildEmailHtml(magicUrl: string, code: string, purposeLabel: string): string {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#050a10;font-family:-apple-system,'Segoe UI',system-ui,sans-serif">
<div style="max-width:480px;margin:0 auto;padding:48px 20px">
  <!-- Logo -->
  <div style="text-align:center;margin-bottom:40px">
    <div style="display:inline-block;width:40px;height:40px;background:linear-gradient(135deg,#a78bfa,#2B7FFF,#0df23b);border-radius:10px;margin-bottom:12px"></div>
    <div style="font-size:15px;font-weight:700;letter-spacing:.08em;color:#f0f2f5">SOVEREIGNLY</div>
  </div>

  <!-- Card -->
  <div style="background:#111b2a;border:1px solid #1e293b;border-radius:16px;padding:40px 32px;text-align:center">
    <h1 style="font-size:22px;font-weight:600;color:#f0f2f5;margin:0 0 8px;letter-spacing:-.02em">
      ${purposeLabel === "sign in to" ? "Sign in to Sovereignly" : "Verify your email"}
    </h1>
    <p style="color:#94a3b8;font-size:14px;margin:0 0 32px;line-height:1.5">
      Click the button below to ${purposeLabel} Sovereignly. This link expires in 10 minutes.
    </p>

    <!-- Magic Link Button -->
    <a href="${magicUrl}" style="display:inline-block;padding:14px 48px;background:#0df23b;color:#050a10;font-size:15px;font-weight:700;text-decoration:none;border-radius:8px;letter-spacing:.01em">
      ${purposeLabel === "sign in to" ? "Sign in" : "Verify email"}
    </a>

    <!-- Divider -->
    <div style="margin:32px 0;border-top:1px solid #1e293b;position:relative">
      <span style="position:absolute;top:-10px;left:50%;transform:translateX(-50%);background:#111b2a;padding:0 12px;color:#475569;font-size:12px">or enter code manually</span>
    </div>

    <!-- Code -->
    <div style="font-size:32px;font-weight:700;letter-spacing:.4em;color:#f0f2f5;font-family:'Courier New',monospace;background:#0d151f;border:1px solid #1e293b;border-radius:10px;padding:16px 24px;display:inline-block">${code}</div>
  </div>

  <!-- Footer -->
  <p style="color:#475569;font-size:11px;text-align:center;margin-top:24px;line-height:1.6">
    If you didn't request this email, you can safely ignore it.<br>
    <span style="color:#334155">Sovereignly — Cryptographically Proven Infrastructure</span>
  </p>
</div>
</body></html>`;
  }

  close() { this.db.close(); }
}
