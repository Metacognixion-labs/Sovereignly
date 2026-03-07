/**
 * SovereignAuth  Solana Wallet Auth
 *
 * Implements Solana wallet sign-in using Ed25519 signature verification.
 * ZERO new dependencies  Ed25519 is already in Web Crypto API.
 * We own this entirely.
 *
 * Supports: Phantom, Backpack, Solflare, any Solana wallet
 *
 * Flow:
 *   1. GET  /auth/solana/nonce            server issues nonce
 *   2. frontend: wallet.signMessage(message bytes)  
 *   3. POST /auth/solana/verify           server verifies Ed25519 sig, issues JWT
 *
 * Message format (SIP-based, human readable):
 *   "Sign in to Sovereignly\n\nNonce: {nonce}\nIssued At: {ts}"
 */

import { verifyEd25519, fromHex } from "../security/crypto.ts";

//  Types 

export interface SolanaVerifyResult {
  valid:      boolean;
  address?:   string;   // base58 Solana public key
  reason?:    string;
}

//  Nonce store 

const nonces = new Map<string, { expiresAt: number; used: boolean }>();
const NONCE_TTL_MS = 10 * 60 * 1000;

export function generateSolanaNonce(): string {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  nonces.set(nonce, { expiresAt: Date.now() + NONCE_TTL_MS, used: false });
  return nonce;
}

function consumeNonce(nonce: string): { ok: boolean; reason?: string } {
  const entry = nonces.get(nonce);
  if (!entry)           return { ok: false, reason: "nonce not found" };
  if (entry.used)       return { ok: false, reason: "nonce already used" };
  if (Date.now() > entry.expiresAt) {
    nonces.delete(nonce);
    return { ok: false, reason: "nonce expired" };
  }
  entry.used = true;
  return { ok: true };
}

//  Message builder 

export function buildSolanaMessage(opts: {
  domain:  string;
  nonce:   string;
  address: string;
  purpose?: string;
}): string {
  return [
    `${opts.domain} wants you to sign in with your Solana account:`,
    opts.address,
    "",
    opts.purpose ?? "Sign in to Sovereignly",
    "",
    `Nonce: ${opts.nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
}

//  Base58 decode (Solana addresses are base58-encoded) 

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Decode(input: string): Uint8Array {
  const bytes = [0];
  for (const char of input) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base58 character: ${char}`);
    let carry = idx;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading zeros
  for (const char of input) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

export function base58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  const leading = [...bytes].findIndex(b => b !== 0);
  const result  = new Array(leading).fill("1");
  digits.reverse().forEach(d => result.push(BASE58_ALPHABET[d]));
  return result.join("");
}

//  Solana signature verification 

export async function verifySolanaSignature(opts: {
  message:   string;             // The sign-in message string
  signature: string;             // base64 or hex encoded 64-byte Ed25519 sig
  publicKey: string;             // base58 encoded 32-byte Ed25519 public key
}): Promise<SolanaVerifyResult> {
  try {
    // Parse the message for nonce
    const nonce = opts.message.split("\n")
      .find(l => l.startsWith("Nonce:"))?.split(": ")[1]?.trim();

    if (!nonce) return { valid: false, reason: "nonce missing from message" };

    const nonceCheck = consumeNonce(nonce);
    if (!nonceCheck.ok) return { valid: false, reason: nonceCheck.reason };

    // Decode public key from base58  raw bytes
    const publicKeyBytes = base58Decode(opts.publicKey);
    if (publicKeyBytes.length !== 32) {
      return { valid: false, reason: `invalid public key length: ${publicKeyBytes.length}` };
    }

    // Decode signature
    let sigBytes: Uint8Array;
    if (opts.signature.startsWith("0x") || /^[0-9a-fA-F]{128}$/.test(opts.signature)) {
      // Hex encoded
      const hex = opts.signature.startsWith("0x") ? opts.signature.slice(2) : opts.signature;
      sigBytes = Uint8Array.from(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
    } else {
      // Base64 encoded (Phantom default)
      sigBytes = Uint8Array.from(atob(opts.signature), c => c.charCodeAt(0));
    }

    if (sigBytes.length !== 64) {
      return { valid: false, reason: `invalid signature length: ${sigBytes.length}` };
    }

    // Import Ed25519 public key using Web Crypto API (ZERO new dependencies)
    const key = await crypto.subtle.importKey(
      "raw", publicKeyBytes,
      { name: "Ed25519" },
      false, ["verify"]
    );

    // Verify signature against the raw message bytes
    const messageBytes = new TextEncoder().encode(opts.message);
    const valid = await crypto.subtle.verify("Ed25519", key, sigBytes, messageBytes);

    if (!valid) return { valid: false, reason: "signature verification failed" };

    return { valid: true, address: opts.publicKey };
  } catch (err: any) {
    return { valid: false, reason: err.message };
  }
}
