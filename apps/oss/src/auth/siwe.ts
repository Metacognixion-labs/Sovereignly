/**
 * SovereignAuth  SIWE (Sign-In With Ethereum)
 *
 * Implements EIP-4361 (Sign-In With Ethereum) natively.
 * Verifies EVM wallet signatures using secp256k1 ecrecover.
 *
 * Single dependency: @noble/curves (pure TypeScript, 40KB, zero C bindings)
 * No Privy. No WalletConnect server. No external calls.
 *
 * Supports:
 *   - MetaMask (EIP-1193 browser injection)
 *   - WalletConnect v2 (client-side QR pairing, no server dependency)
 *   - Coinbase Wallet
 *   - Any EIP-4361 compliant wallet
 *
 * Flow:
 *   1. GET  /auth/siwe/nonce          server issues nonce (stored in KV, 10min TTL)
 *   2. frontend: wallet.signMessage(EIP-4361 message)
 *   3. POST /auth/siwe/verify         server ecrecovers address, verifies, issues JWT
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256Raw }  from "../security/crypto.ts";

//  Types 

export interface SIWEMessage {
  domain:    string;   // e.g. "app.sovereignly.io"
  address:   string;   // EVM address (checksummed)
  statement: string;   // human-readable purpose
  uri:       string;   // requesting URI
  version:   string;   // "1"
  chainId:   number;   // EIP-155 chain ID (1 = Ethereum mainnet)
  nonce:     string;   // server-issued nonce
  issuedAt:  string;   // ISO-8601
  expirationTime?: string;
  resources?: string[];
}

export interface SIWEVerifyResult {
  valid:    boolean;
  address?: string;   // recovered EVM address (lowercased)
  reason?:  string;
}

//  Nonce store (in-memory with TTL  replace with SovereignKV in production) 

const nonces = new Map<string, { expiresAt: number; used: boolean }>();
const NONCE_TTL_MS = 10 * 60 * 1000; // 10 minutes

export function generateNonce(): string {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  nonces.set(nonce, { expiresAt: Date.now() + NONCE_TTL_MS, used: false });
  // Cleanup stale nonces
  if (nonces.size > 10_000) {
    const now = Date.now();
    for (const [k, v] of nonces) {
      if (v.expiresAt < now) nonces.delete(k);
    }
  }
  return nonce;
}

function consumeNonce(nonce: string): { ok: boolean; reason?: string } {
  const entry = nonces.get(nonce);
  if (!entry)              return { ok: false, reason: "nonce not found" };
  if (entry.used)          return { ok: false, reason: "nonce already used" };
  if (Date.now() > entry.expiresAt) {
    nonces.delete(nonce);
    return { ok: false, reason: "nonce expired" };
  }
  entry.used = true;
  return { ok: true };
}

//  EIP-4361 message builder 

export function buildSIWEMessage(msg: SIWEMessage): string {
  const lines = [
    `${msg.domain} wants you to sign in with your Ethereum account:`,
    msg.address,
    "",
    msg.statement,
    "",
    `URI: ${msg.uri}`,
    `Version: ${msg.version}`,
    `Chain ID: ${msg.chainId}`,
    `Nonce: ${msg.nonce}`,
    `Issued At: ${msg.issuedAt}`,
  ];
  if (msg.expirationTime) lines.push(`Expiration Time: ${msg.expirationTime}`);
  if (msg.resources?.length) {
    lines.push("Resources:");
    msg.resources.forEach(r => lines.push(`- ${r}`));
  }
  return lines.join("\n");
}

//  EIP-191 personal_sign prefix 

function personalSignPrefix(msg: string): Uint8Array {
  const enc  = new TextEncoder();
  const body = enc.encode(msg);
  const prefix = enc.encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const result = new Uint8Array(prefix.length + body.length);
  result.set(prefix, 0);
  result.set(body, prefix.length);
  return result;
}

//  Keccak-256 (needed for address recovery) 
// We implement a minimal keccak-256 using the noble/curves internal hasher
// rather than adding another dependency

async function keccak256(data: Uint8Array): Promise<Uint8Array> {
  // @noble/curves ships keccak internally  access via hash utility
  const { keccak_256 } = await import("@noble/curves/abstract/utils").catch(() => null) as any;
  if (keccak_256) return keccak_256(data);

  // Fallback: use @noble/hashes if available (peer dep of @noble/curves)
  try {
    const { keccak_256: k } = await import("@noble/hashes/sha3") as any;
    return k(data);
  } catch {
    throw new Error("keccak_256 not available  ensure @noble/curves 1.3 is installed");
  }
}

//  Address recovery (ecrecover) 

async function recoverAddress(
  messageHash: Uint8Array,
  signature:   string    // hex 0x-prefixed, 65 bytes
): Promise<string> {
  // Strip 0x, parse r, s, v
  const sigHex = signature.startsWith("0x") ? signature.slice(2) : signature;
  if (sigHex.length !== 130) throw new Error(`Invalid signature length: ${sigHex.length}`);

  const sigBytes = Uint8Array.from(
    sigHex.match(/.{2}/g)!.map(b => parseInt(b, 16))
  );

  let v = sigBytes[64];
  if (v === 27 || v === 28) v -= 27; // Normalize v

  // Recover public key using secp256k1
  const recoveryBit   = v as 0 | 1;
  const compactSig    = sigBytes.slice(0, 64);
  const publicKeyBytes = secp256k1.Signature
    .fromCompact(compactSig)
    .addRecoveryBit(recoveryBit)
    .recoverPublicKey(messageHash)
    .toRawBytes(false); // uncompressed, 65 bytes

  // Keccak of public key (skip first byte  0x04 prefix)
  const pubKeyHash = await keccak256(publicKeyBytes.slice(1));

  // Last 20 bytes = Ethereum address
  const address = "0x" + Array.from(pubKeyHash.slice(-20))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  return address.toLowerCase();
}

//  Main verification 

export async function verifySIWE(opts: {
  message:   string;   // The raw EIP-4361 message string
  signature: string;   // 0x-prefixed hex signature from wallet
}): Promise<SIWEVerifyResult> {
  try {
    // Parse the message
    const lines   = opts.message.split("\n");
    const address = lines[1]?.trim().toLowerCase();
    const nonce   = lines.find(l => l.startsWith("Nonce:"))?.split(": ")[1]?.trim();
    const issued  = lines.find(l => l.startsWith("Issued At:"))?.split(": ")[1]?.trim();
    const expiry  = lines.find(l => l.startsWith("Expiration Time:"))?.split(": ")[1]?.trim();

    if (!address || !nonce) return { valid: false, reason: "malformed message" };

    // Check nonce
    const nonceCheck = consumeNonce(nonce);
    if (!nonceCheck.ok) return { valid: false, reason: nonceCheck.reason };

    // Check expiry
    if (expiry && new Date(expiry) < new Date()) {
      return { valid: false, reason: "message expired" };
    }

    // Check issuance (not more than 10 minutes old)
    if (issued) {
      const age = Date.now() - new Date(issued).getTime();
      if (age > NONCE_TTL_MS) return { valid: false, reason: "message too old" };
    }

    // Hash message using EIP-191 prefix + keccak256
    const prefixed    = personalSignPrefix(opts.message);
    const messageHash = await keccak256(prefixed);

    // Recover signer address
    const recovered = await recoverAddress(messageHash, opts.signature);

    // Compare (case-insensitive)
    if (recovered !== address) {
      return { valid: false, reason: `address mismatch: expected ${address}, got ${recovered}` };
    }

    return { valid: true, address: recovered };
  } catch (err: any) {
    return { valid: false, reason: err.message };
  }
}

//  Checksum address (EIP-55) 

export async function checksumAddress(address: string): Promise<string> {
  const lower  = address.toLowerCase().replace("0x", "");
  const hash   = await keccak256(new TextEncoder().encode(lower));
  const hexHash = Array.from(hash).map(b => b.toString(16).padStart(2, "0")).join("");

  const checksummed = lower.split("").map((char, i) => {
    if (!/[a-f0-9]/.test(char)) return char;
    return parseInt(hexHash[i], 16) >= 8 ? char.toUpperCase() : char;
  }).join("");

  return "0x" + checksummed;
}
