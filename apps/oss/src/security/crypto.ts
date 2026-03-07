/**
 * Sovereignly v3  Cryptographic Primitives
 *
 * Provides the foundation for the audit chain:
 *   - Ed25519 node identity keypairs
 *   - SHA-256 / HMAC-SHA256 hashing
 *   - Merkle tree construction and proof verification
 *   - AES-256-GCM symmetric encryption for secrets at rest
 *
 * All operations use the Web Crypto API (available natively in Bun).
 * No external dependencies.
 */

//  Types 

export interface NodeKeyPair {
  publicKey:  Uint8Array;   // 32 bytes
  privateKey: Uint8Array;   // 64 bytes (includes public)
  publicKeyHex: string;
}

export interface MerkleProof {
  root:  string;
  leaf:  string;
  proof: Array<{ sibling: string; direction: "left" | "right" }>;
}

//  Encoding helpers 

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

//  SHA-256 

const encoder = new TextEncoder();


/** keccak256  correct EVM hash. Required for address derivation and EIP-712. */
export function keccak256(data: Uint8Array | string): string {
  const bytes = typeof data === "string"
    ? (data.startsWith("0x") ? hexToBytes(data) : new TextEncoder().encode(data))
    : data;
  return toHex(keccak_256(bytes));
}

/** Derive EVM address from secp256k1 private key  uses keccak256, not SHA-256. */
export function evmAddressFromKey(privateKey: Uint8Array | string): string {
  const key = typeof privateKey === "string"
    ? hexToBytes(privateKey.replace("0x",""))
    : privateKey;
  const pub  = secp256k1.getPublicKey(key, false);  // 65-byte uncompressed
  const hash = keccak_256(pub.slice(1));             // keccak256 of 64-byte pub
  return "0x" + toHex(hash).slice(-40);
}

export async function sha256(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const hash  = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(hash));
}

export async function sha256Raw(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const hash  = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(hash);
}

//  HMAC-SHA-256 

export async function hmac256(secret: string, data: string): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", keyMaterial, encoder.encode(data));
  return toHex(new Uint8Array(sig));
}

export async function hmac256Verify(
  secret: string, data: string, expectedHex: string
): Promise<boolean> {
  const actual = await hmac256(secret, data);
  // Constant-time comparison
  if (actual.length !== expectedHex.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) {
    diff |= actual.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  }
  return diff === 0;
}

//  Ed25519 Node Identity 

export async function generateNodeKeyPair(): Promise<NodeKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );

  const [pubRaw, privRaw] = await Promise.all([
    crypto.subtle.exportKey("raw",  keyPair.publicKey),
    crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  ]);

  const publicKey  = new Uint8Array(pubRaw);
  const privateKey = new Uint8Array(privRaw);

  return { publicKey, privateKey, publicKeyHex: toHex(publicKey) };
}

export async function signEd25519(privateKeyBytes: Uint8Array, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8", privateKeyBytes,
    { name: "Ed25519" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("Ed25519", key, encoder.encode(data));
  return toHex(new Uint8Array(sig));
}

export async function verifyEd25519(
  publicKeyBytes: Uint8Array,
  signature: string,
  data: string
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw", publicKeyBytes,
      { name: "Ed25519" },
      false, ["verify"]
    );
    return await crypto.subtle.verify(
      "Ed25519", key, fromHex(signature), encoder.encode(data)
    );
  } catch {
    return false;
  }
}

//  AES-256-GCM (secrets at rest) 

export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310_000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

export async function encryptAES(plaintext: string, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const ct   = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(plaintext)
  );
  // Format: base64(salt || iv || ciphertext)
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt,                0);
  combined.set(iv,                  salt.length);
  combined.set(new Uint8Array(ct),  salt.length + iv.length);
  return toBase64(combined);
}

export async function decryptAES(ciphertext: string, password: string): Promise<string> {
  const combined = fromBase64(ciphertext);
  const salt = combined.slice(0, 16);
  const iv   = combined.slice(16, 28);
  const ct   = combined.slice(28);
  const key  = await deriveKey(password, salt);
  const pt   = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt);
}

//  Merkle Tree 

export class MerkleTree {
  private leaves: string[] = [];

  constructor(items: string[]) {
    this.leaves = items;
  }

  /** Build and return the Merkle root */
  async root(): Promise<string> {
    if (this.leaves.length === 0) return sha256("empty");
    let nodes = await Promise.all(this.leaves.map(l => sha256(l)));
    while (nodes.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const left  = nodes[i];
        const right = nodes[i + 1] ?? nodes[i]; // duplicate last if odd
        next.push(await sha256(left + right));
      }
      nodes = next;
    }
    return nodes[0];
  }

  /** Generate inclusion proof for leaf at index */
  async proof(index: number): Promise<MerkleProof> {
    if (index >= this.leaves.length) throw new Error("Index out of range");

    let nodes = await Promise.all(this.leaves.map(l => sha256(l)));
    const leaf = nodes[index];
    const proofSteps: MerkleProof["proof"] = [];
    let idx = index;

    while (nodes.length > 1) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      const sibling    = nodes[siblingIdx] ?? nodes[idx];
      proofSteps.push({
        sibling,
        direction: idx % 2 === 0 ? "right" : "left",
      });

      const next: string[] = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const l = nodes[i];
        const r = nodes[i + 1] ?? nodes[i];
        next.push(await sha256(l + r));
      }
      nodes = next;
      idx = Math.floor(idx / 2);
    }

    return { root: nodes[0], leaf, proof: proofSteps };
  }

  /** Verify an inclusion proof */
  static async verifyProof(proof: MerkleProof): Promise<boolean> {
    let current = proof.leaf;
    for (const step of proof.proof) {
      current = step.direction === "right"
        ? await sha256(current + step.sibling)
        : await sha256(step.sibling + current);
    }
    return current === proof.root;
  }
}

// -- Constant-time string comparison ------------------------------------------
// Prevents timing attacks on token/secret comparisons.

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// -- Safe JSON parse (returns fallback on corrupt data) -----------------------

export function safeJsonParse<T = any>(str: string | null | undefined, fallback: T): T {
  if (!str) return fallback;
  try { return JSON.parse(str); } catch { return fallback; }
}
