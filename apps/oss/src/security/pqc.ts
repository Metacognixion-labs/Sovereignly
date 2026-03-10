/**
 * Sovereignly v4.0 — Post-Quantum Cryptography Layer
 *
 * Hybrid classical + post-quantum cryptographic operations.
 * Uses @noble/post-quantum (pure JS, audited, zero native deps).
 *
 * Strategy: Every operation produces BOTH a classical and PQC result.
 * Verification requires BOTH to pass. Security holds if EITHER algorithm
 * remains unbroken.
 *
 * Algorithms:
 *   Signatures:  Ed25519 + ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204 Level 3)
 *   Hashing:     SHA-256 + SHA3-256 (dual Merkle roots)
 *   KDF:         PBKDF2-SHA256 (existing) — acceptable post-quantum
 *   Encryption:  AES-256-GCM (existing) — 128-bit post-quantum security
 *
 * The ML-KEM (Kyber) key encapsulation is included for future cluster P2P.
 */

import { sha3_256 } from "@noble/hashes/sha3";
import { ml_dsa65 }  from "@noble/post-quantum/ml-dsa";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { toHex, fromHex } from "./crypto.ts";

// ── Types ───────────────────────────────────────────────────────────────────

export interface HybridKeyBundle {
  ed25519: {
    publicKey:  Uint8Array;   // 32 bytes
    privateKey: Uint8Array;   // PKCS8 (variable)
    publicKeyHex: string;
  };
  mlDsa65: {
    publicKey:  Uint8Array;   // 1952 bytes
    secretKey:  Uint8Array;   // 4032 bytes
    publicKeyHex: string;
  };
  algorithm: "hybrid-ed25519-mldsa65";
  createdAt: number;
}

export interface HybridSignature {
  ed25519:   string;    // hex
  mlDsa65:   string;    // hex
  algorithm: "hybrid-ed25519-mldsa65";
}

export interface HybridVerification {
  valid:          boolean;
  ed25519Valid:   boolean;
  mlDsa65Valid:   boolean;
}

export interface KEMKeyPair {
  publicKey:  Uint8Array;   // 1184 bytes
  secretKey:  Uint8Array;   // 2400 bytes
}

export interface KEMEncapsulation {
  ciphertext:  Uint8Array;   // 1088 bytes
  sharedSecret: Uint8Array;  // 32 bytes
}

// ── SHA3-256 ────────────────────────────────────────────────────────────────

const encoder = new TextEncoder();

/** SHA3-256 hash (Keccak sponge, different construction from SHA-2) */
export function sha3Hash(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return toHex(sha3_256(bytes));
}

/** SHA3-256 hash returning raw bytes */
export function sha3HashRaw(data: string | Uint8Array): Uint8Array {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return sha3_256(bytes);
}

// ── Hybrid Signature (Ed25519 + ML-DSA-65) ──────────────────────────────────

export class HybridSigner {
  /**
   * Generate a hybrid keypair bundle.
   * Ed25519 via Web Crypto API + ML-DSA-65 via @noble/post-quantum.
   */
  static async generateKeyBundle(): Promise<HybridKeyBundle> {
    // Ed25519 keypair (Web Crypto)
    const ed25519KeyPair = await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    );
    const [pubRaw, privRaw] = await Promise.all([
      crypto.subtle.exportKey("raw", ed25519KeyPair.publicKey),
      crypto.subtle.exportKey("pkcs8", ed25519KeyPair.privateKey),
    ]);

    // ML-DSA-65 keypair (post-quantum)
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const mlKeys = ml_dsa65.keygen(seed);

    return {
      ed25519: {
        publicKey: new Uint8Array(pubRaw),
        privateKey: new Uint8Array(privRaw),
        publicKeyHex: toHex(new Uint8Array(pubRaw)),
      },
      mlDsa65: {
        publicKey: mlKeys.publicKey,
        secretKey: mlKeys.secretKey,
        publicKeyHex: toHex(mlKeys.publicKey).slice(0, 64) + "...",  // Truncated for display
      },
      algorithm: "hybrid-ed25519-mldsa65",
      createdAt: Date.now(),
    };
  }

  /**
   * Sign a message with both Ed25519 and ML-DSA-65.
   * Both signatures must verify for the hybrid to be valid.
   */
  static async sign(
    message:     string,
    ed25519Key:  Uint8Array,
    mlDsa65Key:  Uint8Array,
  ): Promise<HybridSignature> {
    const msgBytes = encoder.encode(message);

    // Ed25519 signature (Web Crypto)
    const ed25519CryptoKey = await crypto.subtle.importKey(
      "pkcs8", ed25519Key,
      { name: "Ed25519" },
      false, ["sign"]
    );
    const ed25519Sig = await crypto.subtle.sign("Ed25519", ed25519CryptoKey, msgBytes);

    // ML-DSA-65 signature (post-quantum)
    const mlDsaSig = ml_dsa65.sign(mlDsa65Key, msgBytes);

    return {
      ed25519:   toHex(new Uint8Array(ed25519Sig)),
      mlDsa65:   toHex(mlDsaSig),
      algorithm: "hybrid-ed25519-mldsa65",
    };
  }

  /**
   * Verify a hybrid signature. BOTH must pass.
   */
  static async verify(
    message:       string,
    sig:           HybridSignature,
    ed25519PubKey: Uint8Array,
    mlDsa65PubKey: Uint8Array,
  ): Promise<HybridVerification> {
    const msgBytes = encoder.encode(message);

    // Ed25519 verification
    let ed25519Valid = false;
    try {
      const pubCryptoKey = await crypto.subtle.importKey(
        "raw", ed25519PubKey,
        { name: "Ed25519" },
        false, ["verify"]
      );
      ed25519Valid = await crypto.subtle.verify(
        "Ed25519", pubCryptoKey, fromHex(sig.ed25519), msgBytes
      );
    } catch {
      ed25519Valid = false;
    }

    // ML-DSA-65 verification
    let mlDsa65Valid = false;
    try {
      mlDsa65Valid = ml_dsa65.verify(mlDsa65PubKey, msgBytes, fromHex(sig.mlDsa65));
    } catch {
      mlDsa65Valid = false;
    }

    return {
      valid: ed25519Valid && mlDsa65Valid,
      ed25519Valid,
      mlDsa65Valid,
    };
  }
}

// ── ML-KEM-768 Key Encapsulation (for future cluster P2P) ──────────────────

export class HybridKEM {
  /** Generate ML-KEM-768 keypair */
  static generateKeyPair(): KEMKeyPair {
    const seed = new Uint8Array(64);
    crypto.getRandomValues(seed);
    const keys = ml_kem768.keygen(seed);
    return {
      publicKey: keys.publicKey,
      secretKey: keys.secretKey,
    };
  }

  /** Encapsulate: generate shared secret + ciphertext from public key */
  static encapsulate(publicKey: Uint8Array): KEMEncapsulation {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const result = ml_kem768.encapsulate(publicKey, seed);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret,
    };
  }

  /** Decapsulate: recover shared secret from ciphertext + secret key */
  static decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(ciphertext, secretKey);
  }
}

// ── Dual Merkle Root (SHA-256 + SHA3-256) ───────────────────────────────────

export class DualMerkleTree {
  private leaves: string[];

  constructor(items: string[]) {
    this.leaves = items;
  }

  /** Build dual Merkle root: { sha256, sha3 } */
  async dualRoot(): Promise<{ sha256: string; sha3: string }> {
    const sha256Root = await this.buildRoot("sha256");
    const sha3Root   = await this.buildRoot("sha3");
    return { sha256: sha256Root, sha3: sha3Root };
  }

  private async buildRoot(algo: "sha256" | "sha3"): Promise<string> {
    const hash = algo === "sha256"
      ? async (d: string) => {
          const h = await crypto.subtle.digest("SHA-256", encoder.encode(d));
          return toHex(new Uint8Array(h));
        }
      : async (d: string) => sha3Hash(d);

    if (this.leaves.length === 0) return hash("empty");

    let nodes = await Promise.all(this.leaves.map(l => hash(l)));
    while (nodes.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const left  = nodes[i];
        const right = nodes[i + 1] ?? nodes[i];
        next.push(await hash(left + right));
      }
      nodes = next;
    }
    return nodes[0];
  }
}

// ── HMAC-SHA3-256 ───────────────────────────────────────────────────────────

/** HMAC-SHA3-256 for JWT signing and webhook verification */
export function hmacSha3(key: string | Uint8Array, data: string | Uint8Array): string {
  const keyBytes  = typeof key === "string"  ? encoder.encode(key)  : key;
  const dataBytes = typeof data === "string" ? encoder.encode(data) : data;

  // HMAC construction: H((K ^ opad) || H((K ^ ipad) || message))
  const blockSize = 136;  // SHA3-256 rate
  let keyBlock = new Uint8Array(blockSize);

  if (keyBytes.length > blockSize) {
    keyBlock.set(sha3_256(keyBytes));
  } else {
    keyBlock.set(keyBytes);
  }

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5C;
  }

  const innerData = new Uint8Array(blockSize + dataBytes.length);
  innerData.set(ipad);
  innerData.set(dataBytes, blockSize);
  const innerHash = sha3_256(innerData);

  const outerData = new Uint8Array(blockSize + innerHash.length);
  outerData.set(opad);
  outerData.set(innerHash, blockSize);

  return toHex(sha3_256(outerData));
}
