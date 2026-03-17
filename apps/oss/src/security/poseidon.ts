/**
 * Poseidon Hash — ZK-Friendly Hash Function
 *
 * Minimal implementation of Poseidon hash for BN254 (alt_bn128) field.
 * Uses the HADES design strategy with partial rounds for efficiency.
 *
 * Why Poseidon:
 *   - 8x fewer constraints per bit than Pedersen in ZK circuits
 *   - Enables zero-knowledge proofs of event inclusion WITHOUT revealing contents
 *   - Auditors can verify Merkle membership in a ZK proof
 *
 * This is a simplified implementation suitable for:
 *   - ZK-ready Merkle tree construction
 *   - Future integration with Circom/Noir ZK provers
 *   - Dual-root chains (SHA-256 for compatibility + Poseidon for ZK)
 *
 * Parameters: t=3, nRoundsF=8, nRoundsP=57 (BN254)
 *
 * References:
 *   https://www.poseidon-hash.info/
 *   https://eprint.iacr.org/2019/458.pdf
 */

// BN254 prime field modulus
const F_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Poseidon parameters for t=3 (2 inputs + 1 capacity element)
const T = 3;
const N_ROUNDS_F = 8;   // full rounds
const N_ROUNDS_P = 57;  // partial rounds
const ALPHA = 5n;        // S-box exponent (x^5)

// Pre-computed round constants (first 195 constants for t=3)
// Generated from Grain LFSR with seed "poseidon_constants_bn254_t3"
// For production: use the full constant set from the Poseidon paper
// Here we use a deterministic derivation from SHA-256 for reproducibility
const roundConstants: bigint[] = [];
const mdsMatrix: bigint[][] = [];

// Initialize constants deterministically (SHA-256 based PRNG)
async function initConstants(): Promise<void> {
  if (roundConstants.length > 0) return;

  // Generate round constants from seed
  const seed = new TextEncoder().encode("poseidon_sovereign_bn254_t3_v1");
  let state = new Uint8Array(
    await crypto.subtle.digest("SHA-256", seed)
  );

  const totalConstants = T * (N_ROUNDS_F + N_ROUNDS_P);
  for (let i = 0; i < totalConstants; i++) {
    state = new Uint8Array(
      await crypto.subtle.digest("SHA-256", state)
    );
    // Convert 32 bytes to field element
    let val = 0n;
    for (let j = 0; j < 32; j++) {
      val = (val << 8n) | BigInt(state[j]);
    }
    roundConstants.push(val % F_P);
  }

  // Generate MDS matrix (Cauchy construction)
  // For t=3: use x_i = i, y_j = t + j
  for (let i = 0; i < T; i++) {
    mdsMatrix.push([]);
    for (let j = 0; j < T; j++) {
      // 1 / (x_i + y_j) mod p
      const sum = (BigInt(i) + BigInt(T + j)) % F_P;
      mdsMatrix[i].push(modInverse(sum, F_P));
    }
  }
}

// Modular inverse using extended Euclidean algorithm
function modInverse(a: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m;
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

// Field arithmetic
function addMod(a: bigint, b: bigint): bigint { return (a + b) % F_P; }
function mulMod(a: bigint, b: bigint): bigint { return (a * b) % F_P; }
function powMod(base: bigint, exp: bigint): bigint {
  let result = 1n;
  base = base % F_P;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = mulMod(result, base);
    exp = exp / 2n;
    base = mulMod(base, base);
  }
  return result;
}

// S-box: x^5 mod p
function sBox(x: bigint): bigint { return powMod(x, ALPHA); }

// MDS matrix multiplication
function mdsMultiply(state: bigint[]): bigint[] {
  const result = new Array(T).fill(0n);
  for (let i = 0; i < T; i++) {
    for (let j = 0; j < T; j++) {
      result[i] = addMod(result[i], mulMod(mdsMatrix[i][j], state[j]));
    }
  }
  return result;
}

// -- Poseidon Permutation -----------------------------------------------------

function poseidonPermutation(state: bigint[]): bigint[] {
  let s = [...state];
  let rcIdx = 0;

  // First half of full rounds
  for (let r = 0; r < N_ROUNDS_F / 2; r++) {
    // Add round constants
    for (let i = 0; i < T; i++) s[i] = addMod(s[i], roundConstants[rcIdx++]);
    // Full S-box
    for (let i = 0; i < T; i++) s[i] = sBox(s[i]);
    // MDS
    s = mdsMultiply(s);
  }

  // Partial rounds (S-box only on first element)
  for (let r = 0; r < N_ROUNDS_P; r++) {
    for (let i = 0; i < T; i++) s[i] = addMod(s[i], roundConstants[rcIdx++]);
    s[0] = sBox(s[0]); // only first element
    s = mdsMultiply(s);
  }

  // Second half of full rounds
  for (let r = 0; r < N_ROUNDS_F / 2; r++) {
    for (let i = 0; i < T; i++) s[i] = addMod(s[i], roundConstants[rcIdx++]);
    for (let i = 0; i < T; i++) s[i] = sBox(s[i]);
    s = mdsMultiply(s);
  }

  return s;
}

// -- Public API ---------------------------------------------------------------

/** Initialize Poseidon constants (must be called once before use) */
export async function initPoseidon(): Promise<void> {
  await initConstants();
}

/** Hash two field elements → one field element */
export function poseidonHash2(a: bigint, b: bigint): bigint {
  if (roundConstants.length === 0) {
    throw new Error("Poseidon not initialized. Call initPoseidon() first.");
  }
  // Sponge: [capacity=0, a, b] → permute → output[0]
  const state = poseidonPermutation([0n, a % F_P, b % F_P]);
  return state[0];
}

/** Hash a string by converting to field element first */
export async function poseidonHashString(input: string): Promise<string> {
  await initPoseidon();
  // Convert string to two field elements via SHA-256
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input))
  );
  const a = bytesToBigInt(hash.slice(0, 16)) % F_P;
  const b = bytesToBigInt(hash.slice(16, 32)) % F_P;
  const result = poseidonHash2(a, b);
  return result.toString(16).padStart(64, "0");
}

/** Hash for Merkle tree: combine two hashes */
export function poseidonMerkleHash(left: string, right: string): string {
  const a = BigInt("0x" + left) % F_P;
  const b = BigInt("0x" + right) % F_P;
  const result = poseidonHash2(a, b);
  return result.toString(16).padStart(64, "0");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let val = 0n;
  for (const b of bytes) val = (val << 8n) | BigInt(b);
  return val;
}

// -- ZK-Ready Incremental Merkle Tree -----------------------------------------

export class PoseidonMerkleTree {
  private frontier: string[];
  private depth: number;
  private count = 0;
  private zeroHashes: string[];

  constructor(maxDepth = 20) {
    this.depth = maxDepth;
    this.frontier = new Array(maxDepth).fill("");

    // Pre-compute zero hashes: z[0] = "0"*64, z[i] = poseidon(z[i-1], z[i-1])
    this.zeroHashes = new Array(maxDepth);
    this.zeroHashes[0] = "0".repeat(64);
    for (let i = 1; i < maxDepth; i++) {
      this.zeroHashes[i] = poseidonMerkleHash(this.zeroHashes[i - 1], this.zeroHashes[i - 1]);
    }
  }

  /** Insert a leaf and return the new root */
  insert(leafHash: string): string {
    let current = leafHash;
    let idx = this.count;

    for (let level = 0; level < this.depth; level++) {
      if (idx % 2 === 0) {
        this.frontier[level] = current;
        current = poseidonMerkleHash(current, this.zeroHashes[level]);
      } else {
        current = poseidonMerkleHash(this.frontier[level], current);
      }
      idx = Math.floor(idx / 2);
    }

    this.count++;
    return current;
  }

  /** Batch insert, return final root */
  insertBatch(leaves: string[]): string {
    let root = "";
    for (const leaf of leaves) root = this.insert(leaf);
    return root;
  }

  get size(): number { return this.count; }
}
