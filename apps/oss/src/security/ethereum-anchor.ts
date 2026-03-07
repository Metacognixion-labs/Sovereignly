/**
 * Sovereignly v3  EthereumAnchor (Retained for AuditAnchor.sol selectors)
 *
 * @deprecated  This module is NOT used in v3. OmnichainAnchor replaces it.
 *
 * WHY KEPT:
 *   - The AuditAnchor.sol contract is still optionally deployable to Base.
 *   - The integration tests verify its selectors (0x001648c0, 0xf32bd282).
 *   - Remove in v4 if contract-based anchoring is fully retired.
 *
 * v3 anchoring uses EAS (Ethereum Attestation Standard) contracts already
 * deployed on Base, Arbitrum, Optimism, and other chains:
 *    No custom contract deployment needed
 *    $0.63/yr at Growth tier vs $876/yr on Ethereum mainnet (99.93%)
 *    Schema UID: 0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc
 *
 * See: src/security/omnichain-anchor.ts (active)
 *
 * Original architecture (v2  Ethereum mainnet custom contract):
 *   SovereignChain block N (N % 1000 === 0)
 *      TenantManager.buildGlobalRoot()
 *      root-of-roots (Merkle over all tenant tips)
 *      EthereumAnchor.anchor(root, blockIdx, tenantCount)   this file
 *      eth_sendRawTransaction to Ethereum mainnet           replaced by EAS
 *
 * Wallet management:
 *   Uses a dedicated signing wallet (not the same as Meridian wallet).
 *   Private key in ETHEREUM_ANCHOR_KEY env var.
 *   Keep minimal ETH balance (~0.01 ETH, top up monthly).
 */

import { sha256Raw } from "../security/crypto.ts";

//  Types 

export interface AnchorResult {
  txHash:        string;
  blockNumber?:  number;
  gasUsed?:      number;
  merkleRoot:    string;
  chainBlockIdx: number;
  tenantCount:   number;
  network:       "ethereum" | "meridian" | "sepolia";
  timestamp:     number;
}

export interface EthereumAnchorConfig {
  rpcUrl:           string;    // Ethereum JSON-RPC (Infura, Alchemy, local node)
  contractAddress:  string;    // AuditAnchor.sol on Ethereum mainnet
  privateKey:       string;    // hex, 0x-prefixed
  network?:         "mainnet" | "sepolia" | "custom";
  chainId?:         number;    // 1=mainnet, 11155111=sepolia
  gasLimit?:        number;    // default 120000 (buffer above 90k estimate)
  maxFeePerGas?:    bigint;    // EIP-1559 in wei
  maxPriorityFee?:  bigint;    // EIP-1559 tip in wei
}

//  Minimal secp256k1 + RLP for raw transaction signing 
// We don't want ethers.js  that's 800KB.
// We use @noble/curves (already our dep) for secp256k1 signing.

async function signTransaction(
  tx:         EIP1559Transaction,
  privateKey: string
): Promise<string> {
  const { secp256k1 } = await import("@noble/curves/secp256k1");

  const privKeyBytes = hexToBytes(privateKey.replace("0x", ""));

  // Encode for signing: keccak256(rlp([chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, [], []]))
  const encoded = rlpEncode([
    numberToHex(tx.chainId),
    numberToHex(tx.nonce),
    numberToHex(tx.maxPriorityFeePerGas),
    numberToHex(tx.maxFeePerGas),
    numberToHex(tx.gasLimit),
    tx.to,
    "0x",           // value = 0
    tx.data,
    [],             // accessList
  ]);

  const hash    = await keccak256(concat([new Uint8Array([2]), rlpToBytes(encoded)]));
  const sig     = secp256k1.sign(hash, privKeyBytes);

  // EIP-1559 signed tx: 0x02 || rlp([chainId, nonce, ..., v, r, s])
  const signed = rlpEncode([
    numberToHex(tx.chainId),
    numberToHex(tx.nonce),
    numberToHex(tx.maxPriorityFeePerGas),
    numberToHex(tx.maxFeePerGas),
    numberToHex(tx.gasLimit),
    tx.to,
    "0x",
    tx.data,
    [],
    numberToHex(sig.recovery),
    "0x" + sig.r.toString(16).padStart(64, "0"),
    "0x" + sig.s.toString(16).padStart(64, "0"),
  ]);

  return "0x02" + bytesToHex(rlpToBytes(signed));
}

interface EIP1559Transaction {
  chainId:             number;
  nonce:               number;
  maxFeePerGas:        bigint;
  maxPriorityFeePerGas:bigint;
  gasLimit:            number;
  to:                  string;
  data:                string;
}

//  ABI encoding for auditAnchor(bytes32, uint256, uint32) 

function encodeAuditAnchor(
  merkleRoot:    string,   // 0x hex
  chainBlockIdx: number,
  tenantCount:   number
): string {
  // Function selector: keccak256("auditAnchor(bytes32,uint256,uint32)")[0:4]
  const selector = "0x001648c0";   // keccak256("auditAnchor(bytes32,uint256,uint32)")[0:4]

  const root    = merkleRoot.replace("0x", "").padStart(64, "0");
  const blockN  = chainBlockIdx.toString(16).padStart(64, "0");
  const tenants = tenantCount.toString(16).padStart(64, "0");

  return selector + root + blockN + tenants;
}

//  Minimal keccak256 using @noble/curves internals 

async function keccak256(data: Uint8Array): Promise<Uint8Array> {
  const { keccak_256 } = await import("@noble/hashes/sha3").catch(async () => {
    // Fallback: dynamic import
    return { keccak_256: null as any };
  }) as any;
  if (!keccak_256) throw new Error("@noble/hashes not available  add to package.json");
  return keccak_256(data);
}

//  Minimal RLP (recursive length prefix) 

function rlpEncode(items: any[]): any[] { return items; }  // placeholder structural
function rlpToBytes(items: any[]): Uint8Array {
  // Real RLP encoding
  const encoded = encodeRLP(items);
  return encoded;
}

function encodeRLP(input: any): Uint8Array {
  if (Array.isArray(input)) {
    const parts = input.map(encodeRLP);
    const total = parts.reduce((s, p) => s + p.length, 0);
    const header = rlpHeader(total, 0xc0);
    const result = new Uint8Array(header.length + total);
    let offset = 0;
    result.set(header, offset); offset += header.length;
    for (const p of parts) { result.set(p, offset); offset += p.length; }
    return result;
  }
  if (typeof input === "string") {
    if (input === "0x" || input === "") return new Uint8Array([0x80]);
    const bytes = hexToBytes(input.startsWith("0x") ? input.slice(2) : input);
    if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
    const header = rlpHeader(bytes.length, 0x80);
    const result = new Uint8Array(header.length + bytes.length);
    result.set(header); result.set(bytes, header.length);
    return result;
  }
  return new Uint8Array([0x80]);
}

function rlpHeader(length: number, offset: number): Uint8Array {
  if (length < 56) return new Uint8Array([offset + length]);
  const hex  = length.toString(16);
  const len  = Math.ceil(hex.length / 2);
  const head = new Uint8Array(1 + len);
  head[0] = offset + 55 + len;
  for (let i = 0; i < len; i++) {
    head[1 + i] = parseInt(hex.slice(i * 2, i * 2 + 2) || "0", 16);
  }
  return head;
}

//  Hex/bytes helpers 

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.length % 2 ? "0" + clean : clean;
  return Uint8Array.from(padded.match(/.{2}/g)!.map(b => parseInt(b, 16)));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function numberToHex(n: number | bigint): string {
  if (n === 0 || n === 0n) return "0x";
  const hex = n.toString(16);
  return "0x" + (hex.length % 2 ? "0" + hex : hex);
}

function concat(arrays: Uint8Array[]): Uint8Array {
  const total  = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset   = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

//  Address derivation from private key 

async function privateKeyToAddress(privateKey: string): Promise<string> {
  const { secp256k1 } = await import("@noble/curves/secp256k1");
  const privBytes  = hexToBytes(privateKey.replace("0x", ""));
  const pubKeyFull = secp256k1.getPublicKey(privBytes, false); // uncompressed 65 bytes
  const pubHash    = await keccak256(pubKeyFull.slice(1));     // keccak of 64 bytes
  return "0x" + bytesToHex(pubHash.slice(-20));
}

//  EthereumAnchor 

export class EthereumAnchor {
  private cfg:     EthereumAnchorConfig;
  private address: string = "";
  private nonce:   number = 0;

  constructor(cfg: EthereumAnchorConfig) {
    this.cfg = {
      network:       "mainnet",
      chainId:       1,
      gasLimit:      120_000,
      maxFeePerGas:  20_000_000_000n, // 20 gwei (overridden by fee fetch)
      maxPriorityFee: 1_500_000_000n, // 1.5 gwei tip
      ...cfg,
    };
    if (cfg.network === "sepolia") this.cfg.chainId = 11155111;
  }

  async init(): Promise<void> {
    this.address = await privateKeyToAddress(this.cfg.privateKey);
    this.nonce   = await this.fetchNonce();
    console.log(`[EthAnchor] Wallet: ${this.address} (${this.cfg.network})`);
    const balance = await this.fetchBalance();
    const ethBalance = Number(balance) / 1e18;
    console.log(`[EthAnchor] Balance: ${ethBalance.toFixed(4)} ETH`);
    if (ethBalance < 0.005) {
      console.warn(`[EthAnchor]  Low ETH balance. Top up ${this.address} on ${this.cfg.network}`);
    }
  }

  //  Primary anchor call 

  async anchor(opts: {
    merkleRoot:    string;   // 0x-prefixed hex, 32 bytes
    chainBlockIdx: number;
    tenantCount:   number;
  }): Promise<AnchorResult> {
    // Fetch current gas price
    const { maxFeePerGas, maxPriorityFeePerGas } = await this.fetchGasFees();

    // Encode the auditAnchor function call
    const data = encodeAuditAnchor(opts.merkleRoot, opts.chainBlockIdx, opts.tenantCount);

    const tx: EIP1559Transaction = {
      chainId:              this.cfg.chainId!,
      nonce:                this.nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
      gasLimit:             this.cfg.gasLimit!,
      to:                   this.cfg.contractAddress,
      data,
    };

    // Sign and broadcast
    const rawTx = await signTransaction(tx, this.cfg.privateKey);
    const txHash = await this.sendRawTransaction(rawTx);

    this.nonce++; // optimistic nonce increment

    const result: AnchorResult = {
      txHash,
      merkleRoot:    opts.merkleRoot,
      chainBlockIdx: opts.chainBlockIdx,
      tenantCount:   opts.tenantCount,
      network:       this.cfg.network === "sepolia" ? "sepolia" : "ethereum",
      timestamp:     Date.now(),
    };

    console.log(
      `[EthAnchor]  Anchored block #${opts.chainBlockIdx} to ${this.cfg.network}`,
      `\n  tx:   ${txHash}`,
      `\n  root: ${opts.merkleRoot}`,
      `\n  tenants: ${opts.tenantCount}`,
    );

    return result;
  }

  //  Wait for confirmation 

  async waitForConfirmation(txHash: string, confirmations = 1): Promise<{
    blockNumber: number;
    gasUsed:     number;
    status:      "success" | "reverted";
  }> {
    const maxAttempts = 60; // ~5 minutes
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(r => setTimeout(r, 5_000));

      const receipt = await this.call("eth_getTransactionReceipt", [txHash]);
      if (!receipt || !receipt.blockNumber) continue;

      const currentBlock = await this.call("eth_blockNumber", []);
      const txBlock      = parseInt(receipt.blockNumber, 16);
      const current      = parseInt(currentBlock, 16);

      if (current - txBlock >= confirmations) {
        return {
          blockNumber: txBlock,
          gasUsed:     parseInt(receipt.gasUsed, 16),
          status:      receipt.status === "0x1" ? "success" : "reverted",
        };
      }
    }
    throw new Error(`Transaction ${txHash} not confirmed after ${maxAttempts} attempts`);
  }

  //  Verification (public, no auth) 

  async verifyAnchor(merkleRoot: string): Promise<{
    exists:       boolean;
    chainBlockIdx?: number;
    anchoredAt?:   number;
    txHash?:      string;
  }> {
    // Call verifyAnchor(bytes32) on the contract
    const selector  = "0xf32bd282"; // keccak256("verifyAnchor(bytes32)")[0:4]
    const data      = selector + merkleRoot.replace("0x", "").padStart(64, "0");

    try {
      const result = await this.call("eth_call", [{
        to:   this.cfg.contractAddress,
        data,
      }, "latest"]);

      if (!result || result === "0x") return { exists: false };

      // Decode bool + Anchor struct
      const exists = parseInt(result.slice(2, 66), 16) === 1;
      if (!exists) return { exists: false };

      const chainBlockIdx = parseInt(result.slice(66, 130), 16);
      const anchoredAt    = parseInt(result.slice(130, 194), 16) * 1000; // to ms

      return { exists: true, chainBlockIdx, anchoredAt };
    } catch {
      return { exists: false };
    }
  }

  //  JSON-RPC helpers 

  private async call(method: string, params: any[]): Promise<any> {
    const res = await fetch(this.cfg.rpcUrl, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal:  AbortSignal.timeout(15_000),
    });
    const data = await res.json();
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    return data.result;
  }

  private async sendRawTransaction(rawTx: string): Promise<string> {
    return this.call("eth_sendRawTransaction", [rawTx]);
  }

  private async fetchNonce(): Promise<number> {
    const result = await this.call("eth_getTransactionCount", [this.address, "pending"]);
    return parseInt(result, 16);
  }

  private async fetchBalance(): Promise<bigint> {
    const result = await this.call("eth_getBalance", [this.address, "latest"]);
    return BigInt(result);
  }

  private async fetchGasFees(): Promise<{
    maxFeePerGas:        bigint;
    maxPriorityFeePerGas: bigint;
  }> {
    try {
      const fee = await this.call("eth_feeHistory", ["0x1", "latest", [50]]);
      const base = BigInt(fee.baseFeePerGas?.[0] ?? "0x5f5e100");
      const tip  = BigInt(fee.reward?.[0]?.[0]   ?? "0x59682f00");
      return {
        maxFeePerGas:         base * 2n + tip,
        maxPriorityFeePerGas: tip,
      };
    } catch {
      return {
        maxFeePerGas:         this.cfg.maxFeePerGas!,
        maxPriorityFeePerGas: this.cfg.maxPriorityFee!,
      };
    }
  }

  getAddress(): string { return this.address; }
}
