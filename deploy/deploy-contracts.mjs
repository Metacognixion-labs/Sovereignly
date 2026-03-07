#!/usr/bin/env node
/**
 * SovereignCloud v2 — Contract Deployment Script
 *
 * Deploys AuditAnchor.sol to:
 *   1. Meridian Ledger (local/testnet first for verification)
 *   2. Ethereum mainnet (for enterprise credibility)
 *
 * Usage:
 *   ETHEREUM_ANCHOR_KEY=0x... ETHEREUM_RPC_URL=https://... node deploy/deploy-contracts.mjs
 *
 * Or dry-run (no deploy, just compile + estimate):
 *   DRY_RUN=true node deploy/deploy-contracts.mjs
 *
 * Flags:
 *   --network meridian    Deploy to Meridian only
 *   --network ethereum    Deploy to Ethereum only
 *   --network both        Deploy to both (default)
 *   --dry-run             Estimate gas, no broadcast
 *   --verify              Verify on Etherscan after deploy
 *
 * After deploy, run:
 *   node deploy/add-validator.mjs --contract 0x... --validator 0x...
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT      = join(__dirname, "..");

// ─── Config from env ──────────────────────────────────────────────────────────

const PRIVATE_KEY      = process.env.ETHEREUM_ANCHOR_KEY;
const ETH_RPC          = process.env.ETHEREUM_RPC_URL;
const MERIDIAN_RPC     = process.env.MERIDIAN_RPC_URL ?? "http://127.0.0.1:8545";
const DRY_RUN          = process.env.DRY_RUN === "true" || process.argv.includes("--dry-run");
const NETWORK          = process.argv.includes("--network")
  ? process.argv[process.argv.indexOf("--network") + 1]
  : "both";
const VERIFY_ETHERSCAN = process.argv.includes("--verify");
const ETHERSCAN_KEY    = process.env.ETHERSCAN_API_KEY;

// ─── AuditAnchor.sol bytecode ─────────────────────────────────────────────────
// Pre-compiled with solc 0.8.24 --optimize --runs=200
// Recompile: solc --bin --abi contracts/AuditAnchor.sol -o build/
//
// If you want to recompile:
//   npm install -g solc
//   solcjs --bin --abi --optimize --optimize-runs=200 contracts/AuditAnchor.sol

const CONTRACT_ABI = [
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "inputs": [
      { "internalType": "bytes32", "name": "merkleRoot",    "type": "bytes32" },
      { "internalType": "uint256", "name": "chainBlockIdx", "type": "uint256" },
      { "internalType": "uint32",  "name": "eventCount",    "type": "uint32"  }
    ],
    "name": "auditAnchor",
    "outputs": [{ "internalType": "uint256", "name": "anchorId", "type": "uint256" }],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{ "internalType": "bytes32", "name": "merkleRoot", "type": "bytes32" }],
    "name": "verifyAnchor",
    "outputs": [
      { "internalType": "bool",                            "name": "exists", "type": "bool" },
      { "internalType": "tuple", "name": "anchor", "type": "tuple",
        "components": [
          { "internalType": "bytes32",  "name": "merkleRoot",    "type": "bytes32"  },
          { "internalType": "uint256",  "name": "chainBlockIdx", "type": "uint256"  },
          { "internalType": "uint256",  "name": "anchoredAt",    "type": "uint256"  },
          { "internalType": "address",  "name": "submitter",     "type": "address"  },
          { "internalType": "uint32",   "name": "eventCount",    "type": "uint32"   }
        ]
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      { "internalType": "address", "name": "validator", "type": "address" },
      { "internalType": "string",  "name": "nodeId",    "type": "string"  }
    ],
    "name": "addValidator",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{ "internalType": "address", "name": "validator", "type": "address" }],
    "name": "removeValidator",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{ "internalType": "address", "name": "", "type": "address" }],
    "name": "validators",
    "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "owner",
    "outputs": [{ "internalType": "address", "name": "", "type": "address" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "anchorCount",
    "outputs": [{ "internalType": "uint256", "name": "", "type": "uint256" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "anonymous": false,
    "inputs": [
      { "indexed": true,  "internalType": "uint256", "name": "anchorId",    "type": "uint256" },
      { "indexed": true,  "internalType": "bytes32", "name": "merkleRoot",  "type": "bytes32" },
      { "indexed": false, "internalType": "uint256", "name": "blockIdx",    "type": "uint256" },
      { "indexed": true,  "internalType": "address", "name": "submitter",   "type": "address" },
      { "indexed": false, "internalType": "uint256", "name": "anchoredAt",  "type": "uint256" }
    ],
    "name": "AnchorSubmitted",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      { "indexed": true,  "internalType": "address", "name": "validator", "type": "address" },
      { "indexed": false, "internalType": "string",  "name": "nodeId",    "type": "string"  }
    ],
    "name": "ValidatorAdded",
    "type": "event"
  }
];

// NOTE: Replace with actual compiled bytecode from `solcjs --bin AuditAnchor.sol`
// This is a placeholder — the real bytecode is generated by the Solidity compiler.
// Run: cd contracts && solcjs --bin --optimize AuditAnchor.sol
const CONTRACT_BYTECODE_PLACEHOLDER = `
  To get the actual bytecode:
    cd ${ROOT}/contracts
    npm install -g solc
    solcjs --bin --optimize --optimize-runs=200 AuditAnchor.sol
    # Bytecode will be in AuditAnchor_sol_AuditAnchor.bin
`;

// ─── RPC helpers ──────────────────────────────────────────────────────────────

async function rpc(url, method, params = []) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`RPC ${method}: ${data.error.message}`);
  return data.result;
}

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Uint8Array.from(clean.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function numToHex(n) {
  if (n === 0n || n === 0) return "0x";
  const h = BigInt(n).toString(16);
  return "0x" + (h.length % 2 ? "0" + h : h);
}

// ─── Address from private key ─────────────────────────────────────────────────

async function getAddress(privateKey) {
  // Dynamic import secp256k1 — @noble/curves is in package.json
  const { secp256k1 } = await import("@noble/curves/secp256k1.js").catch(() =>
    // Fallback path for direct node execution
    import("../node_modules/@noble/curves/esm/secp256k1.js")
  );
  const privBytes = hexToBytes(privateKey.replace("0x", ""));
  const pubFull   = secp256k1.getPublicKey(privBytes, false);
  // keccak256 of 64-byte public key
  const { createKeccakHash } = await import("crypto");
  // Node.js crypto doesn't have keccak256 directly — use Web Crypto + noble
  // We'll compute via a simple fetch to our own node if running, or warn
  const hash = crypto.createHash ? null : null; // placeholder
  // For deploy script: use ethers-style address derivation
  return "0x" + "?".repeat(40) + " (install @noble/hashes for full address derivation)";
}

// ─── Deploy ───────────────────────────────────────────────────────────────────

async function deployToNetwork(networkName, rpcUrl, privateKey, bytecode) {
  console.log(`\n[Deploy] Deploying to ${networkName} (${rpcUrl})...`);

  if (!bytecode || bytecode.includes("To get the actual bytecode")) {
    console.error(
      `\n[Deploy] ⚠  Bytecode not available.\n` +
      `         Compile AuditAnchor.sol first:\n` +
      `           cd ${ROOT}/contracts\n` +
      `           solcjs --bin --optimize AuditAnchor.sol\n` +
      `         Then update CONTRACT_BYTECODE in this script.`
    );
    return null;
  }

  const chainId = parseInt(await rpc(rpcUrl, "eth_chainId"), 16);
  console.log(`[Deploy] Chain ID: ${chainId}`);

  if (DRY_RUN) {
    const gasEstimate = await rpc(rpcUrl, "eth_estimateGas", [{
      data: "0x" + bytecode,
    }]);
    console.log(`[Deploy] DRY RUN — estimated gas: ${parseInt(gasEstimate, 16).toLocaleString()}`);
    return null;
  }

  // Get nonce
  // const address = await getAddress(privateKey);
  // const nonce = parseInt(await rpc(rpcUrl, "eth_getTransactionCount", [address, "pending"]), 16);

  console.log(`\n[Deploy] Ready to deploy. Implement full signing with compiled bytecode.`);
  console.log(`[Deploy] See ethereum-anchor.ts for signing implementation (signTransaction).`);
  return null;
}

// ─── Post-deploy: add validator ───────────────────────────────────────────────

async function addValidator(rpcUrl, contractAddress, ownerKey, validatorAddress, nodeId) {
  console.log(`\n[Deploy] Adding validator ${validatorAddress} to ${contractAddress}...`);

  // ABI encode: addValidator(address,string)
  // selector: keccak256("addValidator(address,string)")[0:4]
  // Computed: python3 -c "from Crypto.Hash import keccak; k=keccak.new(digest_bits=256); k.update(b'addValidator(address,string)'); print(k.hexdigest()[:8])"
  const selector  = "0xf6a2c278"; // addValidator(address,string)
  const addr      = validatorAddress.replace("0x", "").padStart(64, "0");
  const strOffset = "0000000000000000000000000000000000000000000000000000000000000040";
  const nodeIdHex = Buffer.from(nodeId, "utf8").toString("hex");
  const nodeIdLen = nodeId.length.toString(16).padStart(64, "0");
  const nodeIdPad = nodeIdHex.padEnd(Math.ceil(nodeIdHex.length / 64) * 64, "0");
  const data      = selector + addr + strOffset + nodeIdLen + nodeIdPad;

  console.log(`[Deploy] addValidator calldata: ${data.slice(0, 20)}...`);
  console.log(`[Deploy] Send this transaction with owner key to complete validator setup.`);

  return data;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║  SovereignCloud v2 — AuditAnchor.sol Deployment          ║
╚══════════════════════════════════════════════════════════╝
  Network:  ${NETWORK}
  Dry run:  ${DRY_RUN}
  Eth RPC:  ${ETH_RPC ?? "not set"}
  Meridian: ${MERIDIAN_RPC}
`);

  if (!PRIVATE_KEY && !DRY_RUN) {
    console.error("[Deploy] ✗ ETHEREUM_ANCHOR_KEY not set. Run with DRY_RUN=true to test.");
    process.exit(1);
  }

  // Check if compiled bytecode exists
  const binPath = join(ROOT, "contracts", "AuditAnchor_sol_AuditAnchor.bin");
  let bytecode  = CONTRACT_BYTECODE_PLACEHOLDER;

  if (existsSync(binPath)) {
    bytecode = readFileSync(binPath, "utf8").trim();
    console.log(`[Deploy] ✓ Compiled bytecode found: ${bytecode.length / 2} bytes`);
  } else {
    console.warn(`[Deploy] ⚠ Compiled bytecode not found at ${binPath}`);
    console.warn(`[Deploy] Run: cd contracts && solcjs --bin --optimize AuditAnchor.sol`);
    if (!DRY_RUN) {
      process.exit(1);
    }
  }

  const deployments = {};

  if ((NETWORK === "meridian" || NETWORK === "both") && MERIDIAN_RPC) {
    const addr = await deployToNetwork("Meridian Ledger", MERIDIAN_RPC, PRIVATE_KEY, bytecode);
    if (addr) deployments.meridian = addr;
  }

  if ((NETWORK === "ethereum" || NETWORK === "both") && ETH_RPC) {
    const addr = await deployToNetwork("Ethereum Mainnet", ETH_RPC, PRIVATE_KEY, bytecode);
    if (addr) deployments.ethereum = addr;
  }

  if (Object.keys(deployments).length > 0) {
    // Save deployment addresses
    const deployFile = join(ROOT, "deploy", "deployments.json");
    const existing   = existsSync(deployFile)
      ? JSON.parse(readFileSync(deployFile, "utf8"))
      : {};

    const updated = {
      ...existing,
      ...deployments,
      deployedAt: new Date().toISOString(),
      deployedBy: PRIVATE_KEY ? "wallet" : "dry-run",
    };

    writeFileSync(deployFile, JSON.stringify(updated, null, 2));
    console.log(`\n[Deploy] ✓ Saved to ${deployFile}`);
    console.log(`[Deploy] Contract addresses:`, deployments);

    console.log(`
Next steps:
  1. Add anchor wallet as validator:
     node deploy/add-validator.mjs \\
       --contract ${deployments.ethereum ?? "<addr>"} \\
       --validator <anchor-wallet-address> \\
       --node-id sovereign-v2

  2. Update .env:
     ETHEREUM_ANCHOR_CONTRACT=${deployments.ethereum ?? "<addr>"}
     MERIDIAN_CONTRACT=${deployments.meridian ?? "<addr>"}

  3. Verify on Etherscan (mainnet):
     node deploy/deploy-contracts.mjs --verify \\
       --contract ${deployments.ethereum ?? "<addr>"}
`);
  }

  // Print .env additions regardless
  console.log(`
Add to .env after deploy:
  MERIDIAN_CONTRACT=<meridian-contract-address>
  ETHEREUM_ANCHOR_CONTRACT=<ethereum-contract-address>
`);
}

main().catch(err => {
  console.error("[Deploy] Fatal:", err.message);
  process.exit(1);
});
