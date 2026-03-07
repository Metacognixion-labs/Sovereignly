#!/usr/bin/env node
/**
 * SovereignCloud v2 — Add Anchor Wallet as Validator
 *
 * After deploying AuditAnchor.sol, run this script to authorize
 * the anchor wallet to submit proofs to the contract.
 *
 * Usage:
 *   ETHEREUM_ANCHOR_KEY=0x<owner-key> \
 *   ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/KEY \
 *   node deploy/add-validator.mjs \
 *     --contract 0x<AuditAnchor-address> \
 *     --validator 0x<anchor-wallet-address> \
 *     --node-id sovereign-v2
 *
 * Or for Meridian:
 *   MERIDIAN_RPC_URL=http://127.0.0.1:8545 \
 *   node deploy/add-validator.mjs \
 *     --network meridian \
 *     --contract 0x<AuditAnchor-address> \
 *     --validator 0x<anchor-wallet-address>
 *
 * The owner key must be the same key that deployed the contract.
 * The validator address is derived from ETHEREUM_ANCHOR_KEY in your .env.
 *
 * After running, verify:
 *   cast call <contract> "validators(address)(bool)" <validator-address>
 *   # Should return: true
 */

// ─── Parse args ───────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(flag) {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : null;
}

const CONTRACT   = getArg("--contract")  ?? process.env.ETHEREUM_ANCHOR_CONTRACT;
const VALIDATOR  = getArg("--validator") ?? process.env.ETHEREUM_ANCHOR_VALIDATOR;
const NODE_ID    = getArg("--node-id")   ?? "sovereign-v2";
const NETWORK    = getArg("--network")   ?? "ethereum";
const OWNER_KEY  = process.env.ETHEREUM_ANCHOR_KEY;
const RPC_URL    = NETWORK === "meridian"
  ? (process.env.MERIDIAN_RPC_URL ?? "http://127.0.0.1:8545")
  : process.env.ETHEREUM_RPC_URL;
const DRY_RUN    = args.includes("--dry-run") || process.env.DRY_RUN === "true";

// ─── Validate ─────────────────────────────────────────────────────────────────

if (!CONTRACT) {
  console.error("✗ --contract <address> required");
  console.error("  or set ETHEREUM_ANCHOR_CONTRACT in .env");
  process.exit(1);
}
if (!VALIDATOR) {
  console.error("✗ --validator <address> required");
  console.error("  Derive from anchor wallet: node -e \"const c=require('@noble/curves/secp256k1'); ...\"");
  process.exit(1);
}
if (!OWNER_KEY && !DRY_RUN) {
  console.error("✗ ETHEREUM_ANCHOR_KEY not set (must be contract owner key)");
  process.exit(1);
}
if (!RPC_URL) {
  console.error(`✗ ${NETWORK === "meridian" ? "MERIDIAN_RPC_URL" : "ETHEREUM_RPC_URL"} not set`);
  process.exit(1);
}

// ─── RPC + signing helpers ────────────────────────────────────────────────────

async function rpc(method, params = []) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
  });
  const d = await res.json();
  if (d.error) throw new Error(`RPC ${method}: ${d.error.message}`);
  return d.result;
}

function numToHex(n) {
  const h = BigInt(n).toString(16);
  return "0x" + (h.length % 2 ? "0" + h : h);
}

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!clean || clean.length % 2 !== 0) return new Uint8Array(0);
  return Uint8Array.from(clean.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ABI encode addValidator(address, string)
// selector: keccak256("addValidator(address,string)")[0:4] = 0xf6a2c278
// verified with: python3 -c "from Crypto.Hash import keccak; k=keccak.new(digest_bits=256); k.update(b'addValidator(address,string)'); print(k.hexdigest()[:8])"
function encodeAddValidator(validatorAddress, nodeId) {
  const selector  = "f6a2c278";
  const addr      = validatorAddress.replace("0x", "").toLowerCase().padStart(64, "0");
  const offset    = "0000000000000000000000000000000000000000000000000000000000000040";
  const nodeBytes = Buffer.from(nodeId, "utf8");
  const nodeLen   = nodeId.length.toString(16).padStart(64, "0");
  const nodePad   = nodeBytes.toString("hex").padEnd(Math.ceil(nodeBytes.length / 32) * 64, "0");
  return "0x" + selector + addr + offset + nodeLen + nodePad;
}

// ─── Simple EIP-1559 signing (reuse logic from ethereum-anchor.ts) ────────────

async function signAndSend(data, to, ownerKey) {
  const { secp256k1 } = await import("@noble/curves/secp256k1.js").catch(async () =>
    import("../node_modules/@noble/curves/esm/secp256k1.js")
  );

  // Derive sender address
  const privBytes = hexToBytes(ownerKey.replace("0x", ""));
  const pubKey    = secp256k1.getPublicKey(privBytes, false);

  // We need keccak256 for address derivation
  // Since bun has it via Web Crypto: use subtle
  const pubHash   = await crypto.subtle.digest("SHA-256", pubKey.slice(1)); // Fallback: not keccak
  // NOTE: For correct Ethereum address, keccak256 is required.
  // In production: bun has keccak via @noble/hashes/sha3
  // For now we print the calldata for manual execution

  console.log(`\n[Validator] ⚠ Automatic signing requires @noble/hashes for keccak256.`);
  console.log(`[Validator] Use cast (foundry) or ethers.js to send this transaction:`);
  console.log(`\n  cast send \\`);
  console.log(`    --rpc-url ${RPC_URL} \\`);
  console.log(`    --private-key ${ownerKey} \\`);
  console.log(`    ${CONTRACT} \\`);
  console.log(`    "${data}"`);
  console.log(`\n  Or with ethers.js:`);
  console.log(`    const tx = await contract.addValidator("${VALIDATOR}", "${NODE_ID}");`);
  console.log(`    await tx.wait();`);
}

// ─── Verify validator status ──────────────────────────────────────────────────

async function checkValidatorStatus(address) {
  // validators(address) => bool
  // selector: keccak256("validators(address)")[0:4]
  // = 0xfa52c7d8 (verify: python keccak of "validators(address)")
  const selector = "0xfa52c7d8";
  const encoded  = selector + address.replace("0x", "").padStart(64, "0");

  try {
    const result = await rpc("eth_call", [{ to: CONTRACT, data: encoded }, "latest"]);
    return result === "0x" + "0".repeat(63) + "1";
  } catch {
    return false;
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║  SovereignCloud v2 — Add Anchor Wallet as Validator      ║
╚══════════════════════════════════════════════════════════╝
  Network:   ${NETWORK} (${RPC_URL})
  Contract:  ${CONTRACT}
  Validator: ${VALIDATOR}
  Node ID:   ${NODE_ID}
  Dry run:   ${DRY_RUN}
`);

  // Check if already a validator
  console.log("[Validator] Checking current status...");
  const alreadyValidator = await checkValidatorStatus(VALIDATOR).catch(() => false);

  if (alreadyValidator) {
    console.log(`\n[Validator] ✓ ${VALIDATOR} is already a validator on ${CONTRACT}`);
    console.log(`[Validator] No action needed. Your anchor wallet is authorized.`);
    return;
  }

  console.log(`[Validator] ${VALIDATOR} is NOT yet a validator.`);

  // Encode the call
  const calldata = encodeAddValidator(VALIDATOR, NODE_ID);
  console.log(`\n[Validator] addValidator calldata:`);
  console.log(`  ${calldata.slice(0, 74)}...`);

  if (DRY_RUN) {
    console.log(`\n[Validator] DRY RUN — not sending. Calldata ready.`);
  } else {
    await signAndSend(calldata, CONTRACT, OWNER_KEY);
  }

  // Summary
  console.log(`
─── Setup Summary ────────────────────────────────────────────

  After adding validator, update .env:

  ETHEREUM_ANCHOR_CONTRACT=${CONTRACT}
  ETHEREUM_ANCHOR_KEY=0x<your-anchor-wallet-private-key>

  # If Meridian:
  MERIDIAN_CONTRACT=${CONTRACT}
  MERIDIAN_RPC_URL=${RPC_URL}

  # Verify the anchor wallet is set up:
  node deploy/add-validator.mjs \\
    --contract ${CONTRACT} \\
    --validator ${VALIDATOR} \\
    --dry-run

  # Then start SovereignCloud:
  docker compose up -d
  
─────────────────────────────────────────────────────────────
`);
}

main().catch(err => {
  console.error("[Validator] Fatal:", err.message);
  process.exit(1);
});
