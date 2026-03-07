#!/usr/bin/env node
/**
 * register-eas-schema.mjs
 * MetaCognixion — SovereignCloud v3
 *
 * Registers the sovereign-v3 attestation schema on EAS SchemaRegistry.
 * Run once. The resulting UID is hardcoded everywhere else.
 *
 * Usage:
 *   EAS_SIGNER_KEY=0x<privkey> node deploy/register-eas-schema.mjs
 *   EAS_SIGNER_KEY=0x<privkey> node deploy/register-eas-schema.mjs --network arbitrum
 *   EAS_SIGNER_KEY=0x<privkey> node deploy/register-eas-schema.mjs --network all
 *
 * Cost: ~$0.001 per chain (Base gas). One-time.
 * After running: set EAS_SCHEMA_UID in .env (should match precomputed value below).
 */

import { secp256k1 }  from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

// ─── Schema definition ────────────────────────────────────────────────────────

const SCHEMA    = "bytes32 merkleRoot,uint256 blockIndex,uint32 eventCount,string orgId,string protocol";
const RESOLVER  = "0x0000000000000000000000000000000000000000";
const REVOCABLE = true;

// Precomputed: keccak256(abi.encodePacked(schema, resolver, revocable))
// If registration succeeds and the returned UID differs from this, update EAS_SCHEMA_UID in .env
const EXPECTED_UID = "0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc";

// ─── Chain configs ────────────────────────────────────────────────────────────

const CHAINS = {
  base: {
    name:     "Base mainnet",
    chainId:  8453,
    rpcUrl:   process.env.EAS_BASE_RPC ?? "https://mainnet.base.org",
    registry: "0x4200000000000000000000000000000000000020",
    scanner:  "https://base.easscan.org/schema/view",
  },
  "base-sepolia": {
    name:     "Base Sepolia (testnet)",
    chainId:  84532,
    rpcUrl:   process.env.EAS_BASE_SEPOLIA_RPC ?? "https://sepolia.base.org",
    registry: "0x4200000000000000000000000000000000000020",
    scanner:  "https://base-sepolia.easscan.org/schema/view",
  },
  arbitrum: {
    name:     "Arbitrum One",
    chainId:  42161,
    rpcUrl:   process.env.EAS_ARB_RPC ?? "https://arb1.arbitrum.io/rpc",
    registry: "0xaEF4103A04090071165F78D45D83A0C0782c2B2a",
    scanner:  "https://arbitrum.easscan.org/schema/view",
  },
  optimism: {
    name:     "Optimism",
    chainId:  10,
    rpcUrl:   process.env.EAS_OP_RPC ?? "https://mainnet.optimism.io",
    registry: "0x4200000000000000000000000000000000000020",
    scanner:  "https://optimism.easscan.org/schema/view",
  },
};

// ─── Utilities ────────────────────────────────────────────────────────────────

const toHex   = b  => Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("");
const fromHex = h  => { const s=h.startsWith("0x")?h.slice(2):h; return Uint8Array.from(s.match(/.{2}/g).map(b=>parseInt(b,16))); };
const toBig   = n  => { if(n===0n) return new Uint8Array(0); const h=n.toString(16); return fromHex(h.length%2?"0"+h:h); };

const evmAddress = privKey => {
  const pub  = secp256k1.getPublicKey(privKey, false);
  const hash = keccak_256(pub.slice(1));
  return "0x" + toHex(hash).slice(-40);
};

const rlpItem = data => {
  if (data.length === 0)               return new Uint8Array([0x80]);
  if (data.length === 1 && data[0]<0x80) return data;
  if (data.length <= 55)               return Uint8Array.from([0x80+data.length, ...data]);
  const lb = toBig(BigInt(data.length));
  return Uint8Array.from([0xb7+lb.length, ...lb, ...data]);
};
const rlpList = items => {
  const enc   = items.map(rlpItem);
  const total = enc.reduce((a,b)=>a+b.length, 0);
  const hdr   = total <= 55
    ? Uint8Array.from([0xc0+total])
    : (() => { const lb=toBig(BigInt(total)); return Uint8Array.from([0xf7+lb.length,...lb]); })();
  return Uint8Array.from([...hdr, ...enc.flatMap(e=>[...e])]);
};

async function rpc(url, method, params=[]) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc:"2.0", id:Date.now(), method, params }),
  });
  const d = await r.json();
  if (d.error) throw new Error(`${method}: ${d.error.message} (${d.error.code})`);
  return d.result;
}

async function sendTx(rpcUrl, chainId, privKey, to, data) {
  const from = evmAddress(privKey);
  const [feeHist, nonce] = await Promise.all([
    rpc(rpcUrl, "eth_feeHistory", [4, "latest", [50]]),
    rpc(rpcUrl, "eth_getTransactionCount", [from, "pending"]),
  ]);

  const baseFee = BigInt(feeHist.baseFeePerGas.at(-1));
  const tips    = (feeHist.reward?.flat() ?? ["0x3b9aca00"]).map(r=>BigInt(r));
  const tip     = tips.reduce((a,b)=>a+b, 0n) / BigInt(tips.length);
  const maxFee  = baseFee * 2n + tip;
  const nonceN  = parseInt(nonce, 16);

  let gasLimit = 150_000n;
  try {
    const est = await rpc(rpcUrl, "eth_estimateGas", [{ from, to, data }]);
    gasLimit = BigInt(est) * 13n / 10n;
  } catch {}

  const payload = Uint8Array.from([0x02, ...rlpList([
    toBig(BigInt(chainId)), toBig(BigInt(nonceN)), toBig(tip), toBig(maxFee), toBig(gasLimit),
    fromHex(to), new Uint8Array(0), fromHex(data.replace("0x","")), rlpList([]),
  ])]);

  const sigHash = keccak_256(payload);
  const sig     = secp256k1.sign(sigHash, privKey, { lowS: true });

  const rawTx = Uint8Array.from([0x02, ...rlpList([
    toBig(BigInt(chainId)), toBig(BigInt(nonceN)), toBig(tip), toBig(maxFee), toBig(gasLimit),
    fromHex(to), new Uint8Array(0), fromHex(data.replace("0x","")), rlpList([]),
    toBig(BigInt(sig.recovery)), toBig(sig.r), toBig(sig.s),
  ])]);

  return rpc(rpcUrl, "eth_sendRawTransaction", ["0x" + toHex(rawTx)]);
}

// ─── Build register() calldata ───────────────────────────────────────────────
// SchemaRegistry.register(string schema, address resolver, bool revocable)
// Selector: keccak4("register(string,address,bool)") = 0x60d7a278

function buildRegisterCalldata(schema, resolver, revocable) {
  const schemaBytes  = new TextEncoder().encode(schema);
  const schemaLen    = schemaBytes.length.toString(16).padStart(64, "0");
  const schemaPadded = toHex(schemaBytes).padEnd(Math.ceil(schemaBytes.length/32)*64, "0");
  const offset       = (3*32).toString(16).padStart(64,"0");  // 0x60
  const resolverPad  = resolver.replace("0x","").padStart(64,"0");
  const revocablePad = (revocable ? "1" : "0").padStart(64,"0");

  return "0x60d7a278" + offset + resolverPad + revocablePad + schemaLen + schemaPadded;
}

// ─── Verify schema UID ───────────────────────────────────────────────────────
// Check if schema is already registered on-chain

async function isSchemaRegistered(rpcUrl, registryAddr, expectedUid) {
  // SchemaRegistry.getSchema(bytes32 uid) returns (SchemaRecord)
  // Selector: keccak4("getSchema(bytes32)") = 0xa2ea7c6e
  const data = "0xa2ea7c6e" + expectedUid.replace("0x","").padStart(64,"0");
  try {
    const result = await rpc(rpcUrl, "eth_call", [{ to: registryAddr, data }, "latest"]);
    // If schema exists, uid field (first bytes32) will be non-zero
    const uidInResult = result.slice(2, 66);
    return uidInResult !== "0".repeat(64);
  } catch {
    return false;
  }
}

// ─── Extract UID from receipt ─────────────────────────────────────────────────
// SchemaRegistry emits: Registered(bytes32 indexed uid, address indexed registerer, SchemaRecord)
// Topic 0: keccak256("Registered(bytes32,address,(bytes32,address,address,string,bool))")

async function getUidFromReceipt(rpcUrl, txHash, maxWaitMs = 60_000) {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 3000));
    const receipt = await rpc(rpcUrl, "eth_getTransactionReceipt", [txHash]).catch(()=>null);
    if (receipt?.status === "0x1") {
      // The UID is the first indexed topic (topics[1])
      const log = receipt.logs?.[0];
      if (log?.topics?.[1]) {
        return "0x" + log.topics[1].slice(2);
      }
      return null;
    }
    if (receipt?.status === "0x0") throw new Error(`Transaction reverted: ${txHash}`);
  }
  return null; // timeout
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const args    = process.argv.slice(2);
const netArg  = args[args.indexOf("--network")+1] ?? "base";
const dryRun  = args.includes("--dry-run");

const signerKeyRaw = process.env.EAS_SIGNER_KEY;
if (!signerKeyRaw && !dryRun) {
  console.error("Error: EAS_SIGNER_KEY environment variable required.");
  console.error("  EAS_SIGNER_KEY=0x<privkey> node deploy/register-eas-schema.mjs");
  process.exit(1);
}

const privKey = signerKeyRaw ? fromHex(signerKeyRaw.replace("0x","")) : new Uint8Array(32);
const signer  = signerKeyRaw ? evmAddress(privKey) : "0x<dry-run>";

const calldata = buildRegisterCalldata(SCHEMA, RESOLVER, REVOCABLE);

// Determine which networks to register on
const targetNetworks = netArg === "all"
  ? Object.keys(CHAINS)
  : [netArg];

console.log("┌─────────────────────────────────────────────────────────────────┐");
console.log("│  SovereignCloud v3 — EAS Schema Registration                    │");
console.log("└─────────────────────────────────────────────────────────────────┘");
console.log("");
console.log(`Schema:        "${SCHEMA}"`);
console.log(`Resolver:      ${RESOLVER}  (no resolver)`);
console.log(`Revocable:     ${REVOCABLE}`);
console.log(`Expected UID:  ${EXPECTED_UID}`);
console.log(`Signer:        ${signer}`);
console.log(`Networks:      ${targetNetworks.join(", ")}`);
console.log(`Mode:          ${dryRun ? "DRY RUN (no tx)" : "LIVE"}`);
console.log("");

if (dryRun) {
  console.log("Calldata (register on any EAS SchemaRegistry):");
  console.log(`  ${calldata}`);
  console.log("");
  console.log("To register manually via cast (Foundry):");
  for (const net of targetNetworks) {
    const chain = CHAINS[net];
    if (!chain) continue;
    console.log(`  # ${chain.name}`);
    console.log(`  cast send ${chain.registry} \\`);
    console.log(`    "${calldata}" \\`);
    console.log(`    --rpc-url ${chain.rpcUrl} \\`);
    console.log(`    --private-key $EAS_SIGNER_KEY`);
  }
  process.exit(0);
}

const results = [];

for (const net of targetNetworks) {
  const chain = CHAINS[net];
  if (!chain) {
    console.error(`Unknown network: ${net}. Valid options: ${Object.keys(CHAINS).join(", ")}`);
    continue;
  }

  console.log(`Registering on ${chain.name}...`);

  try {
    // Check if already registered
    const alreadyExists = await isSchemaRegistered(chain.rpcUrl, chain.registry, EXPECTED_UID);
    if (alreadyExists) {
      console.log(`  ✓ Already registered — UID ${EXPECTED_UID}`);
      console.log(`  View: ${chain.scanner}/${EXPECTED_UID}`);
      results.push({ network: net, uid: EXPECTED_UID, status: "already_exists" });
      continue;
    }

    // Register
    const txHash = await sendTx(chain.rpcUrl, chain.chainId, privKey, chain.registry, calldata);
    console.log(`  ⏳ Tx submitted: ${txHash}`);
    console.log(`     Waiting for confirmation...`);

    const uid = await getUidFromReceipt(chain.rpcUrl, txHash);

    if (uid) {
      const match = uid.toLowerCase() === EXPECTED_UID.toLowerCase();
      console.log(`  ${match ? "✓" : "⚠"} Registered — UID: ${uid}`);
      if (!match) {
        console.warn(`  ⚠  UID mismatch! Expected: ${EXPECTED_UID}`);
        console.warn(`     Update EAS_SCHEMA_UID in .env to: ${uid}`);
      }
      console.log(`  View: ${chain.scanner}/${uid}`);
      results.push({ network: net, uid, txHash, status: match ? "ok" : "uid_mismatch" });
    } else {
      console.log(`  ⏳ Tx sent but confirmation timed out. Check: https://basescan.org/tx/${txHash}`);
      results.push({ network: net, txHash, status: "pending" });
    }

  } catch (err) {
    console.error(`  ✗ Failed: ${err.message}`);
    results.push({ network: net, status: "error", error: err.message });
  }

  console.log("");
}

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log("┌─────────────────────────────────────────────────────────────────┐");
console.log("│  Registration Summary                                            │");
console.log("└─────────────────────────────────────────────────────────────────┘");
console.log("");

let allOk = true;
for (const r of results) {
  const chain = CHAINS[r.network];
  const status = r.status === "ok" || r.status === "already_exists" ? "✓" : "✗";
  console.log(`  ${status}  ${chain?.name ?? r.network}`);
  if (r.uid)    console.log(`     UID:  ${r.uid}`);
  if (r.txHash) console.log(`     Tx:   ${r.txHash}`);
  if (r.status === "error") { console.log(`     Err:  ${r.error}`); allOk = false; }
  if (r.status === "uid_mismatch") {
    console.log(`     ⚠  Update EAS_SCHEMA_UID to: ${r.uid}`);
    allOk = false;
  }
}

console.log("");
if (allOk && results.length > 0) {
  console.log("Next steps:");
  console.log(`  1. Add to .env:`);
  console.log(`     EAS_SCHEMA_UID=${results[0]?.uid ?? EXPECTED_UID}`);
  if (results.length > 1) {
    console.log(`     EAS_ARB_SCHEMA_UID=${results.find(r=>r.network==="arbitrum")?.uid ?? EXPECTED_UID}`);
  }
  console.log(`  2. Launch SovereignCloud:`);
  console.log(`     ./deploy/launch.sh`);
  console.log(`  3. Verify schema on easscan:`);
  for (const r of results) {
    const chain = CHAINS[r.network];
    if (r.uid) console.log(`     ${chain?.scanner}/${r.uid}`);
  }
} else if (!allOk) {
  console.log("Some registrations failed — check errors above.");
  process.exit(1);
}
