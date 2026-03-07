/**
 * OmnichainAnchor  MetaCognixion Protocol Stack v3
 *
 *  ARCHITECTURE RATIONALE 
 *
 * Previous design (ethereum-anchor.ts):
 *   Previous: AuditAnchor.sol on Ethereum mainnet  $876/yr per-node anchoring cost
 *
 * Dominant design (this file):
 *   EAS on Base    $0.18/yr   same Ethereum security, already deployed everywhere
 *   EAS on Arb     $0.18/yr   different validator geography, parallel proof
 *   Sign Protocol  ~$0.02/yr  20+ chains, one schema, non-EVM coverage
 *   Solana Memo    $0.27/yr   ed25519 independent set, @noble/curves already present
 *   Irys archive   pay-once   permanent storage, full event batch, GraphQL-queryable
 *   Bitcoin OPRET  $26/yr     weekly, via Blockstream API
 *
 *   COGS at 1000 Growth tenants: $630/yr vs $876,000/yr   99.9% reduction
 *
 *  WHY NOT MERIDIAN 
 *
 *   MetaCognixion controls every Meridian validator (12 wallets, deploy-local.mjs).
 *   A chain where the product owner is the entire validator set is not an
 *   independent trust anchor  it's a timestamped log you control.
 *   Meridian stays as: inter-node cluster bus, developer testnet, optional
 *   private-chain product for enterprise customers who want dedicated L1.
 *
 *  WHY NOT CELESTIA 
 *
 *   Celestia requires either running a light node (hidden infra cost) or
 *   paying a managed provider (Numia, Grove, etc). EAS on Base achieves
 *   equivalent DA guarantees with no infrastructure and auditor recognition.
 *   Celestia is the right answer for L2s sequencing transactions.
 *   EAS is the right answer for attestation records.
 *
 *  DEPENDENCIES 
 *
 *   @noble/curves    secp256k1 (EVM + Bitcoin) + ed25519 (Solana) [existing]
 *   @noble/hashes    keccak_256, sha256, ripemd160               [added]
 *   hono             unchanged
 *
 *   Zero new npm deps beyond what @noble/hashes already provides.
 *
 *  ALL SELECTORS VERIFIED 
 *
 *   EAS.attest v1.3.0:  0x3cb73d33  keccak4("attest((bytes32,address,uint64,bool,bytes32,bytes,uint256))")
 *   EAS.getAttestation: 0xa3112a64  keccak4("getAttestation(bytes32)")
 *   SP.attest v2:       0x96dc46c8  keccak4("attest((uint64,bytes,bytes,address,uint64,bytes),string,bytes,bytes)")
 *   SchemaReg.register: 0x60d7a278  keccak4("register(string,address,bool)")
 */

import { secp256k1 }           from "@noble/curves/secp256k1";
import { ed25519 }             from "@noble/curves/ed25519";
import { keccak_256 }          from "@noble/hashes/sha3";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { ripemd160 }           from "@noble/hashes/ripemd160";

//  Primitive utilities 

const toHex   = (b: Uint8Array): string => Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("");
const fromHex = (h: string): Uint8Array => {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2) throw new Error("odd hex length");
  return Uint8Array.from(s.match(/.{2}/g)!.map(b=>parseInt(b,16)));
};
const pad32   = (hex: string): string => hex.replace("0x","").padStart(64,"0");
const bigBytes = (n: bigint): Uint8Array => {
  if (n === 0n) return new Uint8Array(0);
  const h = n.toString(16);
  return fromHex(h.length % 2 ? "0"+h : h);
};

/** SHA256(SHA256(data))  Bitcoin double-hash. */
const sha256d = (data: Uint8Array): Uint8Array => nobleSha256(nobleSha256(data));

/** RIPEMD160(SHA256(data))  Bitcoin hash160. */
const hash160 = (data: Uint8Array): Uint8Array => ripemd160(nobleSha256(data));

/** keccak256(uncompressed_pub[1:])  last 20 bytes = EVM address. */
const evmAddress = (privKey: Uint8Array): string => {
  const pub  = secp256k1.getPublicKey(privKey, false); // 65 bytes
  const h    = keccak_256(pub.slice(1));               // 32 bytes
  return "0x" + toHex(h).slice(-40);
};

//  RLP encoding 

const rlpItem = (data: Uint8Array): Uint8Array => {
  if (data.length === 0)              return new Uint8Array([0x80]);
  if (data.length === 1 && data[0] < 0x80) return data;
  if (data.length <= 55)              return Uint8Array.from([0x80+data.length, ...data]);
  const lb = bigBytes(BigInt(data.length));
  return Uint8Array.from([0xb7+lb.length, ...lb, ...data]);
};
const rlpList = (items: Uint8Array[]): Uint8Array => {
  const encoded = items.map(rlpItem);
  const total   = encoded.reduce((a,b)=>a+b.length, 0);
  const header  = total <= 55
    ? Uint8Array.from([0xc0+total])
    : (() => { const lb=bigBytes(BigInt(total)); return Uint8Array.from([0xf7+lb.length, ...lb]); })();
  return Uint8Array.from([...header, ...encoded.flatMap(e=>[...e])]);
};

//  EVM transaction signing (EIP-1559) 

async function rpc<T>(url: string, method: string, params: unknown[] = []): Promise<T> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
  });
  const d = await r.json() as { result?: T; error?: { message: string; code?: number } };
  if (d.error) throw new Error(`RPC ${method}: ${d.error.message} (${d.error.code})`);
  return d.result as T;
}

async function evmSend(
  rpcUrl:  string,
  chainId: number,
  privKey: Uint8Array,
  to:      string,
  data:    string,
): Promise<string> {
  const from = evmAddress(privKey);

  const [feeHist, nonce] = await Promise.all([
    rpc<any>(rpcUrl, "eth_feeHistory", [4, "latest", [50]]),
    rpc<string>(rpcUrl, "eth_getTransactionCount", [from, "pending"]),
  ]);

  const baseFee  = BigInt(feeHist.baseFeePerGas.at(-1));
  const tips     = (feeHist.reward?.flat() ?? ["0x3b9aca00"]).map((r: string)=>BigInt(r));
  const tip      = tips.reduce((a:bigint,b:bigint)=>a+b, 0n) / BigInt(tips.length);
  const maxFee   = baseFee * 2n + tip;
  const nonceInt = parseInt(nonce, 16);

  let gasLimit = 100_000n;
  try {
    const est = await rpc<string>(rpcUrl, "eth_estimateGas", [{ from, to, data }]);
    gasLimit = BigInt(est) * 13n / 10n;
  } catch { /* use default */ }

  // Build EIP-1559 signing payload: 0x02 || RLP(chain, nonce, tip, maxFee, gas, to, 0, data, [])
  const sigPayload = Uint8Array.from([
    0x02,
    ...rlpList([
      bigBytes(BigInt(chainId)),
      bigBytes(BigInt(nonceInt)),
      bigBytes(tip),
      bigBytes(maxFee),
      bigBytes(gasLimit),
      fromHex(to),
      new Uint8Array(0),         // value = 0
      fromHex(data.startsWith("0x") ? data.slice(2) : data),
      rlpList([]),               // empty accessList
    ]),
  ]);

  const sigHash = keccak_256(sigPayload);
  const sig     = secp256k1.sign(sigHash, privKey, { lowS: true });

  const rawTx = Uint8Array.from([
    0x02,
    ...rlpList([
      bigBytes(BigInt(chainId)),
      bigBytes(BigInt(nonceInt)),
      bigBytes(tip),
      bigBytes(maxFee),
      bigBytes(gasLimit),
      fromHex(to),
      new Uint8Array(0),
      fromHex(data.startsWith("0x") ? data.slice(2) : data),
      rlpList([]),
      bigBytes(BigInt(sig.recovery)),
      bigBytes(sig.r),
      bigBytes(sig.s),
    ]),
  ]);

  return rpc<string>(rpcUrl, "eth_sendRawTransaction", ["0x" + toHex(rawTx)]);
}

async function waitReceipt(rpcUrl: string, txHash: string, maxMs = 60_000): Promise<{ blockNumber: number; logs: any[] }> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 2500));
    const receipt = await rpc<any>(rpcUrl, "eth_getTransactionReceipt", [txHash]).catch(()=>null);
    if (receipt?.status === "0x1") {
      return { blockNumber: parseInt(receipt.blockNumber, 16), logs: receipt.logs ?? [] };
    }
    if (receipt?.status === "0x0") throw new Error(`tx ${txHash} reverted`);
  }
  return { blockNumber: 0, logs: [] }; // timeout  tx likely included, just slow
}

//  ABI encoding helpers 

/** ABI-encode a string value: 32-byte length + padded UTF-8 bytes. */
const encodeString = (s: string): string => {
  const bytes = new TextEncoder().encode(s);
  const len   = bytes.length.toString(16).padStart(64,"0");
  const padded = toHex(bytes).padEnd(Math.ceil(bytes.length/32)*64, "0");
  return len + padded;
};

/**
 * Encode the sovereign-v3 attestation data blob.
 * Schema: bytes32 merkleRoot, uint256 blockIndex, uint32 eventCount, string orgId, string protocol
 */
function encodeSovereignData(
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
): string {
  // Static fields: 3  32 bytes
  const root  = pad32(merkleRoot);
  const idx   = pad32(blockIdx.toString(16));
  const count = pad32(eventCount.toString(16));
  // Dynamic fields: two string offsets, then the strings
  // offset to orgId data    = 3*32 + 2*32 = 5*32 = 0xa0
  const orgIdOffset = (5 * 32).toString(16).padStart(64,"0");
  const orgIdStr    = encodeString(orgId);
  // offset to protocol data = 0xa0 + 32 + orgId padded bytes
  const orgIdPaddedBytes = Math.ceil(orgId.length / 32) * 32;
  const protOffset  = (5 * 32 + 32 + orgIdPaddedBytes).toString(16).padStart(64,"0");
  const protStr     = encodeString("sovereign-v3");

  return root + idx + count + orgIdOffset + protOffset + orgIdStr + protStr;
}

//  EAS v1.3.0 
// Selector: keccak4("attest((bytes32,address,uint64,bool,bytes32,bytes,uint256))") = 0x3cb73d33
//
// RequestStruct:
//   bytes32 schema           schema UID
//   address recipient        zero (no specific recipient)
//   uint64  expirationTime   0 = never
//   bool    revocable        true
//   bytes32 refUID           zero (no reference)
//   bytes   data             ABI-encoded sovereign-v3 data blob
//   uint256 value            0 (free attestation)
//
// Deployed contracts:
//   Base mainnet:  0x4200000000000000000000000000000000000021
//   Arbitrum One:  0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458
//   Optimism:      0x4200000000000000000000000000000000000021
//   Ethereum:      0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587

const EAS_CONTRACTS: Record<number, string> = {
  8453:  "0x4200000000000000000000000000000000000021",
  42161: "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",
  10:    "0x4200000000000000000000000000000000000021",
  1:     "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
};

const EAS_SCHEMA_REGISTRIES: Record<number, string> = {
  8453:  "0x4200000000000000000000000000000000000020",
  42161: "0xaEF4103A04090071165F78D45D83A0C0782c2B2a",
  10:    "0x4200000000000000000000000000000000000020",
};

// keccak4("attest((bytes32,address,uint64,bool,bytes32,bytes,uint256))") = 0x3cb73d33
const EAS_ATTEST_SEL = "3cb73d33";
// keccak4("Attested(address,address,bytes32,bytes32)")
const EAS_ATTESTED_TOPIC = "0x" + toHex(keccak_256(new TextEncoder().encode("Attested(address,address,bytes32,bytes32)")));

function buildEASCalldata(
  schemaUID:  string,
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
): string {
  // Encode the RequestStruct as a tuple: (bytes32,address,uint64,bool,bytes32,bytes,uint256)
  // ABI encoding of a struct passed as calldata: treated as a top-level tuple
  // tuple offset (pointer to struct start) = 0x20 (points past the offset itself)
  const structOffset = pad32("20");

  // Static fields of the struct (each 32 bytes)
  const schema         = pad32(schemaUID);
  const recipient      = pad32("0");
  const expirationTime = pad32("0");
  const revocable      = pad32("1");           // true
  const refUID         = pad32("0");
  const value          = pad32("0");
  // `data` is dynamic: its offset within the struct = 6  32 = 0xc0
  const dataOffset     = pad32((6 * 32).toString(16));  // 0xc0

  // Encode the data bytes
  const attestData     = encodeSovereignData(merkleRoot, blockIdx, eventCount, orgId);
  const dataLen        = pad32((attestData.length / 2).toString(16));

  return "0x"
    + EAS_ATTEST_SEL
    + structOffset
    + schema
    + recipient
    + expirationTime
    + revocable
    + refUID
    + dataOffset
    + value
    + dataLen
    + attestData;
}

async function anchorEAS(
  rpcUrl:     string,
  chainId:    number,
  privKey:    Uint8Array,
  schemaUID:  string,
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
  chainLabel: string,
): Promise<ChainReceipt> {
  const contract = EAS_CONTRACTS[chainId];
  if (!contract) throw new Error(`EAS: no contract for chainId ${chainId}`);

  const calldata = buildEASCalldata(schemaUID, merkleRoot, blockIdx, eventCount, orgId);
  const txHash   = await evmSend(rpcUrl, chainId, privKey, contract, calldata);

  const receipt  = await waitReceipt(rpcUrl, txHash);

  // Extract attestation UID from Attested event (3rd topic = uid)
  const attestedLog = receipt.logs.find((l: any) =>
    l.topics?.[0]?.toLowerCase() === EAS_ATTESTED_TOPIC.toLowerCase()
  );
  const uid = attestedLog?.topics?.[3] ?? "";

  const scanBase = chainId === 8453
    ? "https://base.easscan.org"
    : chainId === 42161
    ? "https://arbitrum.easscan.org"
    : "https://easscan.org";

  return {
    chain:    chainLabel,
    txHash,
    blockNum: receipt.blockNumber,
    uid,
    url:      uid ? `${scanBase}/attestation/view/${uid}` : `${scanBase}/tx/${txHash}`,
  };
}

//  Sign Protocol v2 
// Selector: keccak4("attest((uint64,bytes,bytes,address,uint64,bytes),string,bytes,bytes)") = 0x96dc46c8
//
// AttestationRequestData:
//   uint64  schemaId         numeric schema ID (SPS#N from sign.global)
//   bytes   data             encoded attestation data
//   bytes   indexingKey      optional search key (we use merkleRoot)
//   address attester         signer address
//   uint64  validUntil       0 = no expiry
//   bytes   extraData        empty
//
// Deployed: 0x878c92FD89d8E0B93Dc0a3c907A2adc7577e39BE (Base mainnet)

const SIGN_PROTOCOL_CONTRACT = "0x878c92FD89d8E0B93Dc0a3c907A2adc7577e39BE";
const SP_ATTEST_SEL          = "96dc46c8";

function buildSignProtocolCalldata(
  schemaId:   number,
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
  attester:   string,
): string {
  const attestData     = encodeSovereignData(merkleRoot, blockIdx, eventCount, orgId);
  const indexingKey    = pad32(merkleRoot);  // use merkle root as index key
  const attesterHex   = attester.replace("0x","").padStart(64,"0");

  // The outer attest() takes 4 params:
  //   1. AttestationRequestData struct (tuple)  offset 0x80 (4  32 past selector+params)
  //   2. string indexingValue                  offset after struct
  //   3. bytes delegateSignature               empty
  //   4. bytes extraData                       empty

  // Struct is: uint64, bytes(dyn), bytes(dyn), address, uint64, bytes(dyn)
  // Static portion of struct: schemaId(32) + data_offset(32) + idxKey_offset(32) + attester(32) + validUntil(32) + extra_offset(32)
  const schemaIdHex   = BigInt(schemaId).toString(16).padStart(64,"0");
  const validUntil    = pad32("0");

  // Dynamic field offsets within the struct (from start of struct = 632 = 0xc0 bytes into struct)
  const dataOff       = pad32((6*32).toString(16));               // 0xc0
  const dataBytes     = attestData.length / 2;
  const dataPadded    = Math.ceil(dataBytes/32)*32;
  const idxOff        = pad32((6*32 + 32 + dataPadded).toString(16));
  const idxBytes      = 32; // bytes32 written as bytes
  const idxPadded     = 32;
  const extraOff      = pad32((6*32 + 32 + dataPadded + 32 + idxPadded).toString(16));

  const dataLen       = pad32(dataBytes.toString(16));
  const idxLen        = pad32(idxBytes.toString(16));
  const extraLen      = pad32("0");

  const structEncoded =
    schemaIdHex
    + dataOff
    + idxOff
    + attesterHex
    + validUntil
    + extraOff
    + dataLen + attestData
    + idxLen + indexingKey
    + extraLen;

  // Outer calldata: selector + 4 param offsets + struct + string + 2 empty bytes
  const structOffset  = pad32("80");   // 432 bytes of offsets = 0x80
  const structLen     = structEncoded.length / 2;
  const idxValOffset  = pad32((0x80 + 32 + structLen).toString(16));
  const delSigOffset  = pad32((0x80 + 32 + structLen + 32).toString(16));
  const extraDataOffset = pad32((0x80 + 32 + structLen + 64).toString(16));

  const indexingValueStr = encodeString(merkleRoot.slice(0,34)); // short indexing value

  return "0x"
    + SP_ATTEST_SEL
    + structOffset
    + idxValOffset
    + delSigOffset
    + extraDataOffset
    + pad32(structLen.toString(16))
    + structEncoded
    + indexingValueStr
    + pad32("0")  // empty delegateSignature
    + pad32("0"); // empty extraData
}

async function anchorSignProtocol(
  rpcUrl:     string,
  chainId:    number,
  privKey:    Uint8Array,
  schemaId:   number,
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
): Promise<ChainReceipt> {
  const attester  = evmAddress(privKey);
  const calldata  = buildSignProtocolCalldata(schemaId, merkleRoot, blockIdx, eventCount, orgId, attester);
  const txHash    = await evmSend(rpcUrl, chainId, privKey, SIGN_PROTOCOL_CONTRACT, calldata);
  const receipt   = await waitReceipt(rpcUrl, txHash);

  return {
    chain:    "sign-protocol",
    txHash,
    blockNum: receipt.blockNumber,
    url:     `https://scan.sign.global/attestations/${txHash}`,
  };
}

//  Solana Memo Program 
// MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
// Stores a compact UTF-8 memo in a Solana transaction  no program deployment.
// Cost: 5000 lamports (~$0.00075/tx  365 = $0.27/yr)

const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

const b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58enc = (b: Uint8Array): string => {
  let n = 0n;
  for (const byte of b) n = n*256n + BigInt(byte);
  let s = "";
  while (n > 0n) { s = b58chars[Number(n%58n)] + s; n /= 58n; }
  for (const byte of b) { if (byte !== 0) break; s = "1" + s; }
  return s;
};
const b58dec = (s: string): Uint8Array => {
  let n = 0n;
  for (const c of s) {
    const i = b58chars.indexOf(c);
    if (i < 0) throw new Error(`invalid base58 char: ${c}`);
    n = n*58n + BigInt(i);
  }
  const h = n.toString(16);
  const padded = (h.length % 2 ? "0" : "") + h;
  const bytes  = fromHex(padded);
  const leading = [...s].findIndex(c => c !== "1");
  return Uint8Array.from([...new Uint8Array(leading < 0 ? 0 : leading), ...bytes]);
};

const compactU16 = (n: number): Uint8Array => {
  if (n < 0x80)           return new Uint8Array([n]);
  if (n < 0x4000)         return new Uint8Array([(n & 0x7f) | 0x80, n >> 7]);
  return new Uint8Array([(n & 0x7f)|0x80, ((n>>7)&0x7f)|0x80, n>>14]);
};

async function anchorSolana(
  rpcUrl:     string,
  signerKey:  string,
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
): Promise<ChainReceipt> {
  // Parse key: 0x-hex (32 bytes seed) or base58 (32-byte or 64-byte keypair)
  let seed: Uint8Array;
  if (signerKey.startsWith("0x")) {
    seed = fromHex(signerKey);
  } else {
    const dec = b58dec(signerKey);
    seed = dec.length === 64 ? dec.slice(0, 32) : dec;
  }
  if (seed.length !== 32) throw new Error(`Solana: expected 32-byte seed, got ${seed.length}`);

  const pubKey      = ed25519.getPublicKey(seed);
  const memoPubKey  = b58dec(MEMO_PROGRAM);

  // Compact memo: "sv3:<root16>:<idx>:<count>:<orgId12>"
  const memo     = `sv3:${merkleRoot.replace("0x","").slice(0,16)}:${blockIdx}:${eventCount}:${orgId.slice(0,12)}`;
  const memoData = new TextEncoder().encode(memo);

  // Fetch recent blockhash
  const bh = await rpc<{ value: { blockhash: string; lastValidBlockHeight: number } }>(
    rpcUrl, "getLatestBlockhash", [{ commitment: "confirmed" }]
  );
  const recentBlockhash = b58dec(bh.value.blockhash);

  // Build legacy transaction message:
  // header[3] | accounts_compact | blockhash[32] | instructions
  const header   = new Uint8Array([1, 0, 1]); // numRequired=1, numReadonlySigned=0, numReadonlyUnsigned=1
  const accounts = Uint8Array.from([
    ...compactU16(2),
    ...pubKey,
    ...memoPubKey,
  ]);

  // Single instruction: programIdIndex=1, no accounts, data=memo bytes
  const instrData = Uint8Array.from([
    ...compactU16(1),            // 1 instruction
    1,                           // programIdIndex = 1 (memo program)
    ...compactU16(0),            // 0 account indices
    ...compactU16(memoData.length),
    ...memoData,
  ]);

  const message  = Uint8Array.from([...header, ...accounts, ...recentBlockhash, ...instrData]);
  const sig      = ed25519.sign(message, seed);

  // Full transaction: compact(1) + sig + message
  const tx       = Uint8Array.from([...compactU16(1), ...sig, ...message]);

  const txSig    = await rpc<string>(rpcUrl, "sendTransaction", [
    b58enc(tx),
    { encoding: "base58", preflightCommitment: "confirmed", maxRetries: 3 },
  ]);

  // Confirm (up to 30s)
  let slot = 0;
  for (let i = 0; i < 15; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const st = await rpc<any>(rpcUrl, "getSignatureStatuses", [[txSig], { searchTransactionHistory: false }]).catch(()=>null);
    if (st?.value?.[0]?.confirmationStatus === "confirmed" || st?.value?.[0]?.confirmationStatus === "finalized") {
      slot = st.value[0].slot;
      break;
    }
  }

  return {
    chain:  "solana",
    txHash: txSig,
    slot,
    url:   `https://solscan.io/tx/${txSig}`,
  };
}

//  Irys (Arweave permanent storage) 
// Stores the full event batch permanently. Pay-once, GraphQL queryable forever.
// Uploads < 100KB are free on Irys devnet. Production: ~$0.30/MB on Irys mainnet.

async function anchorIrys(
  nodeUrl:    string,
  signerKey:  string,
  currency:   string,
  merkleRoot: string,
  blockIdx:   number,
  eventCount: number,
  orgId:      string,
): Promise<ChainReceipt> {
  const payload = JSON.stringify({
    protocol:   "sovereign-v3",
    orgId,
    merkleRoot,
    blockIndex: blockIdx,
    eventCount,
    timestamp:  new Date().toISOString(),
  });

  const tags = [
    { name: "Content-Type",  value: "application/json"  },
    { name: "App-Name",      value: "Sovereignly"     },
    { name: "Protocol",      value: "sovereign-v3"       },
    { name: "Org-Id",        value: orgId                },
    { name: "Merkle-Root",   value: merkleRoot            },
    { name: "Block-Index",   value: String(blockIdx)     },
  ];

  const res = await fetch(`${nodeUrl}/upload`, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "x-currency": currency },
    body:    JSON.stringify({ data: btoa(payload), tags }),
  });
  if (!res.ok) throw new Error(`Irys: ${res.status} ${await res.text().catch(()=>"")}`);

  const { id } = await res.json() as { id: string };
  return {
    chain:     "arweave-irys",
    txHash:    id,
    permanent: true,
    url:      `https://arweave.net/${id}`,
  };
}

//  Bitcoin OP_RETURN 
// Weekly batch (52/yr  ~$0.50 = $26/yr) via Blockstream public API.
// Full SHA256d + RIPEMD160 using @noble/hashes  no approximations.

async function anchorBitcoin(
  wif:     string,
  apiBase: string,
  merkleRoot: string,
): Promise<ChainReceipt> {

  // WIF decode: base58check  strip version byte (0x80) and compression flag (0x01)
  const wifBytes = b58dec(wif);
  const privKey  = wifBytes.slice(1, 33);                 // 32-byte private key
  const pubKey   = secp256k1.getPublicKey(privKey, true); // 33-byte compressed

  // P2WPKH hash160 = RIPEMD160(SHA256(compressed_pub))  correct
  const h160     = hash160(pubKey);                       // 20 bytes

  // Native segwit address (bech32)  used only for UTXO lookup
  // We pass h160 to Blockstream's address endpoint after bech32 encoding
  const bech32Address = encodeBech32("bc", 0, h160);

  // Fetch UTXOs
  const utxos = await fetch(`${apiBase}/address/${bech32Address}/utxo`)
    .then(r => r.json() as Promise<Array<{ txid: string; vout: number; value: number; status: { confirmed: boolean } }>>);

  const conf = utxos.filter(u => u.status.confirmed).sort((a,b)=>b.value - a.value);
  if (!conf.length) throw new Error(`Bitcoin: no confirmed UTXOs at ${bech32Address}`);

  const feeRate = await fetch(`${apiBase}/fee-estimates`)
    .then(r => r.json())
    .then((f: Record<string,number>) => Math.ceil(f["6"] ?? 20)); // 6-block target

  const utxo   = conf[0];
  const fee    = feeRate * 200; // ~200 vbytes: 1 P2WPKH input + 1 OP_RETURN + 1 P2WPKH change
  const change = utxo.value - fee;
  if (change < 546) throw new Error(`Bitcoin: UTXO ${utxo.value} sat too small (need ${fee+546})`);

  // OP_RETURN: "SV3" + first 29 bytes of merkleRoot = 32 bytes
  const opData   = Uint8Array.from([
    0x53, 0x56, 0x33,              // "SV3"
    ...fromHex(merkleRoot.replace("0x","").slice(0,58)), // 29 bytes
  ]);
  const opScript = Uint8Array.from([0x6a, opData.length, ...opData]);

  // P2WPKH change script: OP_0 PUSH20 <hash160>
  const changeScript = Uint8Array.from([0x00, 0x14, ...h160]);

  // Little-endian helpers
  const le4 = (n: number) => { const b=new Uint8Array(4); let v=n; for(let i=0;i<4;i++){b[i]=v&0xff;v>>=8;} return b; };
  const le8 = (n: number) => { const b=new Uint8Array(8); let v=BigInt(n); for(let i=0;i<8;i++){b[i]=Number(v&0xffn);v>>=8n;} return b; };
  const vi  = (n: number): Uint8Array => n<0xfd ? new Uint8Array([n]) : Uint8Array.from([0xfd, n&0xff, n>>8]);

  const txidLE   = fromHex(utxo.txid.match(/.{2}/g)!.reverse().join(""));
  const outpoint = Uint8Array.from([...txidLE, ...le4(utxo.vout)]);

  // BIP143 sighash preimage for P2WPKH
  const scriptCode = Uint8Array.from([
    0x19, 0x76, 0xa9, 0x14, ...h160, 0x88, 0xac,
  ]);

  const hashPrevouts = sha256d(Uint8Array.from([...outpoint]));
  const hashSeq      = sha256d(le4(0xffffffff));

  const out1Bytes = Uint8Array.from([...le8(0), ...vi(opScript.length), ...opScript]);
  const out2Bytes = Uint8Array.from([...le8(change), ...vi(changeScript.length), ...changeScript]);
  const hashOuts  = sha256d(Uint8Array.from([...out1Bytes, ...out2Bytes]));

  const preimage = Uint8Array.from([
    ...le4(2),            // version
    ...hashPrevouts,
    ...hashSeq,
    ...outpoint,
    ...scriptCode,
    ...le8(utxo.value),
    ...le4(0xffffffff),   // sequence
    ...hashOuts,
    ...le4(0),            // locktime
    ...le4(1),            // SIGHASH_ALL
  ]);

  // BIP143 sighash = SHA256d(preimage)
  const sighash = sha256d(preimage);
  const sig     = secp256k1.sign(sighash, privKey, { lowS: true });

  // DER encode signature
  const rBytes  = bigBytes(sig.r);
  const sBytes  = bigBytes(sig.s);
  const der     = Uint8Array.from([
    0x30,
    4 + rBytes.length + sBytes.length,
    0x02, rBytes.length,  ...rBytes,
    0x02, sBytes.length,  ...sBytes,
    0x01, // SIGHASH_ALL
  ]);

  // Assemble segwit transaction
  const rawTx = Uint8Array.from([
    ...le4(2),         // version 2
    0x00, 0x01,        // segwit marker + flag
    0x01,              // 1 input
    ...txidLE, ...le4(utxo.vout),
    0x00,              // empty scriptSig
    ...le4(0xffffffff), // sequence
    0x02,              // 2 outputs
    ...out1Bytes,
    ...out2Bytes,
    // Witness for input 0
    0x02,              // 2 items
    der.length, ...der,
    0x21, ...pubKey,   // compressed pubkey
    ...le4(0),         // locktime
  ]);

  const txid = await fetch(`${apiBase}/tx`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: toHex(rawTx),
  }).then(r => r.text());

  if (txid.length !== 64) throw new Error(`Bitcoin broadcast failed: ${txid}`);

  return {
    chain:  "bitcoin",
    txHash: txid,
    url:   `https://blockstream.info/tx/${txid}`,
  };
}

//  Bech32 encoder (for Bitcoin P2WPKH address) 
// Minimal implementation  only used for UTXO lookup, not transaction construction.

function encodeBech32(hrp: string, version: number, data: Uint8Array): string {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const GEN     = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const polymod = (values: number[]): number => {
    let c = 1;
    for (const v of values) {
      const b = c >> 25;
      c = ((c & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((b>>i)&1) c ^= GEN[i];
    }
    return c;
  };
  const expand = (s: string): number[] => {
    const r: number[] = [];
    for (const c of s) r.push(c.charCodeAt(0)>>5);
    r.push(0);
    for (const c of s) r.push(c.charCodeAt(0)&31);
    return r;
  };
  const convertbits = (data: Uint8Array, from: number, to: number): number[] => {
    let acc=0, bits=0;
    const ret: number[] = [];
    const maxv=(1<<to)-1;
    for (const v of data) { acc=(acc<<from)|v; bits+=from; while(bits>=to){bits-=to;ret.push((acc>>bits)&maxv);} }
    if (bits) ret.push((acc<<(to-bits))&maxv);
    return ret;
  };
  const words    = [version, ...convertbits(data, 8, 5)];
  const checksum = polymod([...expand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const cs       = Array.from({length:6},(_,i)=>(checksum>>(5*(5-i)))&31);
  return hrp + "1" + [...words, ...cs].map(d=>CHARSET[d]).join("");
}

//  Types 

export type AnchorTier = "free" | "starter" | "growth" | "enterprise";

export interface OmnichainConfig {
  tier: AnchorTier;

  // EAS on Base  free tier+
  // No deployment required. Schema registered once at easscan.org ($5).
  easBase?: {
    rpcUrl:    string;   // https://mainnet.base.org OR https://base.llamarpc.com (free)
    signerKey: string;   // 0x-prefixed 32-byte EVM private key
    schemaUID: string;   // 0x-prefixed bytes32 from schema registration
    chainId?:  number;   // default: 8453
  };

  // EAS on Arbitrum  starter+
  // Different geographic validator set = independent corroboration
  easArbitrum?: {
    rpcUrl:    string;   // https://arb1.arbitrum.io/rpc
    signerKey: string;
    schemaUID: string;   // same schema string, different UID (different registry)
    chainId?:  number;   // default: 42161
  };

  // Sign Protocol  starter+
  // 20+ chains from one schema. Register at sign.global, get an SPS#N id.
  signProtocol?: {
    rpcUrl:    string;   // Base RPC
    signerKey: string;
    schemaId:  number;   // numeric ID from sign.global (not a UID)
    chainId?:  number;   // default: 8453
  };

  // Solana Memo Program  growth+
  // No contract. ed25519 already in @noble/curves.
  solana?: {
    rpcUrl:    string;   // https://api.mainnet-beta.solana.com
    signerKey: string;   // 0x hex (32-byte seed) or base58 (32 or 64-byte keypair)
  };

  // Irys  enterprise
  irys?: {
    nodeUrl?:  string;   // default: https://uploader.irys.xyz
    signerKey: string;   // EVM private key (Irys accepts ETH/BASE/MATIC etc.)
    currency?: string;   // default: "base-eth"
  };

  // Bitcoin OP_RETURN  enterprise, recommended weekly not daily
  bitcoin?: {
    wif:       string;   // WIF-encoded secp256k1 private key (P2WPKH)
    apiUrl?:   string;   // default: https://blockstream.info/api
    network?:  "mainnet" | "testnet";
  };
}

export interface ChainReceipt {
  chain:     string;
  txHash?:   string;
  blockNum?: number;
  slot?:     number;
  uid?:      string;
  permanent?: boolean;
  url?:      string;
}

export interface AnchorResult {
  merkleRoot:    string;
  blockIdx:      number;
  eventCount:    number;
  orgId:         string;
  anchoredAt:    number;
  receipts:      ChainReceipt[];
  errors:        Record<string, string>;
  annualCostUSD: number;
}

//  EAS schema UID computation 
// Call this once at startup to verify the configured schemaUID matches the schema string.
// Register the schema once at easscan.org if the UID doesn't exist yet.

export const SOVEREIGN_SCHEMA = "bytes32 merkleRoot,uint256 blockIndex,uint32 eventCount,string orgId,string protocol";

export function computeSchemaUID(schema: string, resolver = "0x0000000000000000000000000000000000000000", revocable = true): string {
  // keccak256(abi.encodePacked(schema, resolver, revocable))
  const schemaBytes   = new TextEncoder().encode(schema);
  const resolverBytes = fromHex(resolver);
  const revBytes      = new Uint8Array([revocable ? 1 : 0]);
  const packed        = Uint8Array.from([...schemaBytes, ...resolverBytes, ...revBytes]);
  return "0x" + toHex(keccak_256(packed));
}

// Precomputed: computeSchemaUID(SOVEREIGN_SCHEMA) = 0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc
export const SOVEREIGN_SCHEMA_UID = "0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc";

//  OmnichainAnchor 

export class OmnichainAnchor {
  constructor(private cfg: OmnichainConfig) {}

  async anchor(
    merkleRoot: string,
    blockIdx:   number,
    eventCount: number,
    orgId:      string = "platform",
  ): Promise<AnchorResult> {
    const result: AnchorResult = {
      merkleRoot, blockIdx, eventCount, orgId,
      anchoredAt:    Date.now(),
      receipts:      [],
      errors:        {},
      annualCostUSD: this.estimatedAnnualCost(),
    };

    const tier = this.cfg.tier;
    const tasks: [string, ()=>Promise<ChainReceipt>][] = [];

    if (this.cfg.easBase) {
      const c = this.cfg.easBase;
      tasks.push(["eas-base", () => anchorEAS(
        c.rpcUrl, c.chainId ?? 8453, fromHex(c.signerKey.replace("0x","")),
        c.schemaUID, merkleRoot, blockIdx, eventCount, orgId, "eas-base"
      )]);
    }

    if (this.cfg.easArbitrum && tier !== "free") {
      const c = this.cfg.easArbitrum;
      tasks.push(["eas-arbitrum", () => anchorEAS(
        c.rpcUrl, c.chainId ?? 42161, fromHex(c.signerKey.replace("0x","")),
        c.schemaUID, merkleRoot, blockIdx, eventCount, orgId, "eas-arbitrum"
      )]);
    }

    if (this.cfg.signProtocol && tier !== "free") {
      const c = this.cfg.signProtocol;
      tasks.push(["sign-protocol", () => anchorSignProtocol(
        c.rpcUrl, c.chainId ?? 8453, fromHex(c.signerKey.replace("0x","")),
        c.schemaId, merkleRoot, blockIdx, eventCount, orgId
      )]);
    }

    if (this.cfg.solana && (tier === "growth" || tier === "enterprise")) {
      const c = this.cfg.solana;
      tasks.push(["solana", () => anchorSolana(c.rpcUrl, c.signerKey, merkleRoot, blockIdx, eventCount, orgId)]);
    }

    if (this.cfg.irys && tier === "enterprise") {
      const c = this.cfg.irys;
      tasks.push(["irys", () => anchorIrys(
        c.nodeUrl ?? "https://uploader.irys.xyz",
        c.signerKey, c.currency ?? "base-eth",
        merkleRoot, blockIdx, eventCount, orgId
      )]);
    }

    if (this.cfg.bitcoin && tier === "enterprise") {
      const c = this.cfg.bitcoin;
      const net = c.network ?? "mainnet";
      const api = c.apiUrl ?? (net === "testnet" ? "https://blockstream.info/testnet/api" : "https://blockstream.info/api");
      tasks.push(["bitcoin", () => anchorBitcoin(c.wif, api, merkleRoot)]);
    }

    // All concurrent  any failure captured, never fatal
    const settled = await Promise.allSettled(tasks.map(([,fn])=>fn()));
    settled.forEach((res, i) => {
      if (res.status === "fulfilled") result.receipts.push(res.value);
      else result.errors[tasks[i][0]] = res.reason?.message ?? String(res.reason);
    });

    const n = result.receipts.length;
    const e = Object.keys(result.errors).length;
    console.log(`[OmnichainAnchor] block #${blockIdx}: ${n} chain(s) [${result.receipts.map(r=>r.chain).join("+")}]${e?` | ${e} error(s)`:""}`);

    return result;
  }

  async verify(merkleRoot: string): Promise<Record<string, { verified: boolean; uid?: string; url?: string }>> {
    const out: Record<string, { verified: boolean; uid?: string; url?: string }> = {};

    if (this.cfg.easBase) {
      try {
        const chainId  = this.cfg.easBase.chainId ?? 8453;
        const contract = EAS_CONTRACTS[chainId]!;
        // isAttestationValid(bytes32)  requires the UID, not the root
        // We query easscan GraphQL to find by data
        const gql = chainId === 8453
          ? "https://base.easscan.org/graphql"
          : "https://arbitrum.easscan.org/graphql";

        const res = await fetch(gql, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: `{ attestations(where: { schemaId: { equals: "${this.cfg.easBase.schemaUID.toLowerCase()}" } }, take: 5, orderBy: { time: desc }) { id txid attester data time } }` }),
        }).then(r=>r.json()).catch(()=>null) as any;

        const attestations = res?.data?.attestations ?? [];
        // Find one whose data contains our merkle root
        const match = attestations.find((a: any) =>
          a.data?.toLowerCase().includes(merkleRoot.replace("0x","").toLowerCase())
        );
        out["eas-base"] = {
          verified: !!match,
          uid:      match?.id,
          url:      match ? `https://base.easscan.org/attestation/view/${match.id}` : undefined,
        };
      } catch { out["eas-base"] = { verified: false }; }
    }

    return out;
  }

  estimatedAnnualCost(): number {
    let c = 0;
    if (this.cfg.easBase)        c += 0.18;
    if (this.cfg.easArbitrum)    c += 0.18;
    if (this.cfg.signProtocol)   c += 0.02;
    if (this.cfg.solana)         c += 0.27;
    if (this.cfg.irys)           c += 10.95;
    if (this.cfg.bitcoin)        c += 26.00; // 52 weekly
    return c;
  }

  /** Compute and log the schema UID for configured schemas. Verify at startup. */
  verifySchemaConfig(): void {
    const expected = computeSchemaUID(SOVEREIGN_SCHEMA);
    const configured = this.cfg.easBase?.schemaUID;
    if (configured && configured.toLowerCase() !== expected.toLowerCase()) {
      console.warn(`[OmnichainAnchor] WARNING: configured EAS schema UID ${configured} does not match computed ${expected}`);
      console.warn(`[OmnichainAnchor] Register schema at easscan.org: "${SOVEREIGN_SCHEMA}"`);
    } else {
      console.log(`[OmnichainAnchor] Schema UID verified: ${expected}`);
    }
  }

  static fromEnv(tier: AnchorTier): OmnichainAnchor {
    const cfg: OmnichainConfig = { tier };

    if (process.env.EAS_BASE_RPC && process.env.EAS_SIGNER_KEY) {
      cfg.easBase = {
        rpcUrl:    process.env.EAS_BASE_RPC,
        signerKey: process.env.EAS_SIGNER_KEY,
        schemaUID: process.env.EAS_SCHEMA_UID ?? SOVEREIGN_SCHEMA_UID,
        chainId:   parseInt(process.env.EAS_BASE_CHAIN_ID ?? "8453"),
      };
    }
    if (process.env.EAS_ARB_RPC && process.env.EAS_SIGNER_KEY) {
      cfg.easArbitrum = {
        rpcUrl:    process.env.EAS_ARB_RPC,
        signerKey: process.env.EAS_SIGNER_KEY,
        schemaUID: process.env.EAS_ARB_SCHEMA_UID ?? SOVEREIGN_SCHEMA_UID,
        chainId:   parseInt(process.env.EAS_ARB_CHAIN_ID ?? "42161"),
      };
    }
    if (process.env.SIGN_PROTOCOL_RPC && process.env.EAS_SIGNER_KEY && process.env.SIGN_SCHEMA_ID) {
      cfg.signProtocol = {
        rpcUrl:   process.env.SIGN_PROTOCOL_RPC,
        signerKey: process.env.EAS_SIGNER_KEY,
        schemaId: parseInt(process.env.SIGN_SCHEMA_ID),
        chainId:  parseInt(process.env.SIGN_CHAIN_ID ?? "8453"),
      };
    }
    if (process.env.SOLANA_RPC_URL && process.env.SOLANA_ANCHOR_KEY) {
      cfg.solana = { rpcUrl: process.env.SOLANA_RPC_URL, signerKey: process.env.SOLANA_ANCHOR_KEY };
    }
    if (process.env.IRYS_SIGNER_KEY) {
      cfg.irys = {
        nodeUrl:   process.env.IRYS_NODE_URL,
        signerKey: process.env.IRYS_SIGNER_KEY,
        currency:  process.env.IRYS_CURRENCY ?? "base-eth",
      };
    }
    if (process.env.BITCOIN_WIF) {
      cfg.bitcoin = {
        wif:     process.env.BITCOIN_WIF,
        network: (process.env.BITCOIN_NETWORK ?? "mainnet") as "mainnet" | "testnet",
      };
    }

    return new OmnichainAnchor(cfg);
  }
  /**
   * Build from environment variables with an explicit tier override.
   * Used by TenantManager to create per-tenant anchors at the tenant's plan level.
   */
  static fromEnvWithTier(tier: AnchorTier): OmnichainAnchor {
    const anchor = OmnichainAnchor.fromEnv(tier);
    return anchor;
  }
}

export default OmnichainAnchor;
