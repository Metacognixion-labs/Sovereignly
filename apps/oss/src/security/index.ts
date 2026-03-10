export { SovereignChain } from "./chain.ts";
export { OmnichainAnchor } from "./omnichain-anchor.ts";
export * from "./crypto.ts";

// Security hardening modules (v4.0)
export { SSRFGuard, SSRFError } from "./ssrf-guard.ts";
export { InputShield, inputShield } from "./input-shield.ts";
export { IntentGuard } from "./intent-guard.ts";
export { HybridSigner, HybridKEM, DualMerkleTree, sha3Hash, sha3HashRaw, hmacSha3 } from "./pqc.ts";
