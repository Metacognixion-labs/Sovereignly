/**
 * @sovereignly/core -- Shared Types & Cryptographic Primitives
 * MIT License
 *
 * This package re-exports the types and crypto functions used by both
 * the OSS server and the Cloud premium features. It exists so that
 * apps/cloud can import types without reaching into apps/oss internals.
 *
 * Types: Block, AuditEvent, AuditEventType, ChainConfig, ChainStats
 * Crypto: sha256, keccak256, MerkleTree, generateNodeKeyPair, signEd25519, etc.
 */

// -- Types --------------------------------------------------------------------

export type AuditEventType =
  | "FUNCTION_DEPLOY" | "FUNCTION_DELETE" | "FUNCTION_INVOKE"
  | "AUTH_SUCCESS" | "AUTH_FAILURE"
  | "CONFIG_CHANGE" | "SECRET_ROTATION"
  | "RATE_LIMIT_HIT" | "ANOMALY"
  | "WORKER_CRASH"
  | "NODE_JOIN" | "NODE_LEAVE"
  | "CHAIN_GENESIS" | "MERIDIAN_ANCHOR"
  | "DATA_READ" | "DATA_EXPORT"
  | "SESSION_END" | "MFA_CHALLENGE"
  | "PERMISSION_CHANGE";

export type EventSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AuditEvent {
  id:          string;
  type:        AuditEventType;
  ts:          number;
  nodeId:      string;
  severity:    EventSeverity;
  payload:     Record<string, unknown>;
  blockIndex?: number;
  merkleProof?: string;
}

export interface Block {
  index:      number;
  ts:         number;
  prevHash:   string;
  merkleRoot: string;
  eventCount: number;
  nodeId:     string;
  signature:  string;
  blockHash:  string;
  acks:       Array<{ nodeId: string; sig: string }>;
}

export interface ChainStats {
  blocks:    number;
  events:    number;
  anchored:  number;
  critical:  number;
  tip:       Block | null;
}

export type TenantPlan = "free" | "starter" | "growth" | "enterprise";
export type TenantStatus = "active" | "suspended" | "pending" | "cancelled";
export type AnchorTier = "free" | "starter" | "growth" | "enterprise";

export interface Tenant {
  id:            string;
  name:          string;
  slug:          string;
  plan:          TenantPlan;
  status:        TenantStatus;
  ownerId:       string;
  domain?:       string;
  stripeCustomerId?: string;
  stripeSubId?:      string;
  limits: {
    eventsPerMonth: number;
    functionsMax:   number;
    storageGB:      number;
    kvKeysMax:      number;
    seatsMax:       number;
  };
  createdAt: number;
  updatedAt: number;
}

export interface AnchorReceipt {
  chain:    string;
  txHash:   string;
  blockNum: number;
  uid?:     string;
  url?:     string;
}

export interface ComplianceReport {
  standard:      string;
  overallScore:  number;
  controls:      Array<{ id: string; name: string; status: string; score: number }>;
  generatedAt:   string;
  tenantId?:     string;
}
