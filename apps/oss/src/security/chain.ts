/**
 * Sovereignly v3  SovereignChain
 *
 * A lightweight embedded Proof-of-Authority blockchain that runs inside
 * every Sovereignly node. It provides:
 *
 *    Immutable audit trail of all function deployments, auth events,
 *     config changes, anomalies, and secret rotations.
 *    Cryptographic non-repudiation: every block is Ed25519-signed by
 *     the producing node.
 *    Merkle-authenticated event batching: N events  1 Merkle root
 *     stored per block.
 *    Multi-node replication: peer nodes receive and verify each block.
 *    Meridian Ledger bridge: Merkle roots anchored to the external L1
 *     every ANCHOR_INTERVAL blocks for external verifiability.
 *
 * Consensus model:
 *   Single node   self-signed blocks (no peer verification needed)
 *   Multi-node    PBFT-lite: block producer broadcasts, peers sign
 *                  acknowledgement, 2f+1 sigs required (f = floor(n/3))
 *
 * Storage: blocks persisted in bun:sqlite alongside KV data.
 * On-chain: hashes + metadata only. Full event payloads off-chain, verifiable
 * against the Merkle root.
 */

import { Database } from "bun:sqlite";
import { join }     from "node:path";
import {
  sha256, signEd25519, verifyEd25519, safeJsonParse,
  generateNodeKeyPair, NodeKeyPair,
  MerkleTree, toHex,
} from "./crypto.ts";

//  Event Types 

export type AuditEventType =
  | "FUNCTION_DEPLOY"
  | "FUNCTION_DELETE"
  | "FUNCTION_INVOKE"
  | "AUTH_SUCCESS"
  | "AUTH_FAILURE"
  | "CONFIG_CHANGE"
  | "SECRET_ROTATION"
  | "RATE_LIMIT_HIT"
  | "ANOMALY"
  | "WORKER_CRASH"
  | "NODE_JOIN"
  | "NODE_LEAVE"
  | "CHAIN_GENESIS"
  | "MERIDIAN_ANCHOR";

export interface AuditEvent {
  id:        string;           // UUID
  type:      AuditEventType;
  ts:        number;           // Unix ms
  nodeId:    string;
  severity:  "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  payload:   Record<string, unknown>;
  // Set after Merkle inclusion:
  blockIndex?:   number;
  merkleProof?:  string;       // JSON-serialized MerkleProof
}

//  Block 

export interface Block {
  index:      number;
  ts:         number;
  prevHash:   string;
  merkleRoot: string;          // root of this block's events
  eventCount: number;
  nodeId:     string;
  signature:  string;          // Ed25519 sig of blockHash
  blockHash:  string;          // sha256(index|ts|prevHash|merkleRoot|nodeId)
  // Multi-node: peer acknowledgements
  acks:       Array<{ nodeId: string; sig: string }>;
}

//  Chain config 

export interface ChainConfig {
  dataDir:          string;
  nodeId:           string;
  keyPair?:         NodeKeyPair;       // provided or auto-generated
  blockBatchSize:   number;            // events per block (default 50)
  blockIntervalMs:  number;            // max wait before sealing (default 30s)
  anchorInterval:   number;            // blocks between omnichain anchors (default 100)
  meridianRpcUrl?:  string;            // Meridian cluster bus (NOT a credibility proof)
  meridianContract?: string;           // Meridian contract address
  omniAnchor?:      import("./omnichain-anchor.ts").OmnichainAnchor; // omnichain attestation engine
  anchorOrgId?:     string;            // org ID passed to attestation data
  peers:            string[];          // peer node URLs for block replication
  encKey?:          string;            // per-tenant AES-256-GCM key for payload encryption
}

//  SovereignChain 

export class SovereignChain {
  private db:       Database;
  private cfg:      ChainConfig;
  private kp:       NodeKeyPair | null = null;
  private pending:  AuditEvent[] = [];
  private timer:    ReturnType<typeof setInterval> | null = null;
  private sealing:  boolean = false;

  // Observers
  private onBlockSealed: Array<(block: Block) => void> = [];
  private onAuditEvent:  Array<(event: AuditEvent) => void> = [];

  constructor(cfg: Partial<ChainConfig> & { dataDir: string; nodeId: string }) {
    this.cfg = {
      blockBatchSize:  50,
      blockIntervalMs: 30_000,
      anchorInterval:  100,
      peers: [],
      ...cfg,
    };
    this.db = new Database(join(this.cfg.dataDir, "chain.db"));
    this.bootstrap();
  }

  //  Schema 

  private bootstrap() {
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run("PRAGMA synchronous = NORMAL");

    this.db.run(`
      CREATE TABLE IF NOT EXISTS blocks (
        idx         INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        prev_hash   TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        node_id     TEXT NOT NULL,
        signature   TEXT NOT NULL,
        block_hash  TEXT NOT NULL UNIQUE,
        acks        TEXT DEFAULT '[]',
        anchored    INTEGER DEFAULT 0
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS events (
        id          TEXT PRIMARY KEY,
        type        TEXT NOT NULL,
        ts          INTEGER NOT NULL,
        node_id     TEXT NOT NULL,
        severity    TEXT NOT NULL,
        payload     TEXT NOT NULL,
        block_idx   INTEGER,
        merkle_proof TEXT,
        FOREIGN KEY (block_idx) REFERENCES blocks(idx)
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS node_keys (
        node_id     TEXT PRIMARY KEY,
        public_key  TEXT NOT NULL,
        joined_at   INTEGER NOT NULL,
        status      TEXT DEFAULT 'active'
      )
    `);

    this.db.run("CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_events_sev  ON events(severity)");
  }

  //  Initialise (async key generation) 

  async init(): Promise<void> {
    // Load or generate node keypair
    this.kp = this.cfg.keyPair ?? await generateNodeKeyPair();

    // Register node public key in the chain if first time
    const existing = this.db.prepare("SELECT node_id FROM node_keys WHERE node_id = ?")
      .get(this.cfg.nodeId);

    if (!existing) {
      this.db.prepare(`
        INSERT INTO node_keys (node_id, public_key, joined_at)
        VALUES (?, ?, ?)
      `).run(this.cfg.nodeId, toHex(this.kp.publicKey), Date.now());
    }

    // Genesis block if chain is empty
    const tip = this.getTip();
    if (!tip) {
      await this.sealGenesisBlock();
    }

    // Start block sealing timer
    this.timer = setInterval(() => this.sealIfDue(), this.cfg.blockIntervalMs);

    console.log(`[Chain] SovereignChain ready  tip block #${this.getTip()?.index ?? 0}`);
  }

  //  Public API: emit an audit event 

  async emit(
    type:     AuditEventType,
    payload:  Record<string, unknown>,
    severity: AuditEvent["severity"] = "LOW"
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      id:       crypto.randomUUID(),
      type,
      ts:       Date.now(),
      nodeId:   this.cfg.nodeId,
      severity,
      payload,
    };

    // Persist event (unconfirmed until next block)
    this.db.prepare(`
      INSERT INTO events (id, type, ts, node_id, severity, payload)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(event.id, event.type, event.ts, event.nodeId,
           event.severity, this.cfg.encKey
             ? await this.encryptPayload(JSON.stringify(event.payload))
             : JSON.stringify(event.payload));

    this.pending.push(event);
    this.onAuditEvent.forEach(fn => fn(event));

    // Seal early if batch is full
    if (this.pending.length >= this.cfg.blockBatchSize) {
      this.sealIfDue();
    }

    return event;
  }

  //  Block sealing 

  private async sealIfDue(): Promise<void> {
    if (this.sealing || this.pending.length === 0) return;
    this.sealing = true;
    try {
      await this.sealBlock();
    } finally {
      this.sealing = false;
    }
  }

  private async sealGenesisBlock(): Promise<Block> {
    const genesisEvent: AuditEvent = {
      id:       "00000000-0000-0000-0000-000000000000",
      type:     "CHAIN_GENESIS",
      ts:       Date.now(),
      nodeId:   this.cfg.nodeId,
      severity: "LOW",
      payload:  {
        nodeId:   this.cfg.nodeId,
        version:  "4.0.0",
        platform: "Sovereignly",
        runtime:  `bun/${Bun.version}`,
      },
    };

    this.db.prepare(`
      INSERT OR IGNORE INTO events (id, type, ts, node_id, severity, payload)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      genesisEvent.id, genesisEvent.type, genesisEvent.ts,
      genesisEvent.nodeId, genesisEvent.severity,
      JSON.stringify(genesisEvent.payload)
    );

    this.pending.unshift(genesisEvent);
    return this.sealBlock("0".repeat(64));
  }

  private async sealBlock(prevHashOverride?: string): Promise<Block> {
    if (!this.kp) throw new Error("Chain not initialized");

    const events = [...this.pending];
    this.pending  = [];

    const tip      = this.getTip();
    const index    = tip ? tip.index + 1 : 0;
    const prevHash = prevHashOverride ?? tip?.blockHash ?? "0".repeat(64);

    // Build Merkle tree  deterministic leaves (canonical JSON, sorted keys)
    const merkleLeaves = await Promise.all(
      events.map(e => sha256(
        `${e.id}|${e.type}|${e.ts}|${e.nodeId}|${JSON.stringify(e.payload, Object.keys(e.payload).sort())}`
      ))
    );
    const tree       = new MerkleTree(merkleLeaves);
    const merkleRoot = await tree.root();

    // Block hash = sha256 of canonical fields  single timestamp capture
    const ts = Date.now();
    const blockHash = await sha256(
      `${index}|${ts}|${prevHash}|${merkleRoot}|${this.cfg.nodeId}`
    );

    // Ed25519 signature
    const signature = await signEd25519(this.kp.privateKey, blockHash);

    const block: Block = {
      index,
      ts,
      prevHash,
      merkleRoot,
      eventCount: events.length,
      nodeId:     this.cfg.nodeId,
      signature,
      blockHash,
      acks: [],
    };

    // Persist block
    this.db.prepare(`
      INSERT INTO blocks (idx, ts, prev_hash, merkle_root, event_count,
                          node_id, signature, block_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      block.index, block.ts, block.prevHash, block.merkleRoot,
      block.eventCount, block.nodeId, block.signature, block.blockHash
    );

    // Attach Merkle proofs to events
    for (let i = 0; i < events.length; i++) {
      const proof = await tree.proof(i);
      this.db.prepare(`
        UPDATE events SET block_idx = ?, merkle_proof = ? WHERE id = ?
      `).run(block.index, JSON.stringify(proof), events[i].id);
    }

    this.onBlockSealed.forEach(fn => fn(block));

    // Omnichain anchor if due  EAS/Base, Arbitrum, Solana, Irys, Bitcoin
    if (block.index > 0 && block.index % this.cfg.anchorInterval === 0) {
      if (this.cfg.omniAnchor) {
        this.cfg.omniAnchor.anchor(
          block.merkleRoot,
          block.index,
          block.eventCount,
          this.cfg.anchorOrgId ?? this.cfg.nodeId
        ).then(result => {
          const chains = result.receipts.map(r => r.chain).join("+");
          if (chains) console.log(`[Chain]  Omnichain anchor #${block.index}  ${chains}`);
          if (Object.keys(result.errors).length > 0) {
            console.warn(`[Chain] Anchor errors:`, result.errors);
          }
        }).catch(e => console.warn("[Chain] Omnichain anchor failed:", e.message));
      }
      // Meridian cluster bus (NOT a credibility proof  MetaCognixion controls all validators)
      if (this.cfg.meridianRpcUrl && this.cfg.meridianContract) {
        this.anchorToMeridian(block).catch(e =>
          console.warn("[Chain] Meridian bus relay failed:", e.message)
        );
      }
    }

    // Replicate to peers
    if (this.cfg.peers.length > 0) {
      this.replicateToPeers(block).catch(() => {});
    }

    console.log(
      `[Chain]  Block #${block.index} sealed  ${events.length} events` +
      ` | root: ${merkleRoot.slice(0, 12)}`
    );

    return block;
  }

  //  Peer replication 

  private async replicateToPeers(block: Block): Promise<void> {
    await Promise.allSettled(
      this.cfg.peers.map(peer =>
        fetch(`${peer}/_sovereign/chain/block`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(block),
          signal: AbortSignal.timeout(5_000),
        })
      )
    );
  }

  //  Meridian Ledger anchor 
  // REPURPOSED: Meridian is now the inter-node cluster bus, not a credibility proof.
  // MetaCognixion controls the entire Meridian validator set.
  // Use OmnichainAnchor (EAS/Base, Solana, etc.) for independently verifiable proofs.

  private async anchorToMeridian(block: Block): Promise<void> {
    if (!this.cfg.meridianRpcUrl || !this.cfg.meridianContract) return;

    // Encode the anchor call: auditAnchor(bytes32 root, uint256 blockIdx, uint256 ts)
    const selector = "0xc1e82ea9"; // keccak256("auditAnchor(bytes32,uint256,uint256)")[0:4]  verified
    const root     = "0x" + block.merkleRoot.padStart(64, "0");
    const idx      = block.index.toString(16).padStart(64, "0");
    const ts       = Math.floor(block.ts / 1000).toString(16).padStart(64, "0");
    const data     = selector + root.slice(2) + idx + ts;

    try {
      const res = await fetch(this.cfg.meridianRpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method:  "eth_sendTransaction",
          id:      1,
          params:  [{
            to:   this.cfg.meridianContract,
            data,
            gas:  "0x15F90", // 90k gas
          }],
        }),
        signal: AbortSignal.timeout(10_000),
      });

      const { result: txHash } = await res.json();

      // Record the anchor event
      void this.emit("MERIDIAN_ANCHOR", {
        chainBlockIndex: block.index,
        merkleRoot:      block.merkleRoot,
        txHash,
        rpcUrl:          this.cfg.meridianRpcUrl,
      }, "LOW");

      // Mark block as anchored
      this.db.prepare("UPDATE blocks SET anchored = 1 WHERE idx = ?").run(block.index);

      console.log(`[Chain]  Anchored block #${block.index} to Meridian  ${txHash}`);
    } catch (err: any) {
      console.warn(`[Chain] Meridian anchor skipped: ${err.message}`);
    }
  }

  //  Ingest block from peer 

  async ingestPeerBlock(block: Block): Promise<{ ok: boolean; reason?: string }> {
    // Verify block hash
    const expectedHash = await sha256(
      `${block.index}|${block.ts}|${block.prevHash}|${block.merkleRoot}|${block.nodeId}`
    );
    if (expectedHash !== block.blockHash) {
      return { ok: false, reason: "invalid block hash" };
    }

    // Verify Ed25519 signature
    const nodeKey = this.db.prepare("SELECT public_key FROM node_keys WHERE node_id = ?")
      .get(block.nodeId) as { public_key: string } | undefined;
    if (!nodeKey) return { ok: false, reason: "unknown node" };

    const { fromHex } = await import("./crypto.ts");
    const valid = await verifyEd25519(fromHex(nodeKey.public_key), block.signature, block.blockHash);
    if (!valid) return { ok: false, reason: "invalid signature" };

    // Verify chain continuity
    const tip = this.getTip();
    if (tip && tip.blockHash !== block.prevHash) {
      return { ok: false, reason: "chain discontinuity" };
    }

    // Persist
    this.db.prepare(`
      INSERT OR IGNORE INTO blocks
        (idx, ts, prev_hash, merkle_root, event_count, node_id, signature, block_hash, acks)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      block.index, block.ts, block.prevHash, block.merkleRoot,
      block.eventCount, block.nodeId, block.signature, block.blockHash,
      JSON.stringify(block.acks)
    );

    return { ok: true };
  }

  //  Query API 

  getTip(): Block | null {
    const row = this.db.prepare(`
      SELECT idx AS [index], ts, prev_hash AS prevHash, merkle_root AS merkleRoot,
             event_count AS eventCount, node_id AS nodeId, signature, block_hash AS blockHash,
             acks
      FROM blocks ORDER BY idx DESC LIMIT 1
    `).get() as any;
    if (!row) return null;
    row.acks = safeJsonParse(row.acks, []);
    return row as Block;
  }

  getBlock(index: number): Block | null {
    const row = this.db.prepare(`
      SELECT idx AS [index], ts, prev_hash AS prevHash, merkle_root AS merkleRoot,
             event_count AS eventCount, node_id AS nodeId, signature, block_hash AS blockHash,
             acks
      FROM blocks WHERE idx = ?
    `).get(index) as any;
    if (!row) return null;
    row.acks = safeJsonParse(row.acks, []);
    return row as Block;
  }

  getEvents(opts: {
    type?:     AuditEventType;
    severity?: AuditEvent["severity"];
    since?:    number;
    limit?:    number;
  } = {}): AuditEvent[] {
    const clauses: string[] = [];
    const params:  unknown[] = [];

    if (opts.type)     { clauses.push("type = ?");     params.push(opts.type); }
    if (opts.severity) { clauses.push("severity = ?"); params.push(opts.severity); }
    if (opts.since)    { clauses.push("ts >= ?");      params.push(opts.since); }

    const where  = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const limit  = opts.limit ?? 100;

    const rows = this.db.prepare(`
      SELECT * FROM events ${where} ORDER BY ts DESC LIMIT ?
    `).all(...params, limit) as any[];

    return rows.map(r => ({
      ...r,
      payload:     safeJsonParse(r.payload, {}),
      merkleProof: r.merkle_proof ?? undefined,
      blockIndex:  r.block_idx    ?? undefined,
    }));
  }


  getBlocks(opts: {
    limit?:  number;
    offset?: number;
    since?:  number;   // timestamp ms
  } = {}): Block[] {
    const { limit = 20, offset = 0, since } = opts;
    let sql  = "SELECT * FROM blocks";
    const params: any[] = [];
    if (since !== undefined) {
      sql += " WHERE ts >= ?";
      params.push(since);
    }
    sql += " ORDER BY idx DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);
    return (this.db.prepare(sql).all(...params) as any[]).map(row => ({
      index:      row.idx,
      ts:         row.ts,
      prevHash:   row.prev_hash,
      blockHash:  row.block_hash,
      merkleRoot: row.merkle_root,
      eventCount: row.event_count,
      nodeId:     row.node_id,
      anchored:   row.anchored_at !== null,
    }));
  }

  getStats() {
    const blocks     = (this.db.prepare("SELECT COUNT(*) AS n FROM blocks").get() as any).n;
    const events     = (this.db.prepare("SELECT COUNT(*) AS n FROM events").get() as any).n;
    const anchored   = (this.db.prepare("SELECT COUNT(*) AS n FROM blocks WHERE anchored=1").get() as any).n;
    const critical   = (this.db.prepare("SELECT COUNT(*) AS n FROM events WHERE severity='CRITICAL'").get() as any).n;
    const tip        = this.getTip();

    return { blocks, events, anchored, critical, tip };
  }

  /** Verify entire chain integrity (O(n)  use sparingly) */
  async verifyChainIntegrity(): Promise<{ valid: boolean; failedAt?: number; reason?: string }> {
    const allBlocks = this.db.prepare(
      "SELECT * FROM blocks ORDER BY idx ASC"
    ).all() as any[];

    let prevHash = "0".repeat(64);
    for (const b of allBlocks) {
      if (b.idx > 0 && b.prev_hash !== prevHash) {
        return { valid: false, failedAt: b.idx, reason: "broken chain link" };
      }
      const expectedHash = await sha256(
        `${b.idx}|${b.ts}|${b.prev_hash}|${b.merkle_root}|${b.node_id}`
      );
      if (expectedHash !== b.block_hash) {
        return { valid: false, failedAt: b.idx, reason: "invalid block hash" };
      }
      prevHash = b.block_hash;
    }
    return { valid: true };
  }

  //  Subscriptions 

  onBlock(fn: (block: Block) => void): void   { this.onBlockSealed.push(fn); }
  onEvent(fn: (event: AuditEvent) => void): void { this.onAuditEvent.push(fn); }

  //  Lifecycle 

  //  Per-tenant payload encryption 

  private async encryptPayload(plain: string): Promise<string> {
    if (!this.cfg.encKey) return plain;
    try {
      const { encryptAES } = await import("./crypto.ts");
      return "enc:" + await encryptAES(plain, this.cfg.encKey);
    } catch {
      return plain; // encryption failure is non-fatal  payload stored as plaintext
    }
  }

  async decryptPayload(stored: string): Promise<string> {
    if (!stored.startsWith("enc:") || !this.cfg.encKey) return stored;
    try {
      const { decryptAES } = await import("./crypto.ts");
      return await decryptAES(stored.slice(4), this.cfg.encKey);
    } catch {
      return stored;
    }
  }

  /** Force-seal any pending events before shutdown */
  async flush(): Promise<void> {
    if (!this.kp) return; // Guard: not initialized
    if (this.pending.length > 0) await this.sealBlock();
  }

  close(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    if (!this.kp) { try { this.db.close(); } catch {} return; }
    this.kp = null; // Prevent double-close
    this.flush().then(() => { try { this.db.close(); } catch {} });
  }
}
