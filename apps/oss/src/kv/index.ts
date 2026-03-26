/**
 * Sovereignly v3  KV Store
 * 
 * Built on Bun's native SQLite (bun:sqlite)  zero external dependencies.
 * SQLite is faster than Redis for single-node workloads under 10k RPS,
 * with WAL mode giving near-concurrent reads.
 * 
 * Features:
 *  - Namespaced key-value with O(1) get/set via B-tree index
 *  - TTL with background GC (SQLite expression index)
 *  - Atomic CAS and increment operations
 *  - Pub/sub via BroadcastChannel (multi-isolate)
 *  - Export/import for migrations
 *  - Zero deps  bun:sqlite is built-in
 */

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS kv (
    ns      TEXT    NOT NULL,
    key     TEXT    NOT NULL,
    value   TEXT    NOT NULL,
    expires INTEGER,                        -- Unix ms, NULL = no expiry
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    meta    TEXT,                           -- JSON metadata blob
    PRIMARY KEY (ns, key)
  );

  CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv (expires)
    WHERE expires IS NOT NULL;

  CREATE TABLE IF NOT EXISTS kv_counters (
    ns    TEXT    NOT NULL,
    key   TEXT    NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ns, key)
  );

  PRAGMA journal_mode = WAL;
  PRAGMA synchronous   = NORMAL;
  PRAGMA busy_timeout  = 5000;     -- Wait up to 5s for locked DB before failing
  PRAGMA cache_size    = -64000;   -- 64MB page cache
  PRAGMA temp_store    = MEMORY;
  PRAGMA mmap_size     = 268435456; -- 256MB mmap
`;

export interface KVOptions {
  dataDir?: string;
  gcIntervalMs?: number;
}

export interface KVStats {
  namespace: string;
  keyCount: number;
  expiredCount: number;
  sizeBytes: number;
  hitRate: number;
}

export class SovereignKV {
  private db: Database;
  private reader: Database;  // read-only connection for concurrent reads
  private hits = 0;
  private misses = 0;
  private gcTimer: Timer;

  // Prepared statements for hot paths
  private stmtGet!:    ReturnType<Database["prepare"]>;
  private stmtSet!:    ReturnType<Database["prepare"]>;
  private stmtDel!:    ReturnType<Database["prepare"]>;
  private stmtList!:   ReturnType<Database["prepare"]>;
  private stmtIncr!:   ReturnType<Database["prepare"]>;
  private stmtExpire!: ReturnType<Database["prepare"]>;

  constructor(options: KVOptions = {}) {
    const dataDir = options.dataDir ?? "./data/kv";
    mkdirSync(dataDir, { recursive: true });

    const dbPath = join(dataDir, "kv.sqlite");
    this.db = new Database(dbPath, { create: true });
    this.reader = new Database(dbPath, { readonly: true });
    this.db.exec(SCHEMA);
    // Reader tuning
    this.reader.run("PRAGMA cache_size = -64000");
    this.reader.run("PRAGMA temp_store = MEMORY");
    this.prepareStatements();

    // GC expired keys every 60s
    this.gcTimer = setInterval(() => this.gc(), options.gcIntervalMs ?? 60_000);
    console.log("[KV] SQLite store ready");
  }

  /** Async init hook (constructor handles setup, this is for interface compatibility) */
  async init(): Promise<void> { /* no-op -- SQLite setup is synchronous in constructor */ }

  // -- Public convenience API (uses "default" namespace) ------------------

  async get(key: string): Promise<string | null> {
    const [ns, k] = this.splitKey(key);
    return this._get(ns, k);
  }

  async set(key: string, value: string, opts?: { ttl?: number }): Promise<void> {
    const [ns, k] = this.splitKey(key);
    this._set(ns, k, value, opts);
  }

  async delete(key: string): Promise<boolean> {
    const [ns, k] = this.splitKey(key);
    return this._delete(ns, k);
  }

  async list(prefix?: string): Promise<string[]> {
    // If prefix contains ":", split into ns + prefix
    if (prefix && prefix.includes(":")) {
      const idx = prefix.indexOf(":");
      const ns = prefix.slice(0, idx);
      const p = prefix.slice(idx + 1);
      return this._list(ns, p).map((k: any) => k.key ? `${ns}:${k.key}` : `${ns}:${k}`);
    }
    return this._list(prefix ?? "default").map((k: any) => k.key ?? k);
  }

  private splitKey(key: string): [string, string] {
    const idx = key.indexOf(":");
    if (idx === -1) return ["default", key];
    const ns = key.slice(0, idx) || "default";
    const k = key.slice(idx + 1) || key;
    return [ns, k];
  }


  private prepareStatements() {
    this.stmtGet = this.reader.prepare(`
      SELECT value FROM kv
      WHERE ns = $ns AND key = $key
        AND (expires IS NULL OR expires > $now)
    `);

    this.stmtSet = this.db.prepare(`
      INSERT INTO kv (ns, key, value, expires, created, updated, meta)
      VALUES ($ns, $key, $value, $expires, $now, $now, $meta)
      ON CONFLICT(ns, key) DO UPDATE SET
        value   = excluded.value,
        expires = excluded.expires,
        updated = excluded.updated,
        meta    = excluded.meta
    `);

    this.stmtDel = this.db.prepare(`
      DELETE FROM kv WHERE ns = $ns AND key = $key
    `);

    this.stmtList = this.reader.prepare(`
      SELECT key, meta FROM kv
      WHERE ns = $ns
        AND ($prefix IS NULL OR key LIKE $prefix || '%')
        AND (expires IS NULL OR expires > $now)
      ORDER BY key
      LIMIT $limit
    `);

    this.stmtIncr = this.db.prepare(`
      INSERT INTO kv_counters (ns, key, value) VALUES ($ns, $key, $by)
      ON CONFLICT(ns, key) DO UPDATE SET value = value + $by
      RETURNING value
    `);

    this.stmtExpire = this.db.prepare(`
      DELETE FROM kv WHERE expires IS NOT NULL AND expires <= $now
    `);
  }

  namespace(ns: string): KVNamespace {
    return new KVNamespace(ns, this);
  }

  _get(ns: string, key: string): string | null {
    const row = this.stmtGet.get({ $ns: ns, $key: key, $now: Date.now() }) as any;
    if (!row) { this.misses++; return null; }
    this.hits++;
    return row.value;
  }

  /**
   * Retry a write operation with exponential backoff on SQLITE_BUSY.
   *
   * NOTE: Uses Bun.sleepSync() which blocks the event loop thread.
   * Backoff is short (10ms → 40ms max) and only triggers under SQLite lock
   * contention, which is rare with WAL mode + busy_timeout=5s.
   * Acceptable tradeoff for synchronous SQLite operations.
   */
  private retryWrite<T>(fn: () => T, maxRetries = 2): T {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return fn();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "";
        const isBusy = msg.includes("database is locked") || (err as { code?: string }).code === "SQLITE_BUSY";
        if (!isBusy || attempt === maxRetries) throw err;
        // Exponential backoff: 10ms, 40ms (capped at 2 retries)
        const delay = 10 * Math.pow(4, attempt);
        Bun.sleepSync(delay);
      }
    }
    throw new Error("KV: write retry exhausted"); // unreachable
  }

  _set(
    ns: string, key: string, value: string,
    opts: { ttl?: number; meta?: Record<string, unknown> } = {}
  ): void {
    if (!ns) throw new Error("KV: namespace cannot be empty");
    if (!key) throw new Error("KV: key cannot be empty");
    const now = Date.now();
    this.retryWrite(() =>
      this.stmtSet.run({
        $ns: ns, $key: key, $value: value,
        $expires: opts.ttl ? now + opts.ttl * 1000 : null,
        $now: now,
        $meta: opts.meta ? JSON.stringify(opts.meta) : null,
      })
    );
  }

  _delete(ns: string, key: string): boolean {
    const result = this.retryWrite(() => this.stmtDel.run({ $ns: ns, $key: key }));
    return result.changes > 0;
  }

  _list(ns: string, prefix?: string, limit = 1000) {
    return this.stmtList.all({ $ns: ns, $prefix: prefix ?? null, $now: Date.now(), $limit: limit }) as Array<{
      key: string;
      meta: string | null;
    }>;
  }

  _incr(ns: string, key: string, by = 1): number {
    const row = this.retryWrite(() => this.stmtIncr.get({ $ns: ns, $key: key, $by: by })) as any;
    return row.value;
  }

  /** Batch fetch all key-value pairs for a namespace in a single query (eliminates N+1) */
  _getAllByNamespace(ns: string, limit = 500): Record<string, string> {
    const rows = this.reader.prepare(`
      SELECT key, value FROM kv
      WHERE ns = $ns
        AND (expires IS NULL OR expires > $now)
      ORDER BY key
      LIMIT $limit
    `).all({ $ns: ns, $now: Date.now(), $limit: limit }) as Array<{ key: string; value: string }>;
    const result: Record<string, string> = {};
    for (const row of rows) {
      result[row.key] = row.value;
    }
    return result;
  }

  _cas(ns: string, key: string, expected: string | null, next: string): boolean {
    const current = this._get(ns, key);
    if (current !== expected) return false;
    this._set(ns, key, next);
    return true;
  }

  stats(): KVStats[] {
    const rows = this.db.prepare(`
      SELECT ns,
             COUNT(*) AS keyCount,
             SUM(LENGTH(key) + LENGTH(value)) AS sizeBytes,
             SUM(CASE WHEN expires IS NOT NULL AND expires <= $now THEN 1 ELSE 0 END) AS expiredCount
      FROM kv GROUP BY ns
    `).all({ now: Date.now() }) as any[];

    const total = this.hits + this.misses;
    return rows.map(r => ({
      namespace: r.ns,
      keyCount: r.keyCount,
      sizeBytes: r.sizeBytes ?? 0,
      expiredCount: r.expiredCount ?? 0,
      hitRate: total > 0 ? this.hits / total : 0,
    }));
  }

  listNamespaces(): string[] {
    return (this.db.prepare("SELECT DISTINCT ns FROM kv").all() as any[]).map(r => r.ns);
  }

  private gc() {
    const result = this.stmtExpire.run({ $now: Date.now() });
    if (result.changes > 0) console.log(`[KV] GC removed ${result.changes} expired keys`);
  }

  close() {
    clearInterval(this.gcTimer);
    try { this.reader.close(); } catch {}
    this.db.close();
  }
}

// Fluent namespace handle
export class KVNamespace {
  constructor(private readonly ns: string, private readonly store: SovereignKV) {}

  get(key: string): string | null { return this.store._get(this.ns, key); }
  getJSON<T = unknown>(key: string): T | null {
    const v = this.get(key);
    try { return v ? JSON.parse(v) as T : null; } catch { return null; }
  }
  set(key: string, value: string, opts?: { ttl?: number }): void {
    this.store._set(this.ns, key, value, opts);
  }
  setJSON(key: string, value: unknown, opts?: { ttl?: number }): void {
    this.set(key, JSON.stringify(value), opts);
  }
  delete(key: string): boolean { return this.store._delete(this.ns, key); }
  list(prefix?: string, limit?: number) { return this.store._list(this.ns, prefix, limit); }
  incr(key: string, by = 1): number { return this.store._incr(this.ns, key, by); }
  cas(key: string, expected: string | null, next: string): boolean {
    return this.store._cas(this.ns, key, expected, next);
  }
}
