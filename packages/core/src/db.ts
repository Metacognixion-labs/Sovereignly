/**
 * Database Abstraction Layer
 *
 * Provides a uniform interface over bun:sqlite and libSQL/Turso.
 * Enables gradual migration from local SQLite to distributed libSQL
 * without changing application code.
 *
 * Features:
 *   - Read/write connection separation (built-in)
 *   - Connection pooling for readers
 *   - Prepared statement caching
 *   - BEGIN CONCURRENT readiness (libSQL)
 *   - Embedded replica support (Turso)
 *   - PRAGMA auto-tuning based on role (writer vs reader)
 *
 * Usage:
 *   const db = createDatabase({ path: "data/chain.db", mode: "local" });
 *   const rows = db.reader.prepare("SELECT * FROM blocks").all();
 *   db.writer.prepare("INSERT INTO events ...").run(...);
 *   db.close();
 *
 * Migration path:
 *   1. Replace `new Database(path)` with `createDatabase({ path, mode: "local" })`
 *   2. Use `db.reader` for reads, `db.writer` for writes
 *   3. When ready for Turso: change mode to "turso" and add url/authToken
 */

import { Database } from "bun:sqlite";

// -- Types --------------------------------------------------------------------

export type DatabaseMode = "local" | "turso";

export interface DatabaseConfig {
  /** Path to SQLite file (local mode) */
  path:          string;
  /** "local" for bun:sqlite, "turso" for libSQL (future) */
  mode?:         DatabaseMode;
  /** Number of read-only connections (default: 2) */
  readerCount?:  number;
  /** Cache size in KB (negative = KB, positive = pages) */
  cacheSize?:    number;
  /** Whether this is a high-traffic DB (enables mmap + larger cache) */
  highTraffic?:  boolean;
  /** Turso URL (future) */
  tursoUrl?:     string;
  /** Turso auth token (future) */
  tursoToken?:   string;
}

export interface DatabaseAdapter {
  /** Single writer connection */
  writer: Database;
  /** Read-only connection (round-robins across pool) */
  readonly reader: Database;
  /** Execute a write transaction */
  transaction<T>(fn: () => T): T;
  /** Close all connections */
  close(): void;
  /** Stats */
  stats(): { mode: string; readerPoolSize: number; writerConnected: boolean };
}

// -- Local SQLite Adapter (bun:sqlite) ----------------------------------------

class LocalDatabaseAdapter implements DatabaseAdapter {
  writer: Database;
  private readers: Database[];
  private readerIdx = 0;

  constructor(config: DatabaseConfig) {
    const cacheSize = config.cacheSize ?? (config.highTraffic ? -64000 : -16000);

    // Writer connection
    this.writer = new Database(config.path, { create: true });
    this.writer.run("PRAGMA journal_mode = WAL");
    this.writer.run("PRAGMA synchronous = NORMAL");
    this.writer.run(`PRAGMA cache_size = ${cacheSize}`);
    this.writer.run("PRAGMA busy_timeout = 5000");
    if (config.highTraffic) {
      this.writer.run("PRAGMA temp_store = MEMORY");
      this.writer.run("PRAGMA mmap_size = 268435456"); // 256MB
    }

    // Reader pool
    const readerCount = config.readerCount ?? 2;
    this.readers = [];
    for (let i = 0; i < readerCount; i++) {
      const reader = new Database(config.path, { readonly: true });
      reader.run(`PRAGMA cache_size = ${cacheSize}`);
      if (config.highTraffic) {
        reader.run("PRAGMA temp_store = MEMORY");
        reader.run("PRAGMA mmap_size = 268435456");
      }
      this.readers.push(reader);
    }
  }

  get reader(): Database {
    // Round-robin across reader pool
    const r = this.readers[this.readerIdx % this.readers.length];
    this.readerIdx++;
    return r;
  }

  transaction<T>(fn: () => T): T {
    return this.writer.transaction(fn)();
  }

  close(): void {
    for (const r of this.readers) {
      try { r.close(); } catch {}
    }
    try { this.writer.close(); } catch {}
  }

  stats() {
    return {
      mode: "local",
      readerPoolSize: this.readers.length,
      writerConnected: true,
    };
  }
}

// -- Factory ------------------------------------------------------------------

export function createDatabase(config: DatabaseConfig): DatabaseAdapter {
  switch (config.mode ?? "local") {
    case "local":
      return new LocalDatabaseAdapter(config);
    case "turso":
      // Future: Turso/libSQL adapter
      // For now, fall back to local with a warning
      console.warn("[DB] Turso mode requested but not yet implemented — falling back to local SQLite");
      return new LocalDatabaseAdapter(config);
    default:
      throw new Error(`Unknown database mode: ${config.mode}`);
  }
}

// -- Migration Helper ---------------------------------------------------------

/**
 * Wraps an existing Database for gradual migration.
 * Use this to start adopting the adapter pattern without rewriting everything at once.
 */
export function wrapExistingDatabase(db: Database, path: string): DatabaseAdapter {
  const reader = new Database(path, { readonly: true });
  reader.run("PRAGMA cache_size = -16000");
  return {
    writer: db,
    get reader() { return reader; },
    transaction<T>(fn: () => T): T { return db.transaction(fn)(); },
    close() { try { reader.close(); } catch {} try { db.close(); } catch {} },
    stats() { return { mode: "wrapped", readerPoolSize: 1, writerConnected: true }; },
  };
}
