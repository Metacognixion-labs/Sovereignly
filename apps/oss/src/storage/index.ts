/**
 * Sovereignly v3  Object Storage
 *
 * S3-compatible semantics on your own disk.
 * Uses Bun.file() for zero-copy reads and streaming writes.
 * Metadata persisted in SQLite (same bun:sqlite, second DB file).
 */

import { Database } from "bun:sqlite";
import { join, dirname } from "node:path";
import { mkdir, unlink, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import crypto from "node:crypto";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS objects (
    bucket    TEXT    NOT NULL,
    key       TEXT    NOT NULL,
    size      INTEGER NOT NULL,
    etag      TEXT    NOT NULL,
    mime      TEXT    NOT NULL DEFAULT 'application/octet-stream',
    created   INTEGER NOT NULL,
    modified  INTEGER NOT NULL,
    tags      TEXT,
    meta      TEXT,
    PRIMARY KEY (bucket, key)
  );

  CREATE TABLE IF NOT EXISTS buckets (
    name      TEXT PRIMARY KEY,
    public    INTEGER NOT NULL DEFAULT 0,
    versioned INTEGER NOT NULL DEFAULT 0,
    config    TEXT
  );

  PRAGMA journal_mode = WAL;
  PRAGMA synchronous  = NORMAL;
`;

export interface ObjectMeta {
  bucket: string;
  key: string;
  size: number;
  etag: string;
  mime: string;
  created: Date;
  modified: Date;
  tags: Record<string, string>;
  meta: Record<string, string>;
}

export class SovereignStorage {
  private db: Database;
  private basePath: string;
  private signingSecret: string;

  constructor(options: { dataDir?: string; signingSecret?: string } = {}) {
    this.basePath = options.dataDir ?? "./data/storage";
    this.signingSecret = options.signingSecret ?? crypto.randomBytes(32).toString("hex");
    Bun.spawnSync(["mkdir", "-p", this.basePath]);

    this.db = new Database(join(this.basePath, "meta.sqlite"), { create: true });
    this.db.exec(SCHEMA);
    console.log("[Storage] Object store ready");
  }

  //  Buckets 

  createBucket(name: string, options: { public?: boolean; versioned?: boolean } = {}) {
    this.db.prepare(`
      INSERT OR IGNORE INTO buckets (name, public, versioned)
      VALUES ($name, $public, $versioned)
    `).run({ name, public: options.public ? 1 : 0, versioned: options.versioned ? 1 : 0 });

    Bun.spawnSync(["mkdir", "-p", this.bucketPath(name)]);
    return { name, ...options };
  }

  deleteBucket(name: string, force = false) {
    if (!force) {
      const count = (this.db.prepare("SELECT COUNT(*) as c FROM objects WHERE bucket = $name").get({ name }) as any)?.c ?? 0;
      if (count > 0) throw new Error(`Bucket '${name}' is not empty`);
    }
    this.db.prepare("DELETE FROM objects WHERE bucket = $name").run({ name });
    this.db.prepare("DELETE FROM buckets WHERE name = $name").run({ name });
    Bun.spawnSync(["rm", "-rf", this.bucketPath(name)]);
    return true;
  }

  listBuckets() {
    return this.db.prepare("SELECT * FROM buckets").all() as any[];
  }

  //  Objects 

  async put(
    bucket: string, key: string,
    data: Uint8Array | string | Blob,
    options: { mime?: string; tags?: Record<string, string>; meta?: Record<string, string> } = {}
  ): Promise<ObjectMeta> {
    this.ensureBucket(bucket);

    const buf = data instanceof Uint8Array ? data
      : data instanceof Blob ? new Uint8Array(await data.arrayBuffer())
      : Buffer.from(data as string);

    const etag = crypto.createHash("md5").update(buf).digest("hex");
    const objectPath = this.objectPath(bucket, key);
    await mkdir(dirname(objectPath), { recursive: true });
    await Bun.write(objectPath, buf);

    const now = Date.now();
    this.db.prepare(`
      INSERT INTO objects (bucket, key, size, etag, mime, created, modified, tags, meta)
      VALUES ($bucket, $key, $size, $etag, $mime, $now, $now, $tags, $meta)
      ON CONFLICT(bucket, key) DO UPDATE SET
        size = excluded.size, etag = excluded.etag, mime = excluded.mime,
        modified = excluded.modified, tags = excluded.tags, meta = excluded.meta
    `).run({
      bucket, key, size: buf.length, etag,
      mime: options.mime ?? "application/octet-stream",
      now,
      tags: options.tags ? JSON.stringify(options.tags) : null,
      meta: options.meta ? JSON.stringify(options.meta) : null,
    });

    return this.head(bucket, key)!;
  }

  async get(bucket: string, key: string): Promise<{ data: Uint8Array; meta: ObjectMeta } | null> {
    const meta = this.head(bucket, key);
    if (!meta) return null;
    const path = this.objectPath(bucket, key);
    if (!existsSync(path)) return null;
    const data = new Uint8Array(await Bun.file(path).arrayBuffer());
    return { data, meta };
  }

  // Zero-copy streaming response
  stream(bucket: string, key: string): Response | null {
    const meta = this.head(bucket, key);
    if (!meta) return null;
    const path = this.objectPath(bucket, key);
    if (!existsSync(path)) return null;
    return new Response(Bun.file(path), {
      headers: {
        "content-type": meta.mime,
        "content-length": String(meta.size),
        "etag": `"${meta.etag}"`,
        "last-modified": meta.modified.toUTCString(),
      },
    });
  }

  async delete(bucket: string, key: string): Promise<boolean> {
    const meta = this.head(bucket, key);
    if (!meta) return false;
    try { await unlink(this.objectPath(bucket, key)); } catch {}
    this.db.prepare("DELETE FROM objects WHERE bucket = $bucket AND key = $key").run({ bucket, key });
    return true;
  }

  list(bucket: string, options: { prefix?: string; limit?: number } = {}): ObjectMeta[] {
    const rows = this.db.prepare(`
      SELECT * FROM objects
      WHERE bucket = $bucket
        AND ($prefix IS NULL OR key LIKE $prefix || '%')
      ORDER BY key
      LIMIT $limit
    `).all({
      bucket,
      prefix: options.prefix ?? null,
      limit: options.limit ?? 1000,
    }) as any[];
    return rows.map(this.rowToMeta);
  }

  head(bucket: string, key: string): ObjectMeta | null {
    const row = this.db.prepare("SELECT * FROM objects WHERE bucket = $bucket AND key = $key").get({ bucket, key }) as any;
    return row ? this.rowToMeta(row) : null;
  }

  async copy(srcBucket: string, srcKey: string, dstBucket: string, dstKey: string) {
    const src = this.head(srcBucket, srcKey);
    if (!src) return null;
    this.ensureBucket(dstBucket);
    const srcPath = this.objectPath(srcBucket, srcKey);
    const dstPath = this.objectPath(dstBucket, dstKey);
    await mkdir(dirname(dstPath), { recursive: true });
    await copyFile(srcPath, dstPath);
    this.db.prepare(`
      INSERT INTO objects (bucket, key, size, etag, mime, created, modified, tags, meta)
      VALUES ($bucket, $key, $size, $etag, $mime, $now, $now, $tags, $meta)
      ON CONFLICT(bucket, key) DO UPDATE SET size=excluded.size, etag=excluded.etag
    `).run({ bucket: dstBucket, key: dstKey, size: src.size, etag: src.etag, mime: src.mime, now: Date.now(), tags: null, meta: null });
    return this.head(dstBucket, dstKey);
  }

  //  Pre-signed URLs 

  presign(bucket: string, key: string, op: "GET" | "PUT", expiresInSec: number, baseUrl: string): string {
    const exp = Math.floor(Date.now() / 1000) + expiresInSec;
    const sig = crypto.createHmac("sha256", this.signingSecret)
      .update(`${op}:${bucket}:${key}:${exp}`)
      .digest("hex");
    const q = new URLSearchParams({ bucket, key, op, exp: String(exp), sig });
    return `${baseUrl}/_sovereign/storage/presigned?${q}`;
  }

  validatePresign(params: Record<string, string>): boolean {
    const { bucket, key, op, exp, sig } = params;
    if (!bucket || !key || !op || !exp || !sig) return false;
    if (Date.now() / 1000 > parseInt(exp)) return false;
    const expected = crypto.createHmac("sha256", this.signingSecret)
      .update(`${op}:${bucket}:${key}:${exp}`)
      .digest("hex");
    return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
  }

  //  Helpers 

  private bucketPath(bucket: string) { return join(this.basePath, "buckets", bucket); }
  private objectPath(bucket: string, key: string) { return join(this.bucketPath(bucket), key); }

  private ensureBucket(name: string) {
    const exists = this.db.prepare("SELECT 1 FROM buckets WHERE name = $name").get({ name });
    if (!exists) this.createBucket(name);
  }

  private rowToMeta(row: any): ObjectMeta {
    return {
      bucket: row.bucket,
      key: row.key,
      size: row.size,
      etag: row.etag,
      mime: row.mime,
      created: new Date(row.created),
      modified: new Date(row.modified),
      tags: (() => { try { return row.tags ? JSON.parse(row.tags) : {}; } catch { return {}; } })(),
      meta: (() => { try { return row.meta ? JSON.parse(row.meta) : {}; } catch { return {}; } })(),
    };
  }

  stats() {
    return this.db.prepare(`
      SELECT bucket, COUNT(*) as count, SUM(size) as totalBytes
      FROM objects GROUP BY bucket
    `).all() as Array<{ bucket: string; count: number; totalBytes: number }>;
  }

  close() { this.db.close(); }
}
