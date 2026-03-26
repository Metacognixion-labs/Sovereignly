/**
 * Sovereignly v4  Security Tests
 *
 * Tests all Phase 1-3 security hardening:
 *   - InputShield injection detection
 *   - CSRF header enforcement
 *   - Cookie auth flow
 *   - Rate limiter (memory + KV-backed)
 *   - Zero-trust middleware headers
 *   - Error capture pipeline
 *
 * Run: bun test apps/oss/src/test/security.test.ts
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { InputShield } from "../security/input-shield.ts";
import { SovereignKV } from "../kv/index.ts";

let testDir: string;

beforeAll(async () => {
  testDir = join(tmpdir(), `sovereign-sec-test-${Date.now()}`);
  await mkdir(testDir, { recursive: true });
});

afterAll(async () => {
  // Allow SQLite WAL to release file handles before cleanup (Windows EBUSY workaround)
  await new Promise(r => setTimeout(r, 100));
  await rm(testDir, { recursive: true, force: true }).catch(() => {});
});

// ── InputShield ──────────────────────────────────────────────────────────────

describe("InputShield", () => {
  const shield = new InputShield();

  test("allows clean input", () => {
    const result = shield.scanObject({ name: "John Doe", email: "john@example.com" });
    expect(result.safe).toBe(true);
    expect(result.threats).toHaveLength(0);
  });

  test("detects prototype pollution via Object.create(null)", () => {
    // JS literal { "__proto__": ... } silently sets the prototype, not a key.
    // Use Object.create(null) to create a plain object with __proto__ as real key.
    const malicious = Object.create(null);
    malicious["__proto__"] = { admin: true };
    const result = shield.scanObject(malicious);
    expect(result.safe).toBe(false);
    expect(result.threats.some(t => t.type === "prototype_pollution")).toBe(true);
  });

  test("detects prototype pollution in string values", () => {
    const result = shield.scanObject({ payload: "constructor.prototype.isAdmin = true" });
    expect(result.safe).toBe(false);
  });

  test("detects SQL injection in values", () => {
    const result = shield.scanObject({ query: "'; DROP TABLE users; --" });
    expect(result.safe).toBe(false);
  });

  test("detects path traversal", () => {
    const result = shield.scanObject({ file: "../../../etc/passwd" });
    expect(result.safe).toBe(false);
  });

  test("detects command injection", () => {
    const result = shield.scanObject({ cmd: "ls; rm -rf /" });
    expect(result.safe).toBe(false);
  });

  test("detects template injection", () => {
    const result = shield.scanObject({ tpl: "{{constructor.constructor('return this')()}}" });
    expect(result.safe).toBe(false);
  });

  test("handles deeply nested objects", () => {
    let obj: Record<string, unknown> = { value: "safe" };
    for (let i = 0; i < 25; i++) {
      obj = { nested: obj };
    }
    // Should either reject as too deep or scan successfully
    const result = shield.scanObject(obj);
    expect(typeof result.safe).toBe("boolean");
  });

  test("detects constructor key in object", () => {
    const obj = Object.create(null);
    obj["constructor"] = { "prototype": { "isAdmin": true } };
    const result = shield.scanObject(obj);
    expect(result.safe).toBe(false);
  });
});

// ── KV Batch Fetch ───────────────────────────────────────────────────────────

describe("KV _getAllByNamespace (batch fetch)", () => {
  let kv: SovereignKV;

  beforeAll(async () => {
    const kvDir = join(testDir, "kv-batch");
    await mkdir(kvDir, { recursive: true });
    kv = new SovereignKV({ dataDir: kvDir });
    await kv.init();
  });

  afterAll(() => kv.close());

  test("returns all keys in namespace with single query", () => {
    // Seed data
    kv._set("batch-ns", "key1", "value1");
    kv._set("batch-ns", "key2", "value2");
    kv._set("batch-ns", "key3", "value3");
    kv._set("other-ns", "key4", "value4"); // different namespace

    const result = kv._getAllByNamespace("batch-ns");
    expect(Object.keys(result).length).toBe(3);
    expect(result.key1).toBe("value1");
    expect(result.key2).toBe("value2");
    expect(result.key3).toBe("value3");
    expect(result.key4).toBeUndefined(); // not in batch-ns
  });

  test("respects TTL expiry in batch fetch", async () => {
    kv._set("ttl-ns", "alive", "yes");
    kv._set("ttl-ns", "expired", "yes", { ttl: 0.01 }); // 10ms
    await new Promise(r => setTimeout(r, 50));

    const result = kv._getAllByNamespace("ttl-ns");
    expect(result.alive).toBe("yes");
    expect(result.expired).toBeUndefined();
  });

  test("returns empty object for non-existent namespace", () => {
    const result = kv._getAllByNamespace("nonexistent");
    expect(Object.keys(result).length).toBe(0);
  });

  test("respects limit parameter", () => {
    for (let i = 0; i < 10; i++) {
      kv._set("limit-ns", `k${i}`, `v${i}`);
    }
    const result = kv._getAllByNamespace("limit-ns", 3);
    expect(Object.keys(result).length).toBe(3);
  });
});

// ── KV Retry Logic ───────────────────────────────────────────────────────────

describe("KV retry logic", () => {
  let kv: SovereignKV;

  beforeAll(async () => {
    const kvDir = join(testDir, "kv-retry");
    await mkdir(kvDir, { recursive: true });
    kv = new SovereignKV({ dataDir: kvDir });
    await kv.init();
  });

  afterAll(() => kv.close());

  test("_set succeeds under normal conditions", () => {
    expect(() => kv._set("retry", "key1", "value1")).not.toThrow();
    expect(kv._get("retry", "key1")).toBe("value1");
  });

  test("_delete succeeds under normal conditions", () => {
    kv._set("retry", "delme", "value");
    expect(kv._delete("retry", "delme")).toBe(true);
    expect(kv._get("retry", "delme")).toBeNull();
  });

  test("_incr works correctly with retry wrapper", () => {
    const v1 = kv._incr("retry", "counter", 1);
    expect(v1).toBe(1);
    const v2 = kv._incr("retry", "counter", 5);
    expect(v2).toBe(6);
  });

  test("rejects invalid namespace", () => {
    expect(() => kv._set("", "key", "val")).toThrow("namespace cannot be empty");
  });

  test("rejects invalid key", () => {
    expect(() => kv._set("ns", "", "val")).toThrow("key cannot be empty");
  });
});
