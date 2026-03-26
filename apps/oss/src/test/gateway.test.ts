/**
 * Sovereignly v4  Gateway & Observability Tests
 *
 * Tests gateway infrastructure:
 *   - Health/readiness/liveness endpoints
 *   - Security headers
 *   - Metrics endpoint
 *   - Error capture middleware
 *   - Request ID propagation
 *
 * Run: bun test apps/oss/src/test/gateway.test.ts
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { SovereignKV } from "../kv/index.ts";
import { SovereignChain } from "../security/chain.ts";
import { SovereignRuntime } from "../runtime/index.ts";
import { SovereignStorage } from "../storage/index.ts";
import { createGateway } from "../gateway/index.ts";
import type { Hono } from "hono";

let testDir: string;
let kv: SovereignKV;
let chain: SovereignChain;
let runtime: SovereignRuntime;
let storage: SovereignStorage;
let app: Hono;

beforeAll(async () => {
  testDir = join(tmpdir(), `sovereign-gw-test-${Date.now()}`);
  await mkdir(join(testDir, "kv"), { recursive: true });
  await mkdir(join(testDir, "chain"), { recursive: true });
  await mkdir(join(testDir, "storage"), { recursive: true });
  await mkdir(join(testDir, "runtime"), { recursive: true });

  kv = new SovereignKV({ dataDir: join(testDir, "kv") });
  await kv.init();

  chain = new SovereignChain({ dataDir: join(testDir, "chain"), nodeId: "gw-test" });
  await chain.init();
  // Emit + flush to create at least 1 block (health check requires blocks > 0)
  await chain.emit("NODE_JOIN", { test: true }, "LOW");
  await chain.flush();

  storage = new SovereignStorage({ dataDir: join(testDir, "storage") });

  runtime = new SovereignRuntime(kv, { poolSize: 1 });

  const gw = createGateway(runtime, kv, storage, {
    chain,
    corsOrigins: ["http://localhost:3000"],
    adminToken: "test-admin-token",
  });
  app = gw.app;
});

afterAll(async () => {
  runtime.shutdown();
  kv.close();
  chain.close();
  storage.close();
  await new Promise(r => setTimeout(r, 200));
  await rm(testDir, { recursive: true, force: true }).catch(() => {});
});

// ── Liveness Probe ───────────────────────────────────────────────────────────

describe("/_sovereign/live", () => {
  test("returns 200 with ok:true", async () => {
    const res = await app.request("/_sovereign/live");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.ts).toBeDefined();
  });

  test("includes no-cache header", async () => {
    const res = await app.request("/_sovereign/live");
    expect(res.headers.get("cache-control")).toContain("no-cache");
  });
});

// ── Readiness Probe ──────────────────────────────────────────────────────────

describe("/_sovereign/ready", () => {
  test("returns 200 when all subsystems healthy", async () => {
    const res = await app.request("/_sovereign/ready");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ready).toBe(true);
    expect(body.subsystems.chain).toBe("ok");
    expect(body.subsystems.kv).toBe("ok");
    expect(body.responseMs).toBeDefined();
  });
});

// ── Health Endpoint ──────────────────────────────────────────────────────────

describe("/_sovereign/health", () => {
  test("returns full health details", async () => {
    const res = await app.request("/_sovereign/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.status).toBe("healthy");
    expect(body.version).toBe("4.0.0");
    expect(body.runtime).toBe("bun");
    expect(body.bunVersion).toBeDefined();
    expect(body.uptime).toBeDefined();
    expect(body.responseMs).toBeDefined();
  });

  test("includes cache stats", async () => {
    const res = await app.request("/_sovereign/health");
    const body = await res.json();
    expect(body.cache).toBeDefined();
    expect(typeof body.cache.size).toBe("number");
    expect(typeof body.cache.hitRate).toBe("number");
  });

  test("includes PQC info", async () => {
    const res = await app.request("/_sovereign/health");
    const body = await res.json();
    expect(body.pqc.enabled).toBe(true);
    expect(body.pqc.dualMerkleRoots).toBe(true);
  });
});

// ── Metrics Endpoint ─────────────────────────────────────────────────────────

describe("/_sovereign/metrics", () => {
  test("returns JSON metrics by default", async () => {
    const res = await app.request("/_sovereign/metrics");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body.requests).toBe("number");
    expect(typeof body.errors).toBe("number");
    expect(body.cache).toBeDefined();
  });

  test("returns Prometheus format when requested", async () => {
    const res = await app.request("/_sovereign/metrics?format=prometheus");
    expect(res.status).toBe(200);
    const text = await res.text();
    // Prometheus format has # HELP and # TYPE lines
    expect(text).toContain("# HELP");
    expect(text).toContain("# TYPE");
  });
});

// ── Security Headers ─────────────────────────────────────────────────────────

describe("Security response headers", () => {
  test("includes X-Content-Type-Options", async () => {
    const res = await app.request("/_sovereign/health");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });

  test("includes X-Frame-Options", async () => {
    const res = await app.request("/_sovereign/health");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });

  test("includes Referrer-Policy", async () => {
    const res = await app.request("/_sovereign/health");
    expect(res.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
  });

  test("includes Permissions-Policy", async () => {
    const res = await app.request("/_sovereign/health");
    const pp = res.headers.get("permissions-policy");
    expect(pp).toContain("camera=()");
    expect(pp).toContain("microphone=()");
  });

  test("includes Cross-Origin-Opener-Policy", async () => {
    const res = await app.request("/_sovereign/health");
    expect(res.headers.get("cross-origin-opener-policy")).toBe("same-origin");
  });

  test("includes Cross-Origin-Resource-Policy", async () => {
    const res = await app.request("/_sovereign/health");
    expect(res.headers.get("cross-origin-resource-policy")).toBe("same-origin");
  });

  test("includes X-Request-ID", async () => {
    const res = await app.request("/_sovereign/health");
    const reqId = res.headers.get("x-request-id");
    expect(reqId).toBeTruthy();
    expect(reqId!.length).toBeGreaterThan(0);
  });

  test("propagates client-provided X-Request-ID", async () => {
    const customId = "custom-trace-12345";
    const res = await app.request("/_sovereign/health", {
      headers: { "x-request-id": customId },
    });
    expect(res.headers.get("x-request-id")).toBe(customId);
  });
});

// ── Request Size Limit ───────────────────────────────────────────────────────

describe("Request size limits", () => {
  test("rejects oversized requests", async () => {
    // Default limit is 50MB, create a fake large content-length header
    const res = await app.request("/_sovereign/health", {
      method: "POST",
      headers: { "content-length": String(100 * 1024 * 1024) }, // 100MB
    });
    expect(res.status).toBe(413);
  });
});

// ── Error Reporting Endpoint ─────────────────────────────────────────────────
// Note: /_sovereign/errors/report is registered in server.ts via registerErrorReportingRoutes,
// not in createGateway. These tests validate the route handler via direct import.

describe("Error reporting route handler", () => {
  test("registerErrorReportingRoutes exports correctly", async () => {
    const mod = await import("../observability/index.ts");
    expect(typeof mod.registerErrorReportingRoutes).toBe("function");
  });

  test("errorCaptureMiddleware exports correctly", async () => {
    const mod = await import("../observability/index.ts");
    expect(typeof mod.errorCaptureMiddleware).toBe("function");
  });
});
