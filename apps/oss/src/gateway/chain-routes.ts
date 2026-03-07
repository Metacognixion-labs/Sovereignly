import { timingSafeEqual } from "../security/crypto.ts";
/**
 * Sovereignly OSS  Chain & Compliance Routes
 * MIT License
 *
 * Compliance endpoints return 402 (upgrade required) in OSS edition.
 * Full compliance reports available in Cloud edition.
 */

import type { Hono } from "hono";
import type { SovereignChain } from "../security/chain.ts";
import { issueJWT } from "../security/zero-trust.ts";

export function registerChainRoutes(
  app:        Hono,
  chain:      SovereignChain,
  compliance: any | null,
  cfg:        { adminToken?: string; jwtSecret: string }
) {

  //  Auth: issue JWT 

  app.post("/_sovereign/auth/token", async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const { role = "reader", subject = "api", ttl = 3600 } = body as any;
    const callerToken = c.req.header("x-sovereign-token") ?? "";
    if (!cfg.adminToken || !timingSafeEqual(callerToken, cfg.adminToken)) {
      return c.json({ error: "unauthorized" }, 401);
    }
    const token = await issueJWT({ sub: subject, role }, cfg.jwtSecret, ttl);
    return c.json({ token, role, ttlSecs: ttl, type: "Bearer" });
  });

  //  Chain stats 

  app.get("/_sovereign/chain/stats", (c) => {
    return c.json(chain.getStats());
  });

  app.get("/_sovereign/chain/tip", (c) => {
    const tip = chain.getTip();
    return tip ? c.json(tip) : c.json({ error: "no blocks" }, 404);
  });

  app.get("/_sovereign/chain/block/:index", (c) => {
    const idx = parseInt(c.req.param("index"));
    const block = chain.getBlock(idx);
    return block ? c.json(block) : c.json({ error: "not found" }, 404);
  });

  app.get("/_sovereign/chain/verify", async (c) => {
    const result = await chain.verifyChainIntegrity();
    return c.json(result, result.valid ? 200 : 500);
  });

  app.get("/_sovereign/chain/events", (c) => {
    const { type, severity, since, limit } = c.req.query();
    const events = chain.getEvents({
      type:     type as any,
      severity: severity as any,
      since:    since ? parseInt(since) : undefined,
      limit:    Math.min(parseInt(limit ?? "50"), 500),
    });
    return c.json({ count: events.length, events });
  });

  app.get("/_sovereign/chain/blocks", (c) => {
    const { limit, offset, since } = c.req.query();
    const blocks = chain.getBlocks({
      limit:  parseInt(limit ?? "20"),
      offset: parseInt(offset ?? "0"),
      since:  since ? parseInt(since) : undefined,
    });
    return c.json({ count: blocks.length, blocks });
  });

  //  Peer replication 

  app.post("/_sovereign/chain/block", async (c) => {
    const block = await c.req.json();
    const result = await chain.ingestPeerBlock(block);
    return c.json(result, result.ok ? 200 : 400);
  });

  //  Compliance (premium  return upgrade prompt in OSS) 

  if (compliance) {
    app.get("/_sovereign/compliance/soc2", async (c) => {
      const report = await compliance.generateSOC2Report();
      return c.json(report);
    });

    app.get("/_sovereign/compliance/iso27001", async (c) => {
      const report = compliance.generateReport("ISO27001");
      return c.json(report);
    });

    app.get("/_sovereign/compliance/report", async (c) => {
      const { standard } = c.req.query();
      const report = compliance.generateReport((standard ?? "SOC2") as any);
      return c.json(report);
    });

    app.get("/_sovereign/compliance/export", async (c) => {
      const { from, to, types, proofs } = c.req.query();
      const now = Date.now();
      const data = await compliance.exportAuditTrail({
        from: from ? parseInt(from) : now - 30 * 24 * 60 * 60 * 1000,
        to: to ? parseInt(to) : now,
        types: types ? types.split(",") : undefined,
        includeProofs: proofs === "true",
      });
      return c.json(data);
    });
  } else {
    // OSS edition: compliance endpoints return upgrade prompt
    const upgradeMsg = {
      error: "Compliance reports require Sovereignly Cloud",
      upgrade: "https://sovereignly.io",
      docs: "https://github.com/Metacognixion-labs/Sovereignly#editions",
    };
    app.get("/_sovereign/compliance/soc2", (c) => c.json(upgradeMsg, 402));
    app.get("/_sovereign/compliance/iso27001", (c) => c.json(upgradeMsg, 402));
    app.get("/_sovereign/compliance/report", (c) => c.json(upgradeMsg, 402));
    app.get("/_sovereign/compliance/export", (c) => c.json(upgradeMsg, 402));
  }

  //  Anchor info 

  app.get("/_sovereign/chain/anchor/latest", (c) => {
    const events = chain.getEvents({ type: "MERIDIAN_ANCHOR", limit: 1 });
    return c.json({ latest: events[0] ?? null });
  });

  app.get("/_sovereign/chain/anchor/schema", (c) => {
    return c.json({
      uid: "0xa3518350e4a3857be49837596827c326dad06d71a9ed18cd883774118c1e90dc",
      schema: "bytes32 merkleRoot,uint256 blockIndex,uint32 eventCount,string orgId,string protocol",
    });
  });
}
