/**
 * Bootstrap: Tenant Manager + Billing + Webhooks + Rate Limiter
 */

import { TenantManager }    from "../tenants/manager.ts";
import { BillingService }   from "../billing/stripe.ts";
import { WebhookManager }   from "../webhooks/index.ts";
import { TenantRateLimiter } from "../gateway/tenant-limiter.ts";
import type { SovereignChain } from "@sovereignly/oss/security/chain";
import type { OmnichainAnchor } from "@sovereignly/oss/security/omnichain-anchor";
import type { Config } from "./config.ts";

export function createTenantLayer(cfg: Config, chain: SovereignChain, omniAnchor: OmnichainAnchor) {
  const tenantManager = new TenantManager({
    dataDir:   cfg.dataDir,
    nodeId:    cfg.nodeId,
    serverKey: cfg.serverKey,
    omniAnchor,
  });

  let billing: BillingService | null = null;
  if (cfg.stripeKey && cfg.stripeWebhook && cfg.stripeStarter && cfg.stripeGrowth) {
    billing = new BillingService(
      {
        stripeSecretKey:      cfg.stripeKey,
        stripeWebhookSecret:  cfg.stripeWebhook,
        prices: { starter: cfg.stripeStarter, growth: cfg.stripeGrowth, enterprise: cfg.stripeEnt ?? "" },
        successUrl: `${cfg.appUrl}/dashboard`,
        cancelUrl:  `${cfg.appUrl}/pricing`,
      },
      tenantManager, chain,
    );
  }

  const tenantLimiter = new TenantRateLimiter();
  setInterval(() => tenantLimiter.gc(), 300_000);

  const webhookManager = new WebhookManager(chain);

  return { tenantManager, billing, tenantLimiter, webhookManager };
}

/** Wire chain-block hooks for webhook dispatch */
export function wireChainHooks(
  chain: SovereignChain,
  tenantManager: TenantManager,
  webhookManager: WebhookManager,
  cfg: Config,
) {
  // Dispatch anchor events to tenant webhooks
  chain.onBlock(async (block) => {
    if (block.index > 0 && block.index % cfg.anchorInterval === 0) {
      for (const t of tenantManager.listTenants({ status: "active" })) {
        const ctx = await tenantManager.get(t.id).catch(() => null);
        if (ctx) {
          webhookManager.dispatch(ctx.kv, t.id, "anchor_completed", {
            merkleRoot: block.merkleRoot, blockIndex: block.index,
            eventCount: block.eventCount, nodeId: block.nodeId,
          }).catch(() => {});
        }
      }
    }
  });
}
