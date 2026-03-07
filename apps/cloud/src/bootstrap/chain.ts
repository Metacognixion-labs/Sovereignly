/**
 * Bootstrap: Chain + Omnichain Anchor
 */

import { SovereignChain }  from "@sovereignly/oss/security/chain";
import { OmnichainAnchor } from "@sovereignly/oss/security/omnichain-anchor";
import type { Config } from "./config.ts";

export function createOmniAnchor(cfg: Config) {
  const omniAnchor = OmnichainAnchor.fromEnv(cfg.anchorTier);
  omniAnchor.verifySchemaConfig();
  return omniAnchor;
}

export async function createChain(cfg: Config, omniAnchor: ReturnType<typeof createOmniAnchor>) {
  const chain = new SovereignChain({
    dataDir:        `${cfg.dataDir}/platform`,
    nodeId:         cfg.nodeId,
    anchorInterval: cfg.globalAnchorInterval,
    omniAnchor,
    anchorOrgId:    "platform",
    peers:          cfg.clusterPeers,
  });
  await chain.init();
  return chain;
}
