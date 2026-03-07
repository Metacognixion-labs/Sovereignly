/**
 * Bootstrap: Configuration
 * Reads all environment variables and exports typed config objects.
 */

import type { AnchorTier } from "@sovereignly/oss/security/omnichain-anchor";

export const config = {
  nodeId:      process.env.SOVEREIGN_NODE_ID   ?? "primary",
  port:        parseInt(process.env.PORT        ?? "8787"),
  host:        process.env.HOST                 ?? "0.0.0.0",
  dataDir:     process.env.DATA_DIR             ?? "./data",
  poolSize:    parseInt(process.env.WORKER_POOL_SIZE ?? "4"),
  adminToken:  process.env.ADMIN_TOKEN,
  jwtSecret:   process.env.JWT_SECRET ?? crypto.randomUUID() + crypto.randomUUID(),
  serverKey:   process.env.SOVEREIGN_SERVER_KEY ?? crypto.randomUUID(),
  anchorInterval:       parseInt(process.env.CHAIN_ANCHOR_INTERVAL ?? "100"),
  globalAnchorInterval: parseInt(process.env.GLOBAL_ANCHOR_INTERVAL ?? "100"),
  anchorTier:  (process.env.ANCHOR_TIER ?? "starter") as AnchorTier,

  // Stripe
  stripeKey:      process.env.STRIPE_SECRET_KEY,
  stripeWebhook:  process.env.STRIPE_WEBHOOK_SECRET,
  stripeStarter:  process.env.STRIPE_PRICE_STARTER,
  stripeGrowth:   process.env.STRIPE_PRICE_GROWTH,
  stripeEnt:      process.env.STRIPE_PRICE_ENTERPRISE,

  // Cluster
  clusterId:       process.env.CLUSTER_ID        ?? "default",
  nodeRole:        (process.env.NODE_ROLE         ?? "cluster") as "control" | "cluster" | "edge",
  nodeRegion:      process.env.NODE_REGION        ?? "us-east",
  controlPlaneUrl: process.env.CONTROL_PLANE_URL,
  clusterPeers:    (process.env.CLUSTER_PEERS ?? "").split(",").filter(Boolean),

  // Derived
  appUrl: process.env.SOVEREIGN_DOMAIN
    ? `https://${process.env.SOVEREIGN_DOMAIN}`
    : `http://localhost:${parseInt(process.env.PORT ?? "8787")}`,

  corsOrigins:    (process.env.CORS_ORIGINS ?? "*").split(","),
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT ?? "600"),
  logLevel:       (process.env.LOG_LEVEL ?? "minimal") as "minimal" | "verbose",
  isProduction:   process.env.NODE_ENV === "production",
} as const;

export type Config = typeof config;
