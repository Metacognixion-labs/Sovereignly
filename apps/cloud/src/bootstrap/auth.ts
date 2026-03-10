/**
 * Bootstrap: OAuth + Passkeys + Magic Link + TOTP
 */

import { OAuthBroker }   from "@sovereignly/oss/auth/oauth";
import { PasskeyEngine } from "@sovereignly/oss/auth/passkeys";
import { MagicLinkService } from "../../../oss/src/auth/magic-link.ts";
import { TOTPService }      from "../../../oss/src/auth/totp.ts";
import { createEmailTransport } from "../../../oss/src/auth/email-transport.ts";
import type { Config } from "./config.ts";

export function createAuth(cfg: Config) {
  const oauthBroker = new OAuthBroker({
    google:  process.env.GOOGLE_CLIENT_ID  ? { clientId: process.env.GOOGLE_CLIENT_ID!,  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,  redirectUri: `${cfg.appUrl}/_sovereign/auth/oauth/google/callback`  } : undefined,
    github:  process.env.GITHUB_CLIENT_ID  ? { clientId: process.env.GITHUB_CLIENT_ID!,  clientSecret: process.env.GITHUB_CLIENT_SECRET!,  redirectUri: `${cfg.appUrl}/_sovereign/auth/oauth/github/callback`  } : undefined,
    discord: process.env.DISCORD_CLIENT_ID ? { clientId: process.env.DISCORD_CLIENT_ID!, clientSecret: process.env.DISCORD_CLIENT_SECRET!, redirectUri: `${cfg.appUrl}/_sovereign/auth/oauth/discord/callback` } : undefined,
    meta:    process.env.META_CLIENT_ID    ? { clientId: process.env.META_CLIENT_ID!,    clientSecret: process.env.META_CLIENT_SECRET!,    redirectUri: `${cfg.appUrl}/_sovereign/auth/oauth/meta/callback`    } : undefined,
  });

  const passkeys = new PasskeyEngine({
    dataDir: `${cfg.dataDir}/platform`,
    rpId:    process.env.SOVEREIGN_DOMAIN ?? "localhost",
    rpName:  "Sovereignly",
    origin:  cfg.appUrl,
  });

  const emailTransport = createEmailTransport();
  const dataDir = `${cfg.dataDir}/platform`;

  const magicLink = new MagicLinkService({
    dataDir,
    emailTransport,
    signingKey: cfg.jwtSecret ?? process.env.SOVEREIGN_SERVER_KEY ?? "dev-magic-key",
    appUrl: cfg.appUrl,
  });

  const totpService = new TOTPService({
    dataDir,
    encPassword: cfg.jwtSecret ?? process.env.SOVEREIGN_SERVER_KEY ?? "dev-totp-key",
  });

  return { oauthBroker, passkeys, magicLink, totpService };
}
