/**
 * SovereignAuth  OAuth 2.0 Broker
 *
 * Implements OAuth 2.0 Authorization Code flow for:
 *   - Google    (OpenID Connect)
 *   - GitHub    (OAuth 2.0)
 *   - Discord   (OAuth 2.0)
 *   - Meta      (Facebook OAuth 2.0)
 *
 * ZERO external dependencies. Pure HTTP flows using fetch().
 * We hold the OAuth app credentials  no third party intermediary.
 * Every auth event goes on-chain.
 *
 * Setup per provider:
 *   Google   console.cloud.google.com  Create OAuth App  add redirect URI
 *   GitHub   github.com/settings/developers  OAuth App  add redirect URI
 *   Discord  discord.com/developers  Applications  OAuth2  add redirect URI
 *   Meta     developers.facebook.com  App  Facebook Login  add redirect URI
 *
 * Redirect URI format: https://yourdomain.com/_sovereign/auth/oauth/{provider}/callback
 */

//  Provider configs 

export type OAuthProvider = "google" | "github" | "discord" | "meta";

interface ProviderConfig {
  name:          string;
  authUrl:       string;
  tokenUrl:      string;
  userInfoUrl:   string;
  scopes:        string[];
  iconEmoji:     string;
}

const PROVIDERS: Record<OAuthProvider, ProviderConfig> = {
  google: {
    name:        "Google",
    authUrl:     "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl:    "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
    scopes:      ["openid", "email", "profile"],
    iconEmoji:   "",
  },
  github: {
    name:        "GitHub",
    authUrl:     "https://github.com/login/oauth/authorize",
    tokenUrl:    "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
    scopes:      ["read:user", "user:email"],
    iconEmoji:   "",
  },
  discord: {
    name:        "Discord",
    authUrl:     "https://discord.com/oauth2/authorize",
    tokenUrl:    "https://discord.com/api/oauth2/token",
    userInfoUrl: "https://discord.com/api/users/@me",
    scopes:      ["identify", "email"],
    iconEmoji:   "",
  },
  meta: {
    name:        "Meta",
    authUrl:     "https://www.facebook.com/v19.0/dialog/oauth",
    tokenUrl:    "https://graph.facebook.com/v19.0/oauth/access_token",
    userInfoUrl: "https://graph.facebook.com/me?fields=id,name,email,picture",
    scopes:      ["email", "public_profile"],
    iconEmoji:   "",
  },
};

//  State store (PKCE + CSRF) 

interface OAuthState {
  provider:    OAuthProvider;
  redirectTo:  string;
  codeVerifier: string;   // PKCE
  expiresAt:   number;
}

const stateStore = new Map<string, OAuthState>();
const STATE_TTL  = 10 * 60 * 1000; // 10 minutes

//  PKCE helpers 

async function generateCodeVerifier(): Promise<string> {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

//  OAuthBroker 

export interface OAuthCredentials {
  clientId:     string;
  clientSecret: string;
  redirectUri:  string;   // https://yourdomain.com/_sovereign/auth/oauth/{provider}/callback
}

export interface OAuthUserProfile {
  provider:     OAuthProvider;
  sub:          string;    // provider-specific user ID
  email?:       string;
  name?:        string;
  username?:    string;    // GitHub, Discord
  avatarUrl?:   string;
  raw:          Record<string, unknown>;
}

export class OAuthBroker {
  constructor(
    private credentials: Partial<Record<OAuthProvider, OAuthCredentials>>
  ) {}

  //  Step 1: Generate authorization URL 

  async getAuthorizationUrl(
    provider:   OAuthProvider,
    redirectTo: string = "/"
  ): Promise<{ url: string; state: string }> {
    const creds = this.credentials[provider];
    if (!creds) throw new Error(`OAuth provider "${provider}" not configured`);

    const cfg          = PROVIDERS[provider];
    const state        = crypto.randomUUID();
    const codeVerifier = await generateCodeVerifier();
    const challenge    = await generateCodeChallenge(codeVerifier);

    stateStore.set(state, {
      provider, redirectTo, codeVerifier,
      expiresAt: Date.now() + STATE_TTL,
    });

    // Cleanup stale states
    if (stateStore.size > 1000) {
      const now = Date.now();
      for (const [k, v] of stateStore) {
        if (v.expiresAt < now) stateStore.delete(k);
      }
    }

    const params = new URLSearchParams({
      client_id:     creds.clientId,
      redirect_uri:  creds.redirectUri,
      response_type: "code",
      scope:         cfg.scopes.join(" "),
      state,
    });

    // Add PKCE (GitHub doesn't support, but Google + Discord do)
    if (provider !== "github") {
      params.set("code_challenge",        challenge);
      params.set("code_challenge_method", "S256");
    }

    // Provider-specific extras
    if (provider === "google") {
      params.set("access_type", "online");
      params.set("prompt",      "select_account");
    }

    return { url: `${cfg.authUrl}?${params}`, state };
  }

  //  Step 2: Handle callback  exchange code for tokens 

  async handleCallback(
    provider: OAuthProvider,
    code:     string,
    state:    string
  ): Promise<{ profile: OAuthUserProfile; redirectTo: string }> {
    const creds = this.credentials[provider];
    if (!creds) throw new Error(`Provider not configured: ${provider}`);

    // Verify state (CSRF protection)
    const stateData = stateStore.get(state);
    if (!stateData) throw new Error("Invalid or expired OAuth state");
    if (stateData.provider !== provider) throw new Error("State provider mismatch");
    if (Date.now() > stateData.expiresAt) {
      stateStore.delete(state);
      throw new Error("OAuth state expired");
    }
    stateStore.delete(state);

    const cfg = PROVIDERS[provider];

    // Exchange code for access token
    const tokenBody: Record<string, string> = {
      client_id:     creds.clientId,
      client_secret: creds.clientSecret,
      code,
      redirect_uri:  creds.redirectUri,
      grant_type:    "authorization_code",
    };

    // PKCE
    if (provider !== "github") {
      tokenBody.code_verifier = stateData.codeVerifier;
    }

    const tokenRes = await fetch(cfg.tokenUrl, {
      method:  "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept":       "application/json",
        // GitHub requires Accept header
        ...(provider === "github" ? { "Accept": "application/json" } : {}),
      },
      body: new URLSearchParams(tokenBody),
      signal: AbortSignal.timeout(10_000),
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      throw new Error(`Token exchange failed for ${provider}: ${err}`);
    }

    const tokens = await tokenRes.json();
    const accessToken = tokens.access_token;
    if (!accessToken) throw new Error(`No access_token in ${provider} response`);

    // Fetch user profile
    const userRes = await fetch(cfg.userInfoUrl, {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept":        "application/json",
        // GitHub requires User-Agent
        ...(provider === "github" ? { "User-Agent": "Sovereignly/3.0.1" } : {}),
      },
      signal: AbortSignal.timeout(8_000),
    });

    if (!userRes.ok) throw new Error(`User info failed for ${provider}: ${userRes.status}`);

    const raw    = await userRes.json();
    const profile = this.normalizeProfile(provider, raw, accessToken);

    // GitHub: fetch email separately if not in profile
    if (provider === "github" && !profile.email) {
      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept":        "application/json",
          "User-Agent":    "Sovereignly/3.0.1",
        },
        signal: AbortSignal.timeout(5_000),
      }).catch(() => null);

      if (emailRes?.ok) {
        const emails: any[] = await emailRes.json();
        const primary = emails.find(e => e.primary && e.verified);
        if (primary) profile.email = primary.email;
      }
    }

    return { profile, redirectTo: stateData.redirectTo };
  }

  //  Profile normalization 

  private normalizeProfile(
    provider:    OAuthProvider,
    raw:         any,
    accessToken: string
  ): OAuthUserProfile {
    switch (provider) {
      case "google":
        return {
          provider, sub: raw.sub,
          email:     raw.email,
          name:      raw.name,
          avatarUrl: raw.picture,
          raw,
        };

      case "github":
        return {
          provider, sub: String(raw.id),
          email:     raw.email,
          name:      raw.name || raw.login,
          username:  raw.login,
          avatarUrl: raw.avatar_url,
          raw,
        };

      case "discord":
        return {
          provider, sub: raw.id,
          email:     raw.email,
          name:      raw.global_name || raw.username,
          username:  raw.username,
          avatarUrl: raw.avatar
            ? `https://cdn.discordapp.com/avatars/${raw.id}/${raw.avatar}.png`
            : undefined,
          raw,
        };

      case "meta":
        return {
          provider, sub: raw.id,
          email:     raw.email,
          name:      raw.name,
          avatarUrl: raw.picture?.data?.url,
          raw,
        };

      default:
        return { provider, sub: raw.id ?? raw.sub, raw };
    }
  }

  getProviderInfo(provider: OAuthProvider) {
    return PROVIDERS[provider];
  }

  getSupportedProviders(): OAuthProvider[] {
    return Object.keys(this.credentials) as OAuthProvider[];
  }
}
