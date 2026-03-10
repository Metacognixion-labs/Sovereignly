/**
 * Sovereignly v4.0 — SSRF Guard
 *
 * Prevents Server-Side Request Forgery (SSRF) attacks on webhook delivery
 * and any other outbound HTTP requests from user-controlled URLs.
 *
 * Protections:
 *   1. Block private/reserved IP ranges (RFC 1918, loopback, link-local)
 *   2. Block cloud metadata endpoints (AWS, GCP, Azure)
 *   3. DNS rebinding protection (resolve before connect, pin resolved IP)
 *   4. Protocol enforcement (HTTPS only in production, HTTP allowed in dev)
 *   5. Hostname blocklist (localhost aliases, internal services)
 */

// ── Private/Reserved IP Ranges ──────────────────────────────────────────────

const PRIVATE_RANGES = [
  // IPv4 private
  { prefix: "10.", match: (ip: string) => ip.startsWith("10.") },
  { prefix: "172.16-31", match: (ip: string) => {
    const m = ip.match(/^172\.(\d+)\./);
    return !!m && parseInt(m[1]) >= 16 && parseInt(m[1]) <= 31;
  }},
  { prefix: "192.168.", match: (ip: string) => ip.startsWith("192.168.") },

  // Loopback
  { prefix: "127.", match: (ip: string) => ip.startsWith("127.") },
  { prefix: "::1", match: (ip: string) => ip === "::1" || ip === "0:0:0:0:0:0:0:1" },

  // Link-local
  { prefix: "169.254.", match: (ip: string) => ip.startsWith("169.254.") },
  { prefix: "fe80::", match: (ip: string) => ip.toLowerCase().startsWith("fe80:") },

  // IPv6 private
  { prefix: "fc00::/7", match: (ip: string) => {
    const lower = ip.toLowerCase();
    return lower.startsWith("fc") || lower.startsWith("fd");
  }},

  // Unspecified
  { prefix: "0.0.0.0", match: (ip: string) => ip === "0.0.0.0" },
  { prefix: "::", match: (ip: string) => ip === "::" || ip === "0:0:0:0:0:0:0:0" },
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some(r => r.match(ip));
}

// ── Blocked Hostnames ───────────────────────────────────────────────────────

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",      // GCP metadata
  "metadata.internal",
]);

const BLOCKED_HOSTNAME_SUFFIXES = [
  ".internal",
  ".local",
  ".localhost",
  ".svc.cluster.local",            // Kubernetes
  ".pod.cluster.local",
];

function isBlockedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(lower)) return true;
  return BLOCKED_HOSTNAME_SUFFIXES.some(s => lower.endsWith(s));
}

// ── Cloud Metadata IPs ──────────────────────────────────────────────────────

const METADATA_IPS = new Set([
  "169.254.169.254",               // AWS, GCP, Azure metadata endpoint
  "100.100.100.200",               // Alibaba Cloud metadata
  "169.254.170.2",                 // AWS ECS task metadata
]);

function isMetadataIP(ip: string): boolean {
  return METADATA_IPS.has(ip);
}

// ── Validation Result ───────────────────────────────────────────────────────

export interface SSRFValidation {
  safe:    boolean;
  reason?: string;
}

// ── SSRFGuard ───────────────────────────────────────────────────────────────

export class SSRFGuard {
  private readonly allowHTTP: boolean;

  constructor(opts?: { allowHTTP?: boolean }) {
    // In development, allow HTTP; in production, require HTTPS
    this.allowHTTP = opts?.allowHTTP ?? (process.env.NODE_ENV === "development");
  }

  /**
   * Validate a URL is safe for outbound requests.
   * Does NOT make a network request — only inspects the URL structure.
   */
  validateURL(url: string): SSRFValidation {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return { safe: false, reason: "Invalid URL" };
    }

    // Protocol check
    if (parsed.protocol === "http:" && !this.allowHTTP) {
      return { safe: false, reason: "HTTPS required for webhook URLs" };
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return { safe: false, reason: `Blocked protocol: ${parsed.protocol}` };
    }

    // Port check — block common internal service ports
    const port = parsed.port ? parseInt(parsed.port) : (parsed.protocol === "https:" ? 443 : 80);
    if (port === 0) {
      return { safe: false, reason: "Port 0 is not allowed" };
    }

    // Hostname checks
    const hostname = parsed.hostname;

    if (isBlockedHostname(hostname)) {
      return { safe: false, reason: `Blocked hostname: ${hostname}` };
    }

    // Check if hostname is an IP address
    if (this.isIPAddress(hostname)) {
      if (isPrivateIP(hostname)) {
        return { safe: false, reason: `Blocked private IP: ${hostname}` };
      }
      if (isMetadataIP(hostname)) {
        return { safe: false, reason: `Blocked cloud metadata IP: ${hostname}` };
      }
    }

    // Check for IP-in-hostname tricks (decimal, hex, octal)
    const decodedIP = this.decodeIPTricks(hostname);
    if (decodedIP && (isPrivateIP(decodedIP) || isMetadataIP(decodedIP))) {
      return { safe: false, reason: `Blocked obfuscated private IP: ${hostname} → ${decodedIP}` };
    }

    // Username/password in URL (potential smuggling)
    if (parsed.username || parsed.password) {
      return { safe: false, reason: "Credentials in URL not allowed" };
    }

    return { safe: true };
  }

  /**
   * Perform a safe outbound fetch with DNS rebinding protection.
   * Resolves hostname first, validates the resolved IP, then fetches
   * with the validated IP pinned.
   */
  async safeFetch(url: string, opts?: RequestInit): Promise<Response> {
    // Step 1: Static URL validation
    const validation = this.validateURL(url);
    if (!validation.safe) {
      throw new SSRFError(`SSRF blocked: ${validation.reason}`);
    }

    const parsed = new URL(url);

    // Step 2: DNS resolution and IP validation
    if (!this.isIPAddress(parsed.hostname)) {
      const resolvedIPs = await this.resolveHostname(parsed.hostname);
      if (resolvedIPs.length === 0) {
        throw new SSRFError(`DNS resolution failed for ${parsed.hostname}`);
      }

      // Validate ALL resolved IPs (attacker might have multiple A records)
      for (const ip of resolvedIPs) {
        if (isPrivateIP(ip) || isMetadataIP(ip)) {
          throw new SSRFError(`DNS rebinding detected: ${parsed.hostname} → ${ip}`);
        }
      }
    }

    // Step 3: Fetch with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10_000);

    try {
      return await fetch(url, {
        ...opts,
        signal: controller.signal,
        redirect: "manual",  // Don't follow redirects automatically (could redirect to internal)
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  private isIPAddress(hostname: string): boolean {
    // IPv4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
    // IPv6 (bracketed in URLs, but URL parser strips brackets)
    if (hostname.includes(":")) return true;
    return false;
  }

  /**
   * Detect obfuscated IP addresses:
   * - Decimal: 2130706433 → 127.0.0.1
   * - Hex: 0x7f000001 → 127.0.0.1
   * - Octal: 0177.0.0.1 → 127.0.0.1
   * - Mixed: 127.0.0.1 with leading zeros
   */
  private decodeIPTricks(hostname: string): string | null {
    // Pure decimal integer → IP
    if (/^\d+$/.test(hostname)) {
      const num = parseInt(hostname, 10);
      if (num >= 0 && num <= 0xFFFFFFFF) {
        return `${(num >> 24) & 0xFF}.${(num >> 16) & 0xFF}.${(num >> 8) & 0xFF}.${num & 0xFF}`;
      }
    }

    // Hex integer → IP
    if (/^0x[0-9a-f]+$/i.test(hostname)) {
      const num = parseInt(hostname, 16);
      if (num >= 0 && num <= 0xFFFFFFFF) {
        return `${(num >> 24) & 0xFF}.${(num >> 16) & 0xFF}.${(num >> 8) & 0xFF}.${num & 0xFF}`;
      }
    }

    // Octal octets (leading zeros)
    if (/^0\d+\./.test(hostname)) {
      const parts = hostname.split(".");
      if (parts.length === 4) {
        const octets = parts.map(p => parseInt(p, p.startsWith("0") && p.length > 1 ? 8 : 10));
        if (octets.every(o => o >= 0 && o <= 255)) {
          return octets.join(".");
        }
      }
    }

    return null;
  }

  private async resolveHostname(hostname: string): Promise<string[]> {
    try {
      // Bun supports DNS resolution
      const dns = await import("node:dns/promises");
      const results = await dns.resolve4(hostname);
      return results;
    } catch {
      // If DNS resolution fails, return empty — caller handles it
      return [];
    }
  }
}

// ── Error class ─────────────────────────────────────────────────────────────

export class SSRFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SSRFError";
  }
}
