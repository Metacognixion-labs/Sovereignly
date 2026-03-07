// Sovereignly Edge Gateway -- BSL License
//
// Entry point for edge traffic. Handles:
//   1. Edge function execution (if a function matches the route)
//   2. Cache lookup (return cached response if available)
//   3. Proxy to upstream cluster (forward if no edge handler)

import type { EdgeRuntime } from "./edge-runtime.ts";
import type { EdgeCache } from "./edge-cache.ts";
import type { EventForwarder } from "./event-forwarder.ts";

export interface EdgeGatewayConfig {
  edgeNodeId:    string;
  clusterUrl:    string;    // upstream cluster URL
  cacheTTLMs?:   number;    // default cache TTL for proxied responses
}

export class EdgeGateway {
  private totalRequests = 0;
  private cacheHits = 0;
  private edgeHits = 0;
  private proxyHits = 0;

  constructor(
    private runtime: EdgeRuntime,
    private cache: EdgeCache,
    private forwarder: EventForwarder,
    private config: EdgeGatewayConfig,
  ) {}

  /** Handle an incoming request at the edge */
  async handle(request: {
    path:    string;
    method:  string;
    headers: Record<string, string>;
    body?:   unknown;
  }): Promise<{ status: number; body: unknown; headers: Record<string, string>; source: "edge" | "cache" | "proxy" }> {
    this.totalRequests++;

    // 1. Check if an edge function handles this route
    const fn = this.runtime.match(request.path);
    if (fn) {
      this.edgeHits++;
      const result = await this.runtime.invoke(fn, request);
      return { ...result, source: "edge" };
    }

    // 2. Check cache for GET requests
    if (request.method === "GET") {
      const cacheKey = `${request.path}`;
      const cached = this.cache.get<{ status: number; body: unknown; headers: Record<string, string> }>(cacheKey);
      if (cached) {
        this.cacheHits++;
        return { ...cached, source: "cache" };
      }
    }

    // 3. Proxy to upstream cluster
    this.proxyHits++;
    return this.proxy(request);
  }

  /** Forward request to upstream cluster */
  private async proxy(request: {
    path:    string;
    method:  string;
    headers: Record<string, string>;
    body?:   unknown;
  }): Promise<{ status: number; body: unknown; headers: Record<string, string>; source: "proxy" }> {
    try {
      const url = `${this.config.clusterUrl}${request.path}`;
      const fetchOpts: RequestInit = {
        method: request.method,
        headers: {
          ...request.headers,
          "x-forwarded-by": this.config.edgeNodeId,
          "x-edge-region": request.headers["x-edge-region"] ?? "",
        },
        signal: AbortSignal.timeout(30_000),
      };

      if (request.body && request.method !== "GET" && request.method !== "HEAD") {
        fetchOpts.body = JSON.stringify(request.body);
        (fetchOpts.headers as Record<string, string>)["content-type"] = "application/json";
      }

      const res = await fetch(url, fetchOpts);
      const contentType = res.headers.get("content-type") ?? "application/json";
      let body: unknown;

      if (contentType.includes("json")) {
        body = await res.json();
      } else {
        body = await res.text();
      }

      const responseHeaders: Record<string, string> = {
        "content-type": contentType,
        "x-served-by": this.config.edgeNodeId,
        "x-upstream": this.config.clusterUrl,
      };

      // Cache GET responses with 2xx status
      if (request.method === "GET" && res.status >= 200 && res.status < 300) {
        this.cache.set(request.path, { status: res.status, body, headers: responseHeaders }, this.config.cacheTTLMs);
      }

      return { status: res.status, body, headers: responseHeaders, source: "proxy" };
    } catch (err: any) {
      return {
        status: 502,
        body: { error: "Upstream cluster unreachable", message: err.message },
        headers: { "content-type": "application/json", "x-served-by": this.config.edgeNodeId },
        source: "proxy",
      };
    }
  }

  /** Forward an event to the cluster (fire-and-forget via event forwarder) */
  forwardEvent(type: string, payload: Record<string, unknown>, tenantId?: string): void {
    this.forwarder.queue({ type, payload, tenantId });
  }

  stats() {
    return {
      totalRequests:  this.totalRequests,
      edgeHits:       this.edgeHits,
      cacheHits:      this.cacheHits,
      proxyHits:      this.proxyHits,
      edgeRate:       this.totalRequests > 0 ? `${(this.edgeHits / this.totalRequests * 100).toFixed(1)}%` : "0%",
      cacheRate:      this.totalRequests > 0 ? `${(this.cacheHits / this.totalRequests * 100).toFixed(1)}%` : "0%",
    };
  }
}
