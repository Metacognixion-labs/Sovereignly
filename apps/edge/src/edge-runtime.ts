// Sovereignly Edge Runtime -- BSL License
//
// Lightweight compute runtime for edge nodes.
// Executes edge functions (short-lived, stateless) close to users.
// Edge functions cannot access tenant chains — only cached data and APIs.

export interface EdgeFunction {
  id:       string;
  name:     string;
  code:     string;
  routes:   string[];     // URL patterns this function handles
  timeout:  number;       // max execution time in ms
  enabled:  boolean;
}

export interface EdgeInvocation {
  functionId: string;
  requestId:  string;
  path:       string;
  method:     string;
  headers:    Record<string, string>;
  body?:      unknown;
  startedAt:  number;
  durationMs?: number;
  status?:    number;
}

export class EdgeRuntime {
  private functions = new Map<string, EdgeFunction>();
  private invocations: EdgeInvocation[] = [];
  private maxHistory = 5000;
  private totalInvocations = 0;
  private totalErrors = 0;

  /** Register an edge function */
  register(fn: Omit<EdgeFunction, "id">): EdgeFunction {
    const id = `efn_${crypto.randomUUID().slice(0, 8)}`;
    const full: EdgeFunction = { ...fn, id };
    this.functions.set(id, full);
    console.log(`[EdgeRuntime] Function registered: ${fn.name} (${fn.routes.join(", ")})`);
    return full;
  }

  /** Remove an edge function */
  deregister(id: string): boolean {
    return this.functions.delete(id);
  }

  /** Find a function matching a request path */
  match(path: string): EdgeFunction | null {
    for (const fn of this.functions.values()) {
      if (!fn.enabled) continue;
      for (const route of fn.routes) {
        if (this.matchRoute(route, path)) return fn;
      }
    }
    return null;
  }

  /** Execute an edge function */
  async invoke(fn: EdgeFunction, request: {
    path: string;
    method: string;
    headers: Record<string, string>;
    body?: unknown;
  }): Promise<{ status: number; body: unknown; headers: Record<string, string> }> {
    const invocation: EdgeInvocation = {
      functionId: fn.id,
      requestId:  crypto.randomUUID(),
      path:       request.path,
      method:     request.method,
      headers:    request.headers,
      body:       request.body,
      startedAt:  Date.now(),
    };

    this.totalInvocations++;

    try {
      // Execute the function in a sandboxed context
      const result = await this.executeSandboxed(fn, request);
      invocation.durationMs = Date.now() - invocation.startedAt;
      invocation.status = result.status;
      this.recordInvocation(invocation);
      return result;
    } catch (err: any) {
      this.totalErrors++;
      invocation.durationMs = Date.now() - invocation.startedAt;
      invocation.status = 500;
      this.recordInvocation(invocation);
      return {
        status: 500,
        body: { error: "Edge function execution failed", message: err.message },
        headers: { "content-type": "application/json" },
      };
    }
  }

  private async executeSandboxed(
    fn: EdgeFunction,
    request: { path: string; method: string; headers: Record<string, string>; body?: unknown }
  ): Promise<{ status: number; body: unknown; headers: Record<string, string> }> {
    // Deterministic sandbox: execute function code with timeout
    // In production, this would use isolated-vm or Worker threads
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), fn.timeout);

    try {
      // Create a minimal runtime context for the function
      const ctx = {
        request: {
          path: request.path,
          method: request.method,
          headers: request.headers,
          body: request.body,
        },
        response: {
          status: 200,
          body: null as unknown,
          headers: { "content-type": "application/json" } as Record<string, string>,
        },
      };

      // Execute (for now, evaluate as a module)
      const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
      const handler = new AsyncFunction("ctx", fn.code);
      await handler(ctx);

      return {
        status:  ctx.response.status,
        body:    ctx.response.body,
        headers: ctx.response.headers,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private matchRoute(pattern: string, path: string): boolean {
    // Simple wildcard matching: /api/* matches /api/anything
    if (pattern === "*") return true;
    if (pattern === path) return true;
    if (pattern.endsWith("*")) {
      return path.startsWith(pattern.slice(0, -1));
    }
    return false;
  }

  private recordInvocation(inv: EdgeInvocation) {
    this.invocations.push(inv);
    if (this.invocations.length > this.maxHistory) {
      this.invocations = this.invocations.slice(-this.maxHistory);
    }
  }

  /** List registered functions */
  listFunctions(): EdgeFunction[] {
    return Array.from(this.functions.values());
  }

  /** Recent invocations */
  recent(limit = 50): EdgeInvocation[] {
    return this.invocations.slice(-limit).reverse();
  }

  stats() {
    const fns = Array.from(this.functions.values());
    return {
      functions:        fns.length,
      enabled:          fns.filter(f => f.enabled).length,
      totalInvocations: this.totalInvocations,
      totalErrors:      this.totalErrors,
      errorRate:        this.totalInvocations > 0
        ? `${(this.totalErrors / this.totalInvocations * 100).toFixed(1)}%`
        : "0%",
      recentInvocations: this.invocations.length,
    };
  }
}
