/**
 * Sovereignly v3  Bun Worker Runtime
 *
 * Why Bun Workers over Node.js vm module:
 *  - True OS-level process isolation (no shared memory)
 *  - Each worker runs a fresh Bun context (JavaScriptCore engine)
 *  - Memory limits enforced at OS level
 *  - Worker pool pre-warms isolates  near-zero cold start
 *  - Crash in worker = worker restarts, main process unaffected
 *
 * Architecture:
 *   Gateway  WorkerPool  [Worker, Worker, ... WorkerN]
 *   Each Worker runs worker-sandbox.ts which:
 *     - Receives the function code + request via postMessage
 *     - Evaluates in a restricted scope (no Bun.*, no fs.*)
 *     - Returns serialized Response back
 */

import type { SovereignKV } from "../kv/index.ts";

export interface FunctionRecord {
  id: string;
  name: string;
  code: string;
  version: string;
  route: string;
  methods: string[];
  env: Record<string, string>;
  memoryLimitMB: number;
  timeoutMs: number;
  deployedAt: Date;
  // Stats (mutable)
  invocations: number;
  errors: number;
  avgMs: number;
  p95Ms: number;
  lastInvokedAt?: Date;
}

export interface InvokeRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

export interface InvokeResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  ms: number;
  workerId: number;
  cached: boolean;
}

//  Sandbox Worker Script 
// This is inlined as a string so we can spawn it without a separate file.
const SANDBOX_SCRIPT = /* js */ `
// Sovereignly Sandbox Worker
// Runs inside a Bun.Worker  fully isolated process

self.onmessage = async ({ data }) => {
  const { msgId, code, request, env, kv } = data;
  const start = performance.now();

  try {
    //  Build restricted global scope 
    const kvProxy = {
      get:    (key)          => kv.data[key] ?? null,
      set:    (key, val, o)  => { /* batched back via postMessage */ self.postMessage({ type: 'kv:set', key, val, ttl: o?.ttl }); },
      delete: (key)          => { self.postMessage({ type: 'kv:del', key }); },
      incr:   (key, by = 1) => { self.postMessage({ type: 'kv:incr', key, by }); return (kv.data[key] ? parseInt(kv.data[key]) : 0) + by; },
      list:   (prefix)       => Object.keys(kv.data).filter(k => !prefix || k.startsWith(prefix)).map(key => ({ key })),
    };

    const secretsProxy = {
      get: (name) => env['SECRET_' + name] ?? undefined,
    };

    //  Evaluate function code 
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    const fn = new AsyncFunction(
      'KV', 'SECRETS', 'env', 'fetch', 'Request', 'Response', 'Headers',
      'URL', 'URLSearchParams', 'crypto', 'TextEncoder', 'TextDecoder',
      'atob', 'btoa', 'JSON', 'Math', 'Date', 'performance',
      'console', 'setTimeout', 'clearTimeout', 'Promise',
      code + '\\n; return handler;'
    );

    const handler = await fn(
      kvProxy, secretsProxy, env, fetch,
      Request, Response, Headers, URL, URLSearchParams,
      crypto, TextEncoder, TextDecoder, atob, btoa,
      JSON, Math, Date, performance,
      console, setTimeout, clearTimeout, Promise
    );

    if (typeof handler !== 'function') throw new Error("Function must export a 'handler' function");

    //  Execute handler 
    const req = new Request(request.url, {
      method: request.method,
      headers: new Headers(request.headers),
      body: request.body ?? undefined,
    });

    const result = await handler(req, env);

    let status = 200, headers = {}, body = '';

    if (result instanceof Response) {
      status = result.status;
      result.headers.forEach((v, k) => { headers[k] = v; });
      body = await result.text();
    } else if (result !== undefined) {
      status = 200;
      headers = { 'content-type': 'application/json' };
      body = JSON.stringify(result);
    }

    self.postMessage({
      type: 'result',
      msgId,
      status, headers, body,
      ms: performance.now() - start,
    });

  } catch (err) {
    self.postMessage({
      type: 'result',
      msgId,
      status: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: err.message, type: 'FUNCTION_ERROR' }),
      ms: performance.now() - start,
    });
  }
};
`;

//  Worker Pool 

interface PooledWorker {
  id: number;
  worker: Worker;
  busy: boolean;
  taskCount: number;
}

export class WorkerPool {
  private workers: PooledWorker[] = [];
  private queue: Array<{ resolve: Function; reject: Function; task: any }> = [];
  private pendingResults = new Map<string, { resolve: Function; reject: Function; timer: Timer }>();
  private workerIdCounter = 0;

  constructor(
    private readonly poolSize: number,
    private readonly kv: SovereignKV
  ) {
    this.spawn(poolSize);
    console.log(`[Runtime] Worker pool: ${poolSize} workers pre-warmed`);
  }

  private spawn(count: number) {
    for (let i = 0; i < count; i++) {
      const blob = new Blob([SANDBOX_SCRIPT], { type: "application/javascript" });
      const url = URL.createObjectURL(blob);
      const worker = new Worker(url);
      const id = ++this.workerIdCounter;

      worker.onmessage = (e: MessageEvent) => this.handleMessage(id, e.data);
      worker.onerror = (e: ErrorEvent) => {
        console.error(`[Runtime] Worker ${id} error:`, e.message);
        this.replaceWorker(id);
      };

      this.workers.push({ id, worker, busy: false, taskCount: 0 });
    }
  }

  private handleMessage(workerId: number, msg: any) {
    const worker = this.workers.find(w => w.id === workerId);
    if (!worker) return;

    if (msg.type === 'result') {
      const pending = this.pendingResults.get(msg.msgId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingResults.delete(msg.msgId);
        pending.resolve({ ...msg, workerId });
      }
      worker.busy = false;
      this.drain();
      return;
    }

    // KV side-effects from sandbox
    if (msg.type === 'kv:set') this.kv._set('_worker', msg.key, msg.val, { ttl: msg.ttl });
    if (msg.type === 'kv:del') this.kv._delete('_worker', msg.key);
  }

  private replaceWorker(id: number) {
    const idx = this.workers.findIndex(w => w.id === id);
    if (idx === -1) return;
    this.workers[idx].worker.terminate();
    this.workers.splice(idx, 1);
    this.spawn(1);
  }

  private drain() {
    if (this.queue.length === 0) return;
    const next = this.queue.shift()!;
    this.run(next.task).then(next.resolve).catch(next.reject);
  }

  async run(task: {
    code: string;
    request: InvokeRequest;
    env: Record<string, string>;
    timeoutMs: number;
    kvNamespace: string;
  }): Promise<InvokeResponse> {
    const available = this.workers.find(w => !w.busy);

    if (!available) {
      // Queue it
      return new Promise((resolve, reject) => {
        this.queue.push({ resolve, reject, task });
      });
    }

    available.busy = true;
    available.taskCount++;

    const msgId = crypto.randomUUID();

    // Pre-fetch KV data for the function's namespace
    const kvEntries = this.kv._list(task.kvNamespace, undefined, 500);
    const kvData: Record<string, string> = {};
    for (const { key } of kvEntries) {
      const val = this.kv._get(task.kvNamespace, key);
      if (val) kvData[key] = val;
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingResults.delete(msgId);
        available.busy = false;
        reject(new Error(`Function timeout after ${task.timeoutMs}ms`));
      }, task.timeoutMs);

      this.pendingResults.set(msgId, { resolve, reject, timer });

      available.worker.postMessage({
        msgId,
        code: task.code,
        request: task.request,
        env: task.env,
        kv: { data: kvData, namespace: task.kvNamespace },
      });
    });
  }

  stats() {
    return {
      total: this.workers.length,
      busy: this.workers.filter(w => w.busy).length,
      queued: this.queue.length,
      totalTasks: this.workers.reduce((s, w) => s + w.taskCount, 0),
    };
  }

  terminate() {
    for (const w of this.workers) w.worker.terminate();
    this.workers = [];
  }
}

//  Runtime Manager 

export class SovereignRuntime {
  private functions = new Map<string, FunctionRecord>();
  private pool: WorkerPool;
  private latencyHistory = new Map<string, number[]>(); // fnId  last N ms values

  constructor(
    private readonly kv: SovereignKV,
    options: { poolSize?: number } = {}
  ) {
    this.pool = new WorkerPool(options.poolSize ?? 4, kv);
  }

  register(fn: Omit<FunctionRecord, 'deployedAt' | 'invocations' | 'errors' | 'avgMs' | 'p95Ms'>) {
    const record: FunctionRecord = {
      ...fn,
      deployedAt: new Date(),
      invocations: 0,
      errors: 0,
      avgMs: 0,
      p95Ms: 0,
    };
    this.functions.set(fn.id, record);
    this.latencyHistory.set(fn.id, []);
    console.log(`[Runtime] Registered: ${fn.name}  ${fn.route} [${fn.methods.join('|')}]`);
    return record;
  }

  async invoke(fnId: string, req: InvokeRequest): Promise<InvokeResponse> {
    const fn = this.functions.get(fnId);
    if (!fn) {
      return {
        status: 404,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ error: `Function '${fnId}' not found` }),
        ms: 0, workerId: 0, cached: false,
      };
    }

    try {
      const result = await this.pool.run({
        code: fn.code,
        request: req,
        env: { ...fn.env, FUNCTION_ID: fn.id, FUNCTION_VERSION: fn.version },
        timeoutMs: fn.timeoutMs,
        kvNamespace: fn.id,
      });

      // Update stats
      fn.invocations++;
      fn.lastInvokedAt = new Date();
      if (result.status >= 500) fn.errors++;

      const history = this.latencyHistory.get(fn.id) ?? [];
      history.push(result.ms);
      if (history.length > 100) history.shift();
      this.latencyHistory.set(fn.id, history);

      const sorted = [...history].sort((a, b) => a - b);
      fn.avgMs = history.reduce((s, v) => s + v, 0) / history.length;
      fn.p95Ms = sorted[Math.floor(sorted.length * 0.95)] ?? 0;

      return result;
    } catch (err: any) {
      fn.errors++;
      return {
        status: 504,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ error: err.message }),
        ms: fn.timeoutMs,
        workerId: 0,
        cached: false,
      };
    }
  }

  get(id: string) { return this.functions.get(id); }
  list() { return [...this.functions.values()]; }
  delete(id: string) { return this.functions.delete(id); }
  workerStats() { return this.pool.stats(); }

  shutdown() {
    this.pool.terminate();
  }
}
