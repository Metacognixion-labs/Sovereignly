// Sovereignly Event Bus -- MIT License
// Typed pub/sub system. Chain audit logging is one subscriber among many.
// All infrastructure events flow through here.
//
// Design: in-process, zero-dep, async subscribers, wildcard matching.
// Events are immutable once emitted (per SYSTEM_BIBLE.md).

// -- Event types from EVENTS.md + existing chain types --

export type SystemEvent =
  // Tenant lifecycle
  | "TENANT_CREATED" | "TENANT_DELETED" | "TENANT_SUSPENDED" | "TENANT_UPGRADED"
  // Workflow lifecycle
  | "WORKFLOW_STARTED" | "WORKFLOW_STEP_COMPLETED" | "WORKFLOW_COMPLETED" | "WORKFLOW_FAILED"
  // Agent lifecycle
  | "AGENT_EXECUTED" | "AGENT_REGISTERED" | "AGENT_FAILED"
  // Machine lifecycle
  | "MACHINE_STARTED" | "MACHINE_STOPPED" | "MACHINE_FAILED" | "MACHINE_MIGRATED"
  // Auth events (existing)
  | "AUTH_SUCCESS" | "AUTH_FAILURE" | "MFA_CHALLENGE" | "SESSION_END"
  // Config / data events (existing)
  | "CONFIG_CHANGE" | "SECRET_ROTATION" | "DATA_READ" | "DATA_EXPORT"
  // Security events (existing)
  | "ANOMALY" | "RATE_LIMIT_HIT" | "PERMISSION_CHANGE"
  // Chain events
  | "CHAIN_GENESIS" | "NODE_JOIN" | "NODE_LEAVE"
  // Infrastructure
  | "FUNCTION_DEPLOY" | "FUNCTION_DELETE" | "FUNCTION_INVOKE"
  // Policy
  | "POLICY_CREATED" | "POLICY_VIOLATED" | "POLICY_EVALUATED"
  // Catch-all for extensions
  | string;

export type EventSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface SovereignEvent {
  id:        string;
  type:      SystemEvent;
  ts:        number;
  source:    string;      // which subsystem emitted (e.g. "tenant-runtime", "agent:health-monitor")
  tenantId?: string;      // tenant scope (null = platform-level)
  severity:  EventSeverity;
  payload:   Record<string, unknown>;
  // Immutable once created -- no setter
  readonly _sealed: true;
}

export type EventSubscriber = (event: SovereignEvent) => void | Promise<void>;

interface Subscription {
  id:       string;
  pattern:  string;          // event type or "*" for all
  handler:  EventSubscriber;
  source:   string;          // who subscribed (for debugging)
}

// -- Event Bus --

export class EventBus {
  private subs: Subscription[] = [];
  private history: SovereignEvent[];
  private maxHistory = 10_000;
  private historyIdx = 0;
  private historyFull = false;
  private emitCount = 0;

  constructor() {
    this.history = new Array(this.maxHistory);
  }

  // Subscribe to events. Pattern: exact type, or "*" for all.
  on(pattern: string, handler: EventSubscriber, source = "unknown"): string {
    const id = `sub_${crypto.randomUUID().slice(0, 12)}`;
    this.subs.push({ id, pattern, handler, source });
    return id;
  }

  // Unsubscribe
  off(id: string): boolean {
    const idx = this.subs.findIndex(s => s.id === id);
    if (idx === -1) return false;
    this.subs.splice(idx, 1);
    return true;
  }

  // Emit an event. All matching subscribers called (fire-and-forget).
  async emit(
    type:      SystemEvent,
    payload:   Record<string, unknown>,
    opts: {
      severity?:  EventSeverity;
      source?:    string;
      tenantId?:  string;
    } = {}
  ): Promise<SovereignEvent> {
    const event: SovereignEvent = {
      id:       crypto.randomUUID(),
      type,
      ts:       Date.now(),
      source:   opts.source ?? "platform",
      tenantId: opts.tenantId,
      severity: opts.severity ?? "LOW",
      payload,
      _sealed:  true,
    };

    // Store in circular buffer (no array reallocation)
    this.history[this.historyIdx] = event;
    this.historyIdx = (this.historyIdx + 1) % this.maxHistory;
    if (!this.historyFull && this.historyIdx === 0) this.historyFull = true;
    this.emitCount++;

    // Dispatch to matching subscribers
    const matching = this.subs.filter(s =>
      s.pattern === "*" || s.pattern === type
    );

    // Fire all subscribers (don't await -- non-blocking)
    for (const sub of matching) {
      try {
        const result = sub.handler(event);
        if (result instanceof Promise) {
          result.catch(err =>
            console.warn(`[EventBus] Subscriber ${sub.source} error:`, err.message)
          );
        }
      } catch (err: any) {
        console.warn(`[EventBus] Subscriber ${sub.source} threw:`, err.message);
      }
    }

    return event;
  }

  // Materialize circular buffer into ordered array
  private orderedHistory(): SovereignEvent[] {
    if (!this.historyFull) return this.history.slice(0, this.historyIdx).filter(Boolean);
    return [
      ...this.history.slice(this.historyIdx),
      ...this.history.slice(0, this.historyIdx),
    ].filter(Boolean);
  }

  // Query recent events (from in-memory history)
  query(opts: {
    type?:     string;
    tenantId?: string;
    since?:    number;
    limit?:    number;
  } = {}): SovereignEvent[] {
    let results = this.orderedHistory();
    if (opts.type)     results = results.filter(e => e.type === opts.type);
    if (opts.tenantId) results = results.filter(e => e.tenantId === opts.tenantId);
    if (opts.since)    results = results.filter(e => e.ts >= opts.since);
    return results.slice(-(opts.limit ?? 100));
  }

  // Stats
  stats() {
    const size = this.historyFull ? this.maxHistory : this.historyIdx;
    return {
      subscribers: this.subs.length,
      historySize: size,
      totalEmitted: this.emitCount,
      subscriberDetails: this.subs.map(s => ({
        id: s.id, pattern: s.pattern, source: s.source,
      })),
    };
  }

  // Cleanup
  close() {
    this.subs = [];
    this.history = new Array(this.maxHistory);
    this.historyIdx = 0;
    this.historyFull = false;
  }
}

// Singleton for the platform
export const platformBus = new EventBus();
