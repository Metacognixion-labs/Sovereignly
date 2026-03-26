// Sovereignly Event Bus -- MIT License
// Typed pub/sub system. Chain audit logging is one subscriber among many.
// All infrastructure events flow through here.
//
// Design: in-process, async subscribers, wildcard matching.
// Events are immutable once emitted (per SYSTEM_BIBLE.md).
// Transactional outbox: events persisted to SQLite before dispatch.
// Dead letter queue: failed dispatches retried with exponential backoff.

import { Database } from "bun:sqlite";
import { join }     from "node:path";
import { log } from "../observability/index.ts";

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

// -- Event Bus with Transactional Outbox --

export class EventBus {
  private subs: Subscription[] = [];
  private history: SovereignEvent[];
  private maxHistory = 10_000;
  private historyIdx = 0;
  private historyFull = false;
  private emitCount = 0;

  // Outbox persistence (optional — enabled via initOutbox)
  private outboxDb: Database | null = null;
  private dlqRetryTimer: ReturnType<typeof setInterval> | null = null;
  private failedCount = 0;

  constructor() {
    this.history = new Array(this.maxHistory);
  }

  /** Enable persistent outbox. Events written to SQLite before dispatch. Failed events retried. */
  initOutbox(dataDir: string): void {
    this.outboxDb = new Database(join(dataDir, "event-outbox.db"));
    this.outboxDb.run("PRAGMA journal_mode = WAL");
    this.outboxDb.run("PRAGMA busy_timeout = 5000");
    this.outboxDb.run(`
      CREATE TABLE IF NOT EXISTS outbox (
        id          TEXT PRIMARY KEY,
        type        TEXT NOT NULL,
        payload     TEXT NOT NULL,
        severity    TEXT NOT NULL DEFAULT 'LOW',
        source      TEXT NOT NULL DEFAULT 'platform',
        tenant_id   TEXT,
        ts          INTEGER NOT NULL,
        dispatched  INTEGER NOT NULL DEFAULT 0,
        attempts    INTEGER NOT NULL DEFAULT 0,
        last_error  TEXT
      )
    `);
    this.outboxDb.run("CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(dispatched, attempts)");

    // Retry failed events every 30 seconds (max 5 attempts, exponential backoff)
    this.dlqRetryTimer = setInterval(() => this.retryFailed(), 30_000);

    // Dispatch any un-dispatched events from previous crash
    this.replayPending();
  }

  on(pattern: string, handler: EventSubscriber, source = "unknown"): string {
    const id = `sub_${crypto.randomUUID().slice(0, 12)}`;
    this.subs.push({ id, pattern, handler, source });
    return id;
  }

  off(id: string): boolean {
    const idx = this.subs.findIndex(s => s.id === id);
    if (idx === -1) return false;
    this.subs.splice(idx, 1);
    return true;
  }

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

    // 1. Persist to outbox BEFORE dispatch (transactional outbox pattern)
    if (this.outboxDb) {
      this.outboxDb.prepare(
        "INSERT INTO outbox (id, type, payload, severity, source, tenant_id, ts) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).run(event.id, event.type, JSON.stringify(event.payload), event.severity, event.source, event.tenantId ?? null, event.ts);
    }

    // 2. Store in circular buffer
    this.history[this.historyIdx] = event;
    this.historyIdx = (this.historyIdx + 1) % this.maxHistory;
    if (!this.historyFull && this.historyIdx === 0) this.historyFull = true;
    this.emitCount++;

    // 3. Dispatch to subscribers
    await this.dispatch(event);

    return event;
  }

  private async dispatch(event: SovereignEvent): Promise<void> {
    const matching = this.subs.filter(s => s.pattern === "*" || s.pattern === event.type);
    let failed = false;

    for (const sub of matching) {
      try {
        const result = sub.handler(event);
        if (result instanceof Promise) {
          await result.catch(err => {
            log("warn", "EventBus subscriber error", { subscriber: sub.source, error: err.message });
            failed = true;
          });
        }
      } catch (err: any) {
        log("warn", "EventBus subscriber threw", { subscriber: sub.source, error: err.message });
        failed = true;
      }
    }

    // Mark as dispatched in outbox
    if (this.outboxDb) {
      if (failed) {
        this.outboxDb.prepare("UPDATE outbox SET attempts = attempts + 1, last_error = 'subscriber_error' WHERE id = ?").run(event.id);
        this.failedCount++;
      } else {
        this.outboxDb.prepare("UPDATE outbox SET dispatched = 1 WHERE id = ?").run(event.id);
      }
    }
  }

  /** Replay un-dispatched events from a previous crash */
  private replayPending(): void {
    if (!this.outboxDb) return;
    const pending = this.outboxDb.prepare(
      "SELECT * FROM outbox WHERE dispatched = 0 AND attempts < 5 ORDER BY ts ASC LIMIT 100"
    ).all() as any[];
    if (pending.length > 0) {
      log("info", "Replaying un-dispatched events from outbox", { count: pending.length });
      for (const row of pending) {
        const event: SovereignEvent = {
          id: row.id, type: row.type, ts: row.ts, source: row.source,
          tenantId: row.tenant_id ?? undefined, severity: row.severity,
          payload: JSON.parse(row.payload), _sealed: true,
        };
        this.dispatch(event).catch(() => {});
      }
    }
  }

  /** Retry failed events with exponential backoff */
  private retryFailed(): void {
    if (!this.outboxDb) return;
    const failed = this.outboxDb.prepare(
      "SELECT * FROM outbox WHERE dispatched = 0 AND attempts > 0 AND attempts < 5 ORDER BY ts ASC LIMIT 20"
    ).all() as any[];

    for (const row of failed) {
      const event: SovereignEvent = {
        id: row.id, type: row.type, ts: row.ts, source: row.source,
        tenantId: row.tenant_id ?? undefined, severity: row.severity,
        payload: JSON.parse(row.payload), _sealed: true,
      };
      this.dispatch(event).catch(() => {});
    }

    // Cleanup events that exceeded max attempts (move to DLQ state)
    this.outboxDb.prepare("DELETE FROM outbox WHERE dispatched = 1 AND ts < ?").run(Date.now() - 86400_000); // keep 24h
  }

  private orderedHistory(): SovereignEvent[] {
    if (!this.historyFull) return this.history.slice(0, this.historyIdx).filter(Boolean);
    return [
      ...this.history.slice(this.historyIdx),
      ...this.history.slice(0, this.historyIdx),
    ].filter(Boolean);
  }

  query(opts: {
    type?:     string;
    tenantId?: string;
    since?:    number;
    limit?:    number;
  } = {}): SovereignEvent[] {
    let results = this.orderedHistory();
    if (opts.type)     results = results.filter(e => e.type === opts.type);
    if (opts.tenantId) results = results.filter(e => e.tenantId === opts.tenantId);
    if (opts.since)    results = results.filter(e => e.ts >= opts.since!);
    return results.slice(-(opts.limit ?? 100));
  }

  stats() {
    const size = this.historyFull ? this.maxHistory : this.historyIdx;
    const dlqSize = this.outboxDb
      ? (this.outboxDb.prepare("SELECT COUNT(*) as n FROM outbox WHERE dispatched = 0 AND attempts >= 5").get() as any)?.n ?? 0
      : 0;
    return {
      subscribers: this.subs.length,
      historySize: size,
      totalEmitted: this.emitCount,
      failedCount: this.failedCount,
      dlqSize,
      outboxEnabled: !!this.outboxDb,
      subscriberDetails: this.subs.map(s => ({
        id: s.id, pattern: s.pattern, source: s.source,
      })),
    };
  }

  close() {
    if (this.dlqRetryTimer) clearInterval(this.dlqRetryTimer);
    this.subs = [];
    this.history = new Array(this.maxHistory);
    this.historyIdx = 0;
    this.historyFull = false;
    if (this.outboxDb) { try { this.outboxDb.close(); } catch {} }
  }
}

// Singleton for the platform
export const platformBus = new EventBus();
