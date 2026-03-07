//
// Sovereignly v3 -- Cron Scheduler
//
// Run functions on a schedule (like cron jobs, but serverless).
// Uses Bun's native timer APIs -- no external deps.
//
// Cron syntax: standard 5-field Unix cron
//   "*/5 * * * *"  -> every 5 minutes
//   "0 9 * * 1-5"  -> 9am Mon-Fri
//   "@hourly"      -> shorthand
//

import type { SovereignRuntime } from "../runtime/index.ts";

export interface ScheduledFunction {
  id: string;
  functionId: string;
  cron: string;
  enabled: boolean;
  lastRanAt?: Date;
  nextRunAt: Date;
  runCount: number;
  errorCount: number;
}

type CronField = number | "*" | { step: number } | number[];

interface ParsedCron {
  minute: CronField;
  hour: CronField;
  dom: CronField;  // day of month
  month: CronField;
  dow: CronField;  // day of week
}

// ??? Cron Parser ??????????????????????????????????????????????????????????

const SHORTHANDS: Record<string, string> = {
  "@yearly":   "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
  "@monthly":  "0 0 1 * *",
  "@weekly":   "0 0 * * 0",
  "@daily":    "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@hourly":   "0 * * * *",
  "@minutely": "* * * * *",
};

function parseField(field: string, min: number, max: number): CronField {
  if (field === "*") return "*";
  if (field.includes("/")) {
    const [, step] = field.split("/");
    return { step: parseInt(step) };
  }
  if (field.includes(",")) return field.split(",").map(Number);
  if (field.includes("-")) {
    const [start, end] = field.split("-").map(Number);
    return Array.from({ length: end - start + 1 }, (_, i) => start + i);
  }
  return parseInt(field);
}

function parseCron(expr: string): ParsedCron {
  const resolved = SHORTHANDS[expr] ?? expr;
  const parts = resolved.trim().split(/\s+/);
  if (parts.length !== 5) throw new Error(`Invalid cron: "${expr}"`);
  const [minute, hour, dom, month, dow] = parts;
  return {
    minute: parseField(minute, 0, 59),
    hour:   parseField(hour, 0, 23),
    dom:    parseField(dom, 1, 31),
    month:  parseField(month, 1, 12),
    dow:    parseField(dow, 0, 6),
  };
}

function matches(field: CronField, value: number): boolean {
  if (field === "*") return true;
  if (typeof field === "number") return field === value;
  if ("step" in (field as any)) return value % (field as any).step === 0;
  return (field as number[]).includes(value);
}

function shouldRun(cron: ParsedCron, date: Date): boolean {
  return matches(cron.minute, date.getMinutes()) &&
         matches(cron.hour, date.getHours()) &&
         matches(cron.dom, date.getDate()) &&
         matches(cron.month, date.getMonth() + 1) &&
         matches(cron.dow, date.getDay());
}

function nextOccurrence(expr: string, from = new Date()): Date {
  const cron = parseCron(expr);
  const d = new Date(from.getTime() + 60_000); // start from next minute
  d.setSeconds(0, 0);
  for (let i = 0; i < 525_600; i++) { // search up to 1 year ahead
    if (shouldRun(cron, d)) return d;
    d.setMinutes(d.getMinutes() + 1);
  }
  throw new Error(`No occurrence found for: ${expr}`);
}

// ??? Scheduler ????????????????????????????????????????????????????????????

export class SovereignScheduler {
  private schedules = new Map<string, ScheduledFunction>();
  private timer: Timer;

  constructor(private readonly runtime: SovereignRuntime) {
    // Check every minute at the top of the minute
    const msToNextMinute = (60 - new Date().getSeconds()) * 1000;
    setTimeout(() => {
      this.tick();
      this.timer = setInterval(() => this.tick(), 60_000);
    }, msToNextMinute);

    console.log("[Scheduler] Ready");
  }

  schedule(fnId: string, cron: string, id?: string): ScheduledFunction {
    // Validate cron expression
    parseCron(cron);

    const schedId = id ?? `${fnId}-${cron.replace(/\s+/g, "_")}`;
    const entry: ScheduledFunction = {
      id: schedId,
      functionId: fnId,
      cron,
      enabled: true,
      nextRunAt: nextOccurrence(cron),
      runCount: 0,
      errorCount: 0,
    };
    this.schedules.set(schedId, entry);
    console.log(`[Scheduler] Scheduled ${fnId} @ "${cron}" -> next: ${entry.nextRunAt.toISOString()}`);
    return entry;
  }

  unschedule(id: string): boolean {
    return this.schedules.delete(id);
  }

  list(): ScheduledFunction[] {
    return [...this.schedules.values()];
  }

  private async tick() {
    const now = new Date();
    for (const [, s] of this.schedules) {
      if (!s.enabled) continue;
      if (now < s.nextRunAt) continue;

      // Fire and forget
      this.runtime.invoke(s.functionId, {
        url: `sovereign://scheduler/${s.id}`,
        method: "GET",
        headers: {
          "x-sovereign-trigger": "cron",
          "x-cron-id": s.id,
          "x-cron-expr": s.cron,
        },
        body: null,
      }).then((res) => {
        s.runCount++;
        s.lastRanAt = new Date();
        s.nextRunAt = nextOccurrence(s.cron);
        if (res.status >= 500) s.errorCount++;
        console.log(`[Scheduler] ${s.id} -> ${res.status} (${res.ms.toFixed(1)}ms)`);
      }).catch((err) => {
        s.errorCount++;
        s.nextRunAt = nextOccurrence(s.cron);
        console.error(`[Scheduler] ${s.id} failed:`, err.message);
      });
    }
  }

  stop() {
    clearInterval(this.timer);
  }
}
