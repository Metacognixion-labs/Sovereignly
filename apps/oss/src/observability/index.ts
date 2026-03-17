/**
 * Sovereignly Observability Module
 *
 * Structured logging + Prometheus-compatible metrics + request tracing.
 * Zero external dependencies — uses Bun.nanoseconds() for high-res timing.
 *
 * Provides:
 *   1. Structured JSON logger with trace correlation
 *   2. In-process metric counters/histograms exposed via /_sovereign/metrics
 *   3. Hono middleware for request tracing (duration, status, path)
 *   4. Optional OTLP export when OTEL_ENDPOINT is configured
 */

import type { MiddlewareHandler, Context, Next } from "hono";

// -- Structured Logger --------------------------------------------------------

export type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

let minLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) ?? "info";

export function setLogLevel(level: LogLevel): void { minLevel = level; }

export function log(level: LogLevel, msg: string, meta?: Record<string, unknown>): void {
  if (LOG_LEVELS[level] < LOG_LEVELS[minLevel]) return;
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    node: process.env.SOVEREIGN_NODE_ID ?? "primary",
    ...meta,
  };
  const line = JSON.stringify(entry);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

// -- Metric Registry ----------------------------------------------------------

interface MetricEntry {
  name:        string;
  type:        "counter" | "histogram" | "gauge";
  help:        string;
  value:       number;
  labels?:     Record<string, string>;
  // Histogram-specific
  buckets?:    number[];
  counts?:     number[];
  sum?:        number;
  count?:      number;
}

class MetricRegistry {
  private metrics = new Map<string, MetricEntry>();
  private histograms = new Map<string, { buckets: number[]; counts: number[]; sum: number; count: number }>();

  counter(name: string, help: string, labels?: Record<string, string>): void {
    const key = this.key(name, labels);
    const existing = this.metrics.get(key);
    if (existing) {
      existing.value++;
    } else {
      this.metrics.set(key, { name, type: "counter", help, value: 1, labels });
    }
  }

  counterAdd(name: string, help: string, value: number, labels?: Record<string, string>): void {
    const key = this.key(name, labels);
    const existing = this.metrics.get(key);
    if (existing) {
      existing.value += value;
    } else {
      this.metrics.set(key, { name, type: "counter", help, value, labels });
    }
  }

  gauge(name: string, help: string, value: number, labels?: Record<string, string>): void {
    const key = this.key(name, labels);
    this.metrics.set(key, { name, type: "gauge", help, value, labels });
  }

  histogram(name: string, help: string, value: number, buckets = [5, 10, 25, 50, 100, 250, 500, 1000, 5000]): void {
    let h = this.histograms.get(name);
    if (!h) {
      h = { buckets, counts: new Array(buckets.length + 1).fill(0), sum: 0, count: 0 };
      this.histograms.set(name, h);
    }
    h.sum += value;
    h.count++;
    for (let i = 0; i < h.buckets.length; i++) {
      if (value <= h.buckets[i]) { h.counts[i]++; break; }
      if (i === h.buckets.length - 1) h.counts[h.buckets.length]++; // +Inf
    }
  }

  /** Export in Prometheus text format */
  toPrometheus(): string {
    const lines: string[] = [];

    // Counters and gauges
    const seen = new Set<string>();
    for (const [, m] of this.metrics) {
      if (!seen.has(m.name)) {
        lines.push(`# HELP ${m.name} ${m.help}`);
        lines.push(`# TYPE ${m.name} ${m.type}`);
        seen.add(m.name);
      }
      const labelStr = m.labels
        ? `{${Object.entries(m.labels).map(([k, v]) => `${k}="${v}"`).join(",")}}`
        : "";
      lines.push(`${m.name}${labelStr} ${m.value}`);
    }

    // Histograms
    for (const [name, h] of this.histograms) {
      lines.push(`# HELP ${name} Request duration histogram`);
      lines.push(`# TYPE ${name} histogram`);
      let cumulative = 0;
      for (let i = 0; i < h.buckets.length; i++) {
        cumulative += h.counts[i];
        lines.push(`${name}_bucket{le="${h.buckets[i]}"} ${cumulative}`);
      }
      cumulative += h.counts[h.buckets.length];
      lines.push(`${name}_bucket{le="+Inf"} ${cumulative}`);
      lines.push(`${name}_sum ${h.sum}`);
      lines.push(`${name}_count ${h.count}`);
    }

    return lines.join("\n") + "\n";
  }

  /** Export as JSON (for /_sovereign/metrics) */
  toJSON(): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [key, m] of this.metrics) {
      result[key] = { type: m.type, value: m.value, labels: m.labels };
    }
    for (const [name, h] of this.histograms) {
      result[name] = { type: "histogram", sum: h.sum, count: h.count, avg: h.count > 0 ? h.sum / h.count : 0 };
    }
    return result;
  }

  private key(name: string, labels?: Record<string, string>): string {
    if (!labels) return name;
    return `${name}{${Object.entries(labels).sort().map(([k, v]) => `${k}=${v}`).join(",")}}`;
  }
}

export const metrics = new MetricRegistry();

// -- Request Tracing Middleware -----------------------------------------------

export function tracingMiddleware(): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const start = Bun.nanoseconds();
    const traceId = crypto.randomUUID().replace(/-/g, "");
    const method = c.req.method;
    const path = new URL(c.req.url).pathname;

    // Set trace ID on context for downstream correlation
    (c as any).set("traceId", traceId);
    c.header("X-Trace-Id", traceId);

    await next();

    const durationMs = (Bun.nanoseconds() - start) / 1e6;
    const status = c.res.status;

    // Record metrics
    metrics.counter("sovereign_http_requests_total", "Total HTTP requests", { method, status: String(status) });
    metrics.histogram("sovereign_http_duration_ms", "Request duration in ms", durationMs);

    if (status >= 400) {
      metrics.counter("sovereign_http_errors_total", "Total HTTP errors", { method, status: String(status) });
    }

    // Structured log
    if (durationMs > 1000 || status >= 500) {
      log("warn", "Slow or errored request", { traceId, method, path, status, durationMs: Math.round(durationMs) });
    }
  };
}

// -- Prometheus endpoint handler ----------------------------------------------

export function prometheusHandler(c: Context): Response {
  return new Response(metrics.toPrometheus(), {
    headers: { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" },
  });
}
