// Sovereignly Cognitive Infrastructure Model -- BSL License
//
// ML-powered decision engine. Learns from historical events.
// Predicts failures, optimizes placement, auto-scales.
// Upgrades the rule-based DecisionEngine from Phase 4.
//
// Phase 6 implementation: statistical models (no external ML deps).
// Tracks patterns, computes moving averages, detects anomalies via z-score.

import type { EventBus, SovereignEvent } from "../../../oss/src/events/bus.ts";
import type { StateRegistry } from "./state-registry.ts";

interface TimeSeries {
  values:    number[];
  timestamps: number[];
  maxLen:    number;
}

interface Prediction {
  metric:      string;
  current:     number;
  predicted:   number;
  confidence:  number;
  direction:   "up" | "down" | "stable";
  anomaly:     boolean;
  zScore:      number;
}

export class CognitiveModel {
  private series = new Map<string, TimeSeries>();
  private patterns = new Map<string, number>();  // event type -> frequency per hour
  private subId: string;
  private sweepInterval: ReturnType<typeof setInterval>;

  constructor(
    private bus:   EventBus,
    private state: StateRegistry,
  ) {
    // Ingest all events for learning
    this.subId = bus.on("*", (e) => this.learn(e), "cognitive-model");

    // Periodic analysis every 2 minutes
    this.sweepInterval = setInterval(() => this.analyze(), 120_000);
  }

  private learn(event: SovereignEvent) {
    // Track event frequency by type
    const count = this.patterns.get(event.type) ?? 0;
    this.patterns.set(event.type, count + 1);

    // Track numeric signals as time series
    if (event.type === "ANOMALY" || event.type === "MACHINE_FAILED" || event.type === "AGENT_FAILED") {
      this.addSample("failure_rate", 1);
    }
    if (event.type === "WORKFLOW_COMPLETED") {
      const duration = event.payload.durationMs as number;
      if (duration) this.addSample("workflow_duration", duration);
    }
    if (event.type === "AUTH_FAILURE") {
      this.addSample("auth_failure_rate", 1);
    }
  }

  private addSample(metric: string, value: number) {
    let ts = this.series.get(metric);
    if (!ts) {
      ts = { values: [], timestamps: [], maxLen: 500 };
      this.series.set(metric, ts);
    }
    ts.values.push(value);
    ts.timestamps.push(Date.now());
    if (ts.values.length > ts.maxLen) {
      ts.values = ts.values.slice(-ts.maxLen);
      ts.timestamps = ts.timestamps.slice(-ts.maxLen);
    }
  }

  // Statistical analysis
  private analyze() {
    // Emit a summary event with current model state
    const predictions = this.predict();
    const anomalies = predictions.filter(p => p.anomaly);

    if (anomalies.length > 0) {
      void this.bus.emit("CONFIG_CHANGE", {
        event: "cognitive_anomaly_detected",
        anomalies: anomalies.map(a => ({ metric: a.metric, zScore: a.zScore, current: a.current })),
      }, { severity: "MEDIUM", source: "cognitive-model" });
    }
  }

  // Predict current state of each metric
  predict(): Prediction[] {
    const predictions: Prediction[] = [];

    for (const [metric, ts] of this.series) {
      if (ts.values.length < 5) continue;

      const mean = ts.values.reduce((a, b) => a + b, 0) / ts.values.length;
      const variance = ts.values.reduce((a, v) => a + (v - mean) ** 2, 0) / ts.values.length;
      const stddev = Math.sqrt(variance);

      const recent = ts.values.slice(-5);
      const recentMean = recent.reduce((a, b) => a + b, 0) / recent.length;

      const zScore = stddev > 0 ? (recentMean - mean) / stddev : 0;
      const anomaly = Math.abs(zScore) > 2;

      // Simple linear trend
      const direction = recentMean > mean * 1.1 ? "up" : recentMean < mean * 0.9 ? "down" : "stable";

      // Confidence based on sample size
      const confidence = Math.min(1, ts.values.length / 100);

      predictions.push({
        metric,
        current:    recentMean,
        predicted:  mean,  // predict regression to mean
        confidence,
        direction,
        anomaly,
        zScore:     Math.round(zScore * 100) / 100,
      });
    }

    return predictions;
  }

  // Event frequency analysis
  eventFrequency(): Record<string, number> {
    return Object.fromEntries(this.patterns);
  }

  // Risk score for an entity (0-100, higher = more risk)
  riskScore(entityId: string): { score: number; factors: string[] } {
    const entity = this.state.get(entityId);
    if (!entity) return { score: 0, factors: ["entity not found"] };

    let score = 0;
    const factors: string[] = [];

    if (entity.status === "degraded") { score += 30; factors.push("degraded status"); }
    if (entity.status === "failed")   { score += 60; factors.push("failed status"); }
    if (entity.events > 50)           { score += 10; factors.push("high event count"); }

    // Check failure time series
    const failTs = this.series.get("failure_rate");
    if (failTs && failTs.values.length > 10) {
      const recentFails = failTs.values.slice(-10).reduce((a, b) => a + b, 0);
      if (recentFails > 5) { score += 20; factors.push("recent failure spike"); }
    }

    return { score: Math.min(100, score), factors };
  }

  stats() {
    return {
      metrics:        this.series.size,
      eventPatterns:  this.patterns.size,
      totalSamples:   Array.from(this.series.values()).reduce((s, ts) => s + ts.values.length, 0),
      predictions:    this.predict().length,
      anomaliesNow:   this.predict().filter(p => p.anomaly).length,
    };
  }

  close() {
    this.bus.off(this.subId);
    clearInterval(this.sweepInterval);
  }
}
