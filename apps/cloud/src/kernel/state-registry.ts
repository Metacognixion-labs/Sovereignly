// Sovereignly State Registry -- BSL License
//
// Global state of all tenants, machines, workflows, agents.
// Event-sourced: subscribes to EventBus, materializes current state.
// The single source of truth for the kernel's decision engines.

import type { EventBus, SovereignEvent } from "../../../oss/src/events/bus.ts";

export type EntityType = "tenant" | "machine" | "workflow" | "agent";
export type EntityStatus = "active" | "degraded" | "failed" | "stopped" | "pending";

export interface StateEntity {
  id:         string;
  type:       EntityType;
  status:     EntityStatus;
  region?:    string;
  tenantId?:  string;
  metadata:   Record<string, unknown>;
  createdAt:  number;
  updatedAt:  number;
  events:     number;   // count of events processed for this entity
}

export class StateRegistry {
  private entities = new Map<string, StateEntity>();
  private eventCount = 0;
  private subIds: string[] = [];

  constructor(private bus: EventBus) {
    // Subscribe to entity lifecycle events
    this.subIds.push(bus.on("TENANT_CREATED",   (e) => this.onEntity(e, "tenant", "active"), "state-registry"));
    this.subIds.push(bus.on("TENANT_DELETED",   (e) => this.onEntity(e, "tenant", "stopped"), "state-registry"));
    this.subIds.push(bus.on("TENANT_SUSPENDED", (e) => this.onEntity(e, "tenant", "stopped"), "state-registry"));
    this.subIds.push(bus.on("MACHINE_STARTED",  (e) => this.onEntity(e, "machine", "active"), "state-registry"));
    this.subIds.push(bus.on("MACHINE_FAILED",   (e) => this.onEntity(e, "machine", "failed"), "state-registry"));
    this.subIds.push(bus.on("MACHINE_STOPPED",  (e) => this.onEntity(e, "machine", "stopped"), "state-registry"));
    this.subIds.push(bus.on("WORKFLOW_STARTED",  (e) => this.onEntity(e, "workflow", "active"), "state-registry"));
    this.subIds.push(bus.on("WORKFLOW_COMPLETED",(e) => this.onEntity(e, "workflow", "stopped"), "state-registry"));
    this.subIds.push(bus.on("WORKFLOW_FAILED",   (e) => this.onEntity(e, "workflow", "failed"), "state-registry"));
    this.subIds.push(bus.on("AGENT_REGISTERED",  (e) => this.onEntity(e, "agent", "active"), "state-registry"));
    this.subIds.push(bus.on("AGENT_FAILED",      (e) => this.onEntity(e, "agent", "failed"), "state-registry"));
    this.subIds.push(bus.on("ANOMALY",           (e) => this.onAnomaly(e), "state-registry"));
  }

  private onEntity(event: SovereignEvent, type: EntityType, status: EntityStatus) {
    this.eventCount++;
    const id = (event.payload.tenantId ?? event.payload.machineId ?? event.payload.workflowId ?? event.payload.agentId ?? event.id) as string;

    const existing = this.entities.get(id);
    if (existing) {
      existing.status = status;
      existing.updatedAt = event.ts;
      existing.events++;
      Object.assign(existing.metadata, event.payload);
    } else {
      this.entities.set(id, {
        id, type, status,
        region:    event.payload.region as string | undefined,
        tenantId:  event.tenantId,
        metadata:  { ...event.payload },
        createdAt: event.ts,
        updatedAt: event.ts,
        events:    1,
      });
    }
  }

  private onAnomaly(event: SovereignEvent) {
    this.eventCount++;
    // Mark affected entity as degraded if identifiable
    const tenantId = event.tenantId ?? event.payload.tenantId as string;
    if (tenantId) {
      const entity = this.entities.get(tenantId);
      if (entity && entity.status === "active") {
        entity.status = "degraded";
        entity.updatedAt = event.ts;
        entity.events++;
      }
    }
  }

  // Query state
  get(id: string): StateEntity | undefined { return this.entities.get(id); }

  list(opts?: { type?: EntityType; status?: EntityStatus; region?: string }): StateEntity[] {
    let results = Array.from(this.entities.values());
    if (opts?.type)   results = results.filter(e => e.type === opts.type);
    if (opts?.status) results = results.filter(e => e.status === opts.status);
    if (opts?.region) results = results.filter(e => e.region === opts.region);
    return results.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  count(type?: EntityType): number {
    if (!type) return this.entities.size;
    return Array.from(this.entities.values()).filter(e => e.type === type).length;
  }

  stats() {
    const all = Array.from(this.entities.values());
    return {
      total:        all.length,
      byType:       { tenant: this.count("tenant"), machine: this.count("machine"), workflow: this.count("workflow"), agent: this.count("agent") },
      byStatus:     { active: all.filter(e => e.status === "active").length, degraded: all.filter(e => e.status === "degraded").length, failed: all.filter(e => e.status === "failed").length, stopped: all.filter(e => e.status === "stopped").length },
      eventsProcessed: this.eventCount,
    };
  }

  close() { for (const id of this.subIds) this.bus.off(id); }
}
