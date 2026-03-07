// Sovereignly Control Plane — Node Registry
// BSL License — MetaCognixion
//
// Central registry for all nodes in the Sovereignly network.
// Unlike the cluster-level NodeRegistry, this is the authoritative
// source of truth for the entire network. Persists node state to SQLite.

import { Database } from "bun:sqlite";
import { join } from "node:path";

export type NodeRole = "control" | "cluster" | "edge";
export type NodeStatus = "healthy" | "degraded" | "offline";

export interface SovereignNode {
  nodeId:        string;
  region:        string;
  role:          NodeRole;
  clusterId:     string;
  version:       string;
  capabilities:  string[];
  status:        NodeStatus;
  load:          number;
  uptime:        number;
  lastHeartbeat: number;
  registeredAt:  number;
}

export interface HeartbeatPayload {
  nodeId:        string;
  region:        string;
  role?:         NodeRole;
  clusterId?:    string;
  load:          number;
  uptime:        number;
  version?:      string;
  capabilities?: string[];
}

const DEGRADED_THRESHOLD = 90_000;
const OFFLINE_THRESHOLD  = 180_000;

export class ControlPlaneNodeRegistry {
  private db: Database;
  private sweepInterval: ReturnType<typeof setInterval>;

  constructor(dataDir: string) {
    this.db = new Database(join(dataDir, "nodes.db"));
    this.initSchema();
    this.sweepInterval = setInterval(() => this.sweep(), 30_000);
  }

  private initSchema() {
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run(`
      CREATE TABLE IF NOT EXISTS nodes (
        node_id         TEXT PRIMARY KEY,
        region          TEXT NOT NULL,
        role            TEXT NOT NULL DEFAULT 'cluster',
        cluster_id      TEXT NOT NULL DEFAULT 'default',
        version         TEXT NOT NULL DEFAULT 'unknown',
        capabilities    TEXT NOT NULL DEFAULT '[]',
        status          TEXT NOT NULL DEFAULT 'healthy',
        load            REAL NOT NULL DEFAULT 0,
        uptime          INTEGER NOT NULL DEFAULT 0,
        last_heartbeat  INTEGER NOT NULL,
        registered_at   INTEGER NOT NULL
      )
    `);
    this.db.run("CREATE INDEX IF NOT EXISTS idx_nodes_region ON nodes(region)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_nodes_role ON nodes(role)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_nodes_cluster ON nodes(cluster_id)");
  }

  heartbeat(payload: HeartbeatPayload): SovereignNode {
    const now = Date.now();
    const existing = this.get(payload.nodeId);

    if (existing) {
      this.db.prepare(`
        UPDATE nodes SET
          load = ?, uptime = ?, last_heartbeat = ?, status = 'healthy',
          version = COALESCE(?, version),
          capabilities = COALESCE(?, capabilities),
          region = COALESCE(?, region)
        WHERE node_id = ?
      `).run(
        payload.load, payload.uptime, now,
        payload.version ?? null,
        payload.capabilities ? JSON.stringify(payload.capabilities) : null,
        payload.region ?? null,
        payload.nodeId
      );
    } else {
      this.db.prepare(`
        INSERT INTO nodes (node_id, region, role, cluster_id, version, capabilities, status, load, uptime, last_heartbeat, registered_at)
        VALUES (?, ?, ?, ?, ?, ?, 'healthy', ?, ?, ?, ?)
      `).run(
        payload.nodeId,
        payload.region,
        payload.role ?? "cluster",
        payload.clusterId ?? "default",
        payload.version ?? "unknown",
        JSON.stringify(payload.capabilities ?? []),
        payload.load, payload.uptime, now, now
      );
      console.log(`[ControlPlane] Node registered: ${payload.nodeId} (${payload.role ?? "cluster"}@${payload.region})`);
    }

    return this.get(payload.nodeId)!;
  }

  deregister(nodeId: string): boolean {
    const result = this.db.prepare("DELETE FROM nodes WHERE node_id = ?").run(nodeId);
    return result.changes > 0;
  }

  private sweep() {
    const now = Date.now();
    this.db.prepare(
      "UPDATE nodes SET status = 'degraded' WHERE status = 'healthy' AND ? - last_heartbeat > ?"
    ).run(now, DEGRADED_THRESHOLD);
    this.db.prepare(
      "UPDATE nodes SET status = 'offline' WHERE status != 'offline' AND ? - last_heartbeat > ?"
    ).run(now, OFFLINE_THRESHOLD);
  }

  get(nodeId: string): SovereignNode | null {
    const row = this.db.prepare("SELECT * FROM nodes WHERE node_id = ?").get(nodeId) as any;
    return row ? this.rowToNode(row) : null;
  }

  list(opts?: { role?: NodeRole; region?: string; status?: NodeStatus; clusterId?: string }): SovereignNode[] {
    const clauses: string[] = [];
    const params: any[] = [];
    if (opts?.role)      { clauses.push("role = ?");       params.push(opts.role); }
    if (opts?.region)    { clauses.push("region = ?");     params.push(opts.region); }
    if (opts?.status)    { clauses.push("status = ?");     params.push(opts.status); }
    if (opts?.clusterId) { clauses.push("cluster_id = ?"); params.push(opts.clusterId); }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    return (this.db.prepare(`SELECT * FROM nodes ${where} ORDER BY last_heartbeat DESC`).all(...params) as any[])
      .map(r => this.rowToNode(r));
  }

  regions(): string[] {
    return (this.db.prepare("SELECT DISTINCT region FROM nodes WHERE status != 'offline'").all() as any[])
      .map(r => r.region);
  }

  clusters(): string[] {
    return (this.db.prepare("SELECT DISTINCT cluster_id FROM nodes WHERE status != 'offline'").all() as any[])
      .map(r => r.cluster_id);
  }

  stats() {
    const all = this.list();
    const byRole: Record<string, number> = { control: 0, cluster: 0, edge: 0 };
    const byStatus: Record<string, number> = { healthy: 0, degraded: 0, offline: 0 };
    let totalLoad = 0;
    for (const n of all) {
      byRole[n.role] = (byRole[n.role] ?? 0) + 1;
      byStatus[n.status] = (byStatus[n.status] ?? 0) + 1;
      totalLoad += n.load;
    }
    return {
      totalNodes: all.length,
      byRole, byStatus,
      regions: this.regions(),
      clusters: this.clusters(),
      avgLoad: all.length > 0 ? Number((totalLoad / all.length).toFixed(3)) : 0,
    };
  }

  private rowToNode(row: any): SovereignNode {
    return {
      nodeId:        row.node_id,
      region:        row.region,
      role:          row.role,
      clusterId:     row.cluster_id,
      version:       row.version,
      capabilities:  JSON.parse(row.capabilities),
      status:        row.status,
      load:          row.load,
      uptime:        row.uptime,
      lastHeartbeat: row.last_heartbeat,
      registeredAt:  row.registered_at,
    };
  }

  close() {
    clearInterval(this.sweepInterval);
    this.db.close();
  }
}
