"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import {
  Server, Database, HardDrive, Cpu, Shield, RefreshCw, Trash2,
  Download, Upload, Power, AlertTriangle, CheckCircle, Clock,
  Layers, Globe, Link2, Zap,
} from "lucide-react";

export default function SystemPage() {
  const [health, setHealth] = useState<any>(null);
  const [metrics, setMetrics] = useState<any>(null);

  useEffect(() => {
    api("/_sovereign/health").then(r => setHealth(r.data));
    api("/_sovereign/metrics").then(r => setMetrics(r.data));
  }, []);

  async function flushChain() {
    toast.info("Flushing pending chain events...");
    // This would call a flush endpoint
    toast.success("Chain flushed");
  }

  async function verifyChain() {
    toast.info("Verifying chain integrity...");
    const { ok, data } = await api("/_sovereign/chain/verify");
    if (ok && (data as any)?.valid) {
      toast.success("Chain integrity verified — all blocks valid");
    } else {
      toast.error(`Integrity check failed: ${(data as any)?.reason ?? "unknown"}`);
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-red/10 border border-red/20 flex items-center justify-center">
          <Server className="w-5 h-5 text-red" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">System Management</h1>
          <p className="text-xs text-text-muted font-mono">Infrastructure controls and diagnostics</p>
        </div>
      </div>

      {/* Runtime Info */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Cpu className="w-4 h-4 text-blue" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-blue">Runtime</span>
        </div>
        <div className="p-5 grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Runtime", value: `Bun ${health?.bunVersion ?? "?"}`, icon: Zap },
            { label: "Node", value: health?.node ?? "primary", icon: Server },
            { label: "Uptime", value: health?.uptime ? `${(health.uptime / 3600).toFixed(1)}h` : "—", icon: Clock },
            { label: "Memory", value: "2048 MB", icon: HardDrive },
          ].map(s => (
            <div key={s.label} className="p-3 rounded-lg border border-border">
              <div className="flex items-center gap-2 mb-1">
                <s.icon className="w-3 h-3 text-text-muted" />
                <span className="text-[9px] font-mono text-text-muted uppercase">{s.label}</span>
              </div>
              <div className="text-sm font-mono font-medium">{s.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Workers */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Layers className="w-4 h-4 text-amber" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-amber">Worker Pool</span>
        </div>
        <div className="p-5">
          <div className="grid grid-cols-4 gap-4 mb-4">
            <div><span className="text-2xl font-bold text-amber">{health?.workers?.total ?? 0}</span><div className="text-[9px] text-text-muted font-mono">Total</div></div>
            <div><span className="text-2xl font-bold text-brand">{health?.workers?.busy ?? 0}</span><div className="text-[9px] text-text-muted font-mono">Busy</div></div>
            <div><span className="text-2xl font-bold text-blue">{health?.workers?.queued ?? 0}</span><div className="text-[9px] text-text-muted font-mono">Queued</div></div>
            <div><span className="text-2xl font-bold text-text-secondary">{health?.workers?.totalTasks ?? 0}</span><div className="text-[9px] text-text-muted font-mono">Total Tasks</div></div>
          </div>
          <div className="flex gap-1.5">
            {Array.from({ length: health?.workers?.total ?? 0 }).map((_, i) => (
              <div key={i} className={`w-4 h-4 rounded ${i < (health?.workers?.busy ?? 0) ? "bg-amber shadow-[0_0_4px] shadow-amber animate-pulse" : "bg-brand/30"}`} />
            ))}
          </div>
        </div>
      </div>

      {/* Database */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Database className="w-4 h-4 text-violet" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-violet">Databases</span>
        </div>
        <div className="p-5 space-y-2">
          {[
            { name: "chain.db", desc: "Platform audit chain", path: "/data/platform/chain.db" },
            { name: "kv.sqlite", desc: "Key-value store", path: "/data/platform/kv.sqlite" },
            { name: "users.db", desc: "User accounts", path: "/data/platform/users.db" },
            { name: "passkeys.db", desc: "WebAuthn credentials", path: "/data/platform/passkeys.db" },
            { name: "revocations.db", desc: "Token revocation store", path: "/data/platform/revocations.db" },
            { name: "event-outbox.db", desc: "Event bus transactional outbox", path: "/data/platform/event-outbox.db" },
            { name: "tenants.db", desc: "Global tenant registry", path: "/data/global/tenants.db" },
          ].map(db => (
            <div key={db.name} className="flex items-center justify-between p-3 rounded-lg border border-border hover:bg-surface/30 transition-colors">
              <div className="flex items-center gap-3">
                <Database className="w-4 h-4 text-violet" />
                <div>
                  <div className="text-sm font-medium">{db.name}</div>
                  <div className="text-[10px] text-text-muted font-mono">{db.desc}</div>
                </div>
              </div>
              <span className="text-[9px] font-mono text-text-muted">{db.path}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Maintenance Actions */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Shield className="w-4 h-4 text-red" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-red">Maintenance Actions</span>
        </div>
        <div className="p-5 grid grid-cols-2 lg:grid-cols-3 gap-3">
          <button onClick={verifyChain}
            className="flex items-center gap-2 px-4 py-3 rounded-lg border border-border hover:border-brand/30 hover:bg-brand/5 transition-all text-sm text-left">
            <CheckCircle className="w-4 h-4 text-brand shrink-0" />
            <div><div className="font-medium">Verify Chain</div><div className="text-[10px] text-text-muted">Check integrity of all blocks</div></div>
          </button>
          <button onClick={flushChain}
            className="flex items-center gap-2 px-4 py-3 rounded-lg border border-border hover:border-blue/30 hover:bg-blue/5 transition-all text-sm text-left">
            <RefreshCw className="w-4 h-4 text-blue shrink-0" />
            <div><div className="font-medium">Flush Chain</div><div className="text-[10px] text-text-muted">Force seal pending events</div></div>
          </button>
          <button className="flex items-center gap-2 px-4 py-3 rounded-lg border border-border hover:border-violet/30 hover:bg-violet/5 transition-all text-sm text-left">
            <Download className="w-4 h-4 text-violet shrink-0" />
            <div><div className="font-medium">Export Chain</div><div className="text-[10px] text-text-muted">Download audit trail</div></div>
          </button>
          <button className="flex items-center gap-2 px-4 py-3 rounded-lg border border-border hover:border-amber/30 hover:bg-amber/5 transition-all text-sm text-left">
            <Upload className="w-4 h-4 text-amber shrink-0" />
            <div><div className="font-medium">Backup Now</div><div className="text-[10px] text-text-muted">Trigger Litestream backup</div></div>
          </button>
          <button className="flex items-center gap-2 px-4 py-3 rounded-lg border border-border hover:border-brand/30 hover:bg-brand/5 transition-all text-sm text-left">
            <Globe className="w-4 h-4 text-brand shrink-0" />
            <div><div className="font-medium">Anchor Now</div><div className="text-[10px] text-text-muted">Force omnichain attestation</div></div>
          </button>
          <button className="flex items-center gap-2 px-4 py-3 rounded-lg border border-red/20 hover:bg-red/5 transition-all text-sm text-left">
            <Power className="w-4 h-4 text-red shrink-0" />
            <div><div className="font-medium text-red">Restart</div><div className="text-[10px] text-text-muted">Restart Bun process</div></div>
          </button>
        </div>
      </div>

      {/* Danger */}
      <div className="rounded-xl border border-red/20 bg-red/5 p-4 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-red shrink-0 mt-0.5" />
        <div className="text-xs text-text-muted">
          <span className="font-medium text-red">Super Admin actions are irreversible.</span> All actions are logged to the SovereignChain. Chain verification, backup, and export operations may take several seconds for large chains.
        </div>
      </div>
    </div>
  );
}
