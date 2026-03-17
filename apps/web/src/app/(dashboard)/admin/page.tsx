"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import Link from "next/link";
import {
  Shield, Users, Building2, Blocks, Link2, Cpu, Database, Globe,
  Activity, ShieldCheck, Atom, Zap, HardDrive, Clock, AlertTriangle,
  TrendingUp, Server, Crown, BarChart3, Layers,
} from "lucide-react";

interface PlatformStats {
  health: any;
  chain: any;
  compliance: any;
  quantum: any;
  metrics: any;
}

function StatCard({ label, value, icon: Icon, color, sub }: {
  label: string; value: string | number; icon: typeof Activity; color: string; sub?: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-panel p-4 hover:border-border-bright transition-colors">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[9px] font-mono uppercase tracking-widest text-text-muted">{label}</span>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div className="text-2xl font-bold" style={{ color }}>{typeof value === "number" ? fmt(value) : value}</div>
      {sub && <div className="text-[10px] text-text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

export default function SuperAdminPage() {
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api("/_sovereign/health"),
      api("/_sovereign/chain/stats"),
      api("/_sovereign/compliance/live"),
      api("/_sovereign/quantum/algorithms"),
      api("/_sovereign/metrics"),
    ]).then(([health, chain, compliance, quantum, metrics]) => {
      setStats({
        health: health.data,
        chain: chain.data,
        compliance: compliance.data,
        quantum: quantum.data,
        metrics: metrics.data,
      });
      setLoading(false);
    });
  }, []);

  const h = stats?.health;
  const c = stats?.chain;
  const comp = stats?.compliance;
  const m = stats?.metrics;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red/10 border border-red/20 flex items-center justify-center">
            <Crown className="w-5 h-5 text-red" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Super Admin</h1>
            <p className="text-xs text-text-muted font-mono">MetaCognixion Platform Control</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono bg-red/10 text-red border border-red/20">
            <Crown className="w-3 h-3" /> GOD MODE
          </span>
          <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono ${
            h?.ok ? "bg-brand/10 text-brand border border-brand/20" : "bg-red/10 text-red border border-red/20"
          }`}>
            {h?.ok ? "HEALTHY" : "DEGRADED"}
          </span>
        </div>
      </div>

      {/* Platform Overview Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard label="Status" value={h?.ok ? "HEALTHY" : "DOWN"} icon={Activity} color={h?.ok ? "#4CAF50" : "#EF5350"} sub={`v${h?.version ?? "?"}`} />
        <StatCard label="Uptime" value={h?.uptime ? `${(h.uptime / 3600).toFixed(1)}h` : "—"} icon={Clock} color="#42A5F5" sub={`Bun ${h?.bunVersion ?? "?"}`} />
        <StatCard label="Chain Blocks" value={c?.blocks ?? 0} icon={Link2} color="#42A5F5" sub={`${c?.events ?? 0} events`} />
        <StatCard label="Workers" value={h?.workers?.total ?? 0} icon={Cpu} color="#FFA726" sub={`${h?.workers?.busy ?? 0} busy`} />
        <StatCard label="Compliance" value={comp?.score ? `${comp.score}/100` : "—"} icon={ShieldCheck} color="#4CAF50" sub={`${comp?.summary?.pass ?? 0} pass`} />
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Infrastructure Panel */}
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Server className="w-4 h-4 text-blue" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-blue">Infrastructure</span>
          </div>
          <div className="p-5 space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-text-muted">Runtime</span><span className="font-mono">{h?.runtime} {h?.bunVersion}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Node ID</span><span className="font-mono">{h?.node}</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Region</span><span className="font-mono">iad (US East)</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Machine</span><span className="font-mono">shared-cpu-1x / 2GB</span></div>
            <div className="flex justify-between"><span className="text-text-muted">Volume</span><span className="font-mono">1GB encrypted SSD</span></div>
            <div className="flex justify-between">
              <span className="text-text-muted">Subsystems</span>
              <div className="flex gap-1.5">
                {Object.entries(h?.subsystems ?? {}).map(([k, v]) => (
                  <span key={k} className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                    v === "ok" || v === "configured" ? "bg-brand/10 text-brand border-brand/20" : "bg-red/10 text-red border-red/20"
                  }`}>{k}</span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Security & PQC Panel */}
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Shield className="w-4 h-4" style={{ color: "#AB47BC" }} />
            <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "#AB47BC" }}>Security & Post-Quantum</span>
          </div>
          <div className="p-5 space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-text-muted">PQC Status</span>
              <span className={`font-mono ${h?.pqc?.enabled ? "text-brand" : "text-red"}`}>{h?.pqc?.enabled ? "ACTIVE" : "DISABLED"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Dual Merkle</span>
              <span className="font-mono text-brand">{h?.pqc?.dualMerkleRoots ? "SHA-256 + SHA3-256" : "SHA-256 only"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Algorithms</span>
              <div className="flex flex-wrap gap-1 justify-end">
                {(h?.pqc?.algorithms ?? []).map((a: string) => (
                  <span key={a} className="text-[8px] font-mono px-1.5 py-0.5 rounded" style={{ background: "rgba(171,71,188,0.1)", color: "#AB47BC", border: "1px solid rgba(171,71,188,0.2)" }}>{a}</span>
                ))}
              </div>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Quantum Cloud</span>
              <span className="font-mono text-text-muted">{h?.pqc?.quantumCloud ? "Connected" : "Local PQC"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Anchored Blocks</span>
              <span className="font-mono">{c?.anchored ?? 0}</span>
            </div>
          </div>
        </div>

        {/* Tenants Panel */}
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Building2 className="w-4 h-4 text-brand" />
              <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Tenants</span>
            </div>
            <Link href="/admin/tenants" className="text-[10px] text-blue hover:text-blue-bright">View All →</Link>
          </div>
          <div className="p-5">
            <div className="flex items-center gap-4 p-3 rounded-lg bg-surface border border-border">
              <Building2 className="w-5 h-5 text-brand" />
              <div className="flex-1">
                <div className="font-medium text-sm">MetaCognixion</div>
                <div className="text-[10px] text-text-muted font-mono">org_5fa7beb396fe4029 · enterprise</div>
              </div>
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-brand/10 text-brand border border-brand/20">active</span>
            </div>
          </div>
        </div>

        {/* Quick Actions Panel */}
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-amber">Quick Actions</span>
          </div>
          <div className="p-5 grid grid-cols-2 gap-2">
            {[
              { label: "View Chain", href: "/chain", icon: Link2, color: "text-blue" },
              { label: "Compliance", href: "/compliance", icon: ShieldCheck, color: "text-brand" },
              { label: "Quantum", href: "/quantum", icon: Atom, color: "text-violet" },
              { label: "Functions", href: "/functions", icon: Blocks, color: "text-blue" },
              { label: "Logs", href: "/logs", icon: Activity, color: "text-amber" },
              { label: "System", href: "/admin/system", icon: Server, color: "text-red" },
            ].map(a => (
              <Link key={a.label} href={a.href}
                className="flex items-center gap-2 px-3 py-2.5 rounded-lg border border-border hover:border-border-bright hover:bg-surface/50 transition-all text-sm">
                <a.icon className={`w-4 h-4 ${a.color}`} />
                {a.label}
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Compliance Controls */}
      {comp?.controls && (
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-brand" />
              <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Live Compliance Controls</span>
            </div>
            <span className="text-xs font-mono text-text-muted">{comp.summary?.pass ?? 0}/{comp.controls.length} passing</span>
          </div>
          <div className="p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {comp.controls.map((ctrl: any) => (
              <div key={ctrl.id} className="flex items-center gap-3 p-3 rounded-lg border border-border">
                <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                  ctrl.status === "pass" ? "bg-brand shadow-[0_0_4px] shadow-brand" :
                  ctrl.status === "warn" ? "bg-amber shadow-[0_0_4px] shadow-amber" :
                  "bg-red shadow-[0_0_4px] shadow-red"
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{ctrl.name}</div>
                  <div className="text-[9px] text-text-muted font-mono">{ctrl.framework} {ctrl.reference}</div>
                </div>
                <span className={`text-sm font-bold ${ctrl.score >= 80 ? "text-brand" : ctrl.score >= 50 ? "text-amber" : "text-red"}`}>
                  {ctrl.score}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Admin Footer */}
      <div className="rounded-xl border border-red/20 bg-red/5 p-4 text-xs text-text-muted flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-red shrink-0" />
        <span>Super Admin access grants full platform control. All actions are logged to the SovereignChain audit trail. Admin token: <code className="font-mono text-red">sk-sovereign-admin-2026</code> (change this in production).</span>
      </div>
    </div>
  );
}
