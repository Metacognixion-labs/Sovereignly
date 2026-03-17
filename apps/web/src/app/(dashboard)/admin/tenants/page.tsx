"use client";

import { useState } from "react";
import { toast } from "sonner";
import {
  Building2, Search, Shield, Trash2, Ban, CheckCircle, Crown,
  Link2, Database, Users, BarChart3, Plus,
} from "lucide-react";

interface Tenant {
  id: string; name: string; slug: string; plan: string; status: string;
  ownerId: string; events: number; members: number; createdAt: string;
}

const MOCK_TENANTS: Tenant[] = [
  { id: "org_5fa7beb396fe4029", name: "MetaCognixion", slug: "metacognixion", plan: "enterprise", status: "active", ownerId: "jp@metacognixion.com", events: 84, members: 1, createdAt: "2026-03-17" },
];

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>(MOCK_TENANTS);
  const [search, setSearch] = useState("");
  const [filterPlan, setFilterPlan] = useState("all");

  const filtered = tenants.filter(t => {
    if (search && !t.name.toLowerCase().includes(search.toLowerCase()) && !t.id.includes(search)) return false;
    if (filterPlan !== "all" && t.plan !== filterPlan) return false;
    return true;
  });

  function suspend(id: string) {
    if (!confirm("Suspend this tenant? They will lose access to their data.")) return;
    setTenants(tenants.map(t => t.id === id ? { ...t, status: "suspended" } : t));
    toast.success("Tenant suspended");
  }

  function activate(id: string) {
    setTenants(tenants.map(t => t.id === id ? { ...t, status: "active" } : t));
    toast.success("Tenant activated");
  }

  function deleteTenant(id: string) {
    if (!confirm("DELETE this tenant and ALL their data? This cannot be undone.")) return;
    if (!confirm("Are you absolutely sure? Type the tenant ID to confirm.")) return;
    setTenants(tenants.filter(t => t.id !== id));
    toast.success("Tenant deleted");
  }

  function changePlan(id: string, plan: string) {
    setTenants(tenants.map(t => t.id === id ? { ...t, plan } : t));
    toast.success(`Plan changed to ${plan}`);
  }

  const planColor = (p: string) => ({
    free: "bg-surface text-text-muted border-border",
    starter: "bg-blue/10 text-blue border-blue/20",
    growth: "bg-brand/10 text-brand border-brand/20",
    enterprise: "bg-violet/10 text-violet border-violet/20",
  }[p] ?? "bg-surface text-text-muted border-border");

  const statusColor = (s: string) => ({
    active: "bg-brand/10 text-brand border-brand/20",
    suspended: "bg-red/10 text-red border-red/20",
    cancelled: "bg-text-muted/10 text-text-muted border-border",
  }[s] ?? "");

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Tenant Management</h1>
          <p className="text-sm text-text-muted mt-0.5">{tenants.length} total tenants</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
          <Plus className="w-4 h-4" /> Create Tenant
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by name or ID..."
            className="w-full pl-10 pr-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
        </div>
        <select value={filterPlan} onChange={e => setFilterPlan(e.target.value)}
          className="px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none">
          <option value="all">All Plans</option>
          <option value="free">Free</option>
          <option value="starter">Starter</option>
          <option value="growth">Growth</option>
          <option value="enterprise">Enterprise</option>
        </select>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Total", value: tenants.length, color: "text-blue" },
          { label: "Active", value: tenants.filter(t => t.status === "active").length, color: "text-brand" },
          { label: "Suspended", value: tenants.filter(t => t.status === "suspended").length, color: "text-red" },
          { label: "Enterprise", value: tenants.filter(t => t.plan === "enterprise").length, color: "text-violet" },
        ].map(s => (
          <div key={s.label} className="rounded-xl border border-border bg-panel p-4 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-[9px] font-mono text-text-muted uppercase">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tenant List */}
      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-[9px] font-mono uppercase tracking-widest text-text-muted">
              <th className="text-left px-5 py-3">Tenant</th>
              <th className="text-left px-5 py-3">Plan</th>
              <th className="text-left px-5 py-3">Status</th>
              <th className="text-right px-5 py-3">Events</th>
              <th className="text-right px-5 py-3">Members</th>
              <th className="text-right px-5 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(t => (
              <tr key={t.id} className="border-b border-border/50 hover:bg-surface/30 transition-colors">
                <td className="px-5 py-4">
                  <div className="font-medium">{t.name}</div>
                  <div className="text-[10px] text-text-muted font-mono">{t.id} · {t.ownerId}</div>
                </td>
                <td className="px-5 py-4">
                  <select value={t.plan} onChange={e => changePlan(t.id, e.target.value)}
                    className={`text-[9px] font-mono px-2 py-1 rounded border ${planColor(t.plan)} bg-transparent focus:outline-none cursor-pointer`}>
                    <option value="free">Free</option>
                    <option value="starter">Starter</option>
                    <option value="growth">Growth</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                </td>
                <td className="px-5 py-4">
                  <span className={`text-[9px] font-mono px-2 py-1 rounded border ${statusColor(t.status)}`}>{t.status}</span>
                </td>
                <td className="px-5 py-4 text-right font-mono text-xs">{t.events}</td>
                <td className="px-5 py-4 text-right font-mono text-xs">{t.members}</td>
                <td className="px-5 py-4 text-right">
                  <div className="flex items-center justify-end gap-1">
                    {t.status === "active" ? (
                      <button onClick={() => suspend(t.id)} className="p-1.5 rounded hover:bg-amber/10" title="Suspend">
                        <Ban className="w-3.5 h-3.5 text-text-muted hover:text-amber" />
                      </button>
                    ) : (
                      <button onClick={() => activate(t.id)} className="p-1.5 rounded hover:bg-brand/10" title="Activate">
                        <CheckCircle className="w-3.5 h-3.5 text-text-muted hover:text-brand" />
                      </button>
                    )}
                    <button onClick={() => deleteTenant(t.id)} className="p-1.5 rounded hover:bg-red/10" title="Delete">
                      <Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
