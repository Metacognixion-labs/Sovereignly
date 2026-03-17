"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import { toast } from "sonner";
import {
  Building2, Search, Trash2, Ban, CheckCircle, Plus, Eye, Loader2,
  Download, RefreshCw, ChevronDown,
} from "lucide-react";

interface Tenant {
  id: string; name: string; slug: string; plan: string; status: string;
  ownerId: string; createdAt: number; updatedAt: number;
}

interface TenantStats {
  chain?: { blocks: number; events: number; anchored: number };
  kv?: { keys: number; sizeBytes: number };
}

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterPlan, setFilterPlan] = useState("all");
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPlan, setNewPlan] = useState("free");
  const [creating, setCreating] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [stats, setStats] = useState<Record<string, TenantStats>>({});

  async function load() {
    setLoading(true);
    const r = await api<any>("/_sovereign/tenants");
    if (r.ok && r.data) setTenants(Array.isArray(r.data) ? r.data : r.data.tenants ?? []);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  async function create() {
    if (!newName.trim() || !newEmail.trim()) { toast.error("Name and email required"); return; }
    setCreating(true);
    const { ok, data } = await api("/_sovereign/tenants", {
      method: "POST", body: JSON.stringify({ name: newName.trim(), ownerId: newEmail.trim(), plan: newPlan }),
    });
    if (ok) { toast.success(`Tenant "${newName}" created`); setShowCreate(false); setNewName(""); setNewEmail(""); load(); }
    else toast.error((data as any)?.error ?? "Failed");
    setCreating(false);
  }

  async function updatePlan(id: string, plan: string) {
    const { ok } = await api(`/_sovereign/tenants/${id}`, { method: "PATCH", body: JSON.stringify({ plan }) });
    if (ok) { setTenants(ts => ts.map(t => t.id === id ? { ...t, plan } : t)); toast.success(`Plan → ${plan}`); }
    else toast.error("Failed");
  }

  async function updateStatus(id: string, status: string) {
    const { ok } = await api(`/_sovereign/tenants/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
    if (ok) { setTenants(ts => ts.map(t => t.id === id ? { ...t, status } : t)); toast.success(`Status → ${status}`); }
    else toast.error("Failed");
  }

  async function deleteTenant(id: string, name: string) {
    if (!confirm(`Delete "${name}" and ALL data? This cannot be undone.`)) return;
    const { ok } = await api(`/_sovereign/tenants/${id}`, { method: "DELETE" });
    if (ok) { setTenants(ts => ts.filter(t => t.id !== id)); toast.success("Deleted"); }
    else toast.error("Failed");
  }

  async function toggleExpand(id: string) {
    if (expandedId === id) { setExpandedId(null); return; }
    setExpandedId(id);
    if (!stats[id]) {
      const { ok, data } = await api<TenantStats>(`/_sovereign/tenants/${id}/stats`);
      if (ok && data) setStats(s => ({ ...s, [id]: data }));
    }
  }

  const filtered = tenants.filter(t => {
    if (search && !t.name?.toLowerCase().includes(search.toLowerCase()) && !t.id.includes(search) && !t.ownerId?.includes(search)) return false;
    if (filterPlan !== "all" && t.plan !== filterPlan) return false;
    return true;
  });

  const planColor = (p: string): string => ({ free: "bg-surface text-text-muted border-border", starter: "bg-blue/10 text-blue border-blue/20", growth: "bg-brand/10 text-brand border-brand/20", enterprise: "bg-violet/10 text-violet border-violet/20" }[p] ?? "bg-surface text-text-muted border-border");
  const statusColor = (s: string): string => ({ active: "bg-brand/10 text-brand border-brand/20", suspended: "bg-amber/10 text-amber border-amber/20", cancelled: "bg-red/10 text-red border-red/20" }[s] ?? "bg-surface text-text-muted border-border");

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div><h1 className="text-2xl font-semibold tracking-tight">Tenant Management</h1><p className="text-sm text-text-muted mt-0.5">{tenants.length} tenants</p></div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 rounded-lg border border-border hover:bg-surface"><RefreshCw className="w-4 h-4 text-text-muted" /></button>
          <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright"><Plus className="w-4 h-4" /> Create</button>
        </div>
      </div>

      {showCreate && (
        <div className="rounded-xl border border-brand/30 bg-brand/5 p-5 space-y-3">
          <h3 className="font-medium">Create Tenant</h3>
          <div className="grid grid-cols-3 gap-3">
            <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Org name" autoFocus className="px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
            <input value={newEmail} onChange={e => setNewEmail(e.target.value)} placeholder="Owner email" type="email" className="px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
            <select value={newPlan} onChange={e => setNewPlan(e.target.value)} className="px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none">
              <option value="free">Free</option><option value="starter">Starter</option><option value="growth">Growth</option><option value="enterprise">Enterprise</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button onClick={create} disabled={creating} className="px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright disabled:opacity-50">{creating ? "Creating..." : "Create"}</button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-surface">Cancel</button>
          </div>
        </div>
      )}

      <div className="flex gap-3">
        <div className="relative flex-1"><Search className="w-4 h-4 absolute left-3 top-2.5 text-text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." className="w-full pl-10 pr-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" /></div>
        <select value={filterPlan} onChange={e => setFilterPlan(e.target.value)} className="px-3 py-2 rounded-lg bg-surface border border-border text-sm outline-none">
          <option value="all">All Plans</option><option value="free">Free</option><option value="starter">Starter</option><option value="growth">Growth</option><option value="enterprise">Enterprise</option>
        </select>
      </div>

      <div className="grid grid-cols-5 gap-3">
        {[{ l: "Total", v: tenants.length, c: "text-blue" }, { l: "Active", v: tenants.filter(t => t.status === "active").length, c: "text-brand" }, { l: "Free", v: tenants.filter(t => t.plan === "free").length, c: "text-text-muted" }, { l: "Paid", v: tenants.filter(t => t.plan !== "free").length, c: "text-blue" }, { l: "Enterprise", v: tenants.filter(t => t.plan === "enterprise").length, c: "text-violet" }].map(s => (
          <div key={s.l} className="rounded-xl border border-border bg-panel p-3 text-center"><div className={`text-xl font-bold ${s.c}`}>{s.v}</div><div className="text-[9px] font-mono text-text-muted uppercase">{s.l}</div></div>
        ))}
      </div>

      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        {loading ? <div className="p-8 text-center"><Loader2 className="w-6 h-6 animate-spin mx-auto text-brand" /></div> :
        filtered.length === 0 ? <div className="p-12 text-center text-text-muted"><Building2 className="w-8 h-8 mx-auto mb-2 opacity-30" />{tenants.length === 0 ? "No tenants" : "No matches"}</div> :
        <div className="divide-y divide-border/50">
          {filtered.map(t => (
            <div key={t.id}>
              <div className="px-5 py-3 flex items-center justify-between hover:bg-surface/30 transition-colors">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <Building2 className="w-4 h-4 text-brand shrink-0" />
                  <div className="min-w-0"><div className="text-sm font-medium truncate">{t.name}</div><div className="text-[10px] text-text-muted font-mono truncate">{t.id} · {t.ownerId}</div></div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <select value={t.plan} onChange={e => updatePlan(t.id, e.target.value)} className={`text-[9px] font-mono px-2 py-1 rounded border ${planColor(t.plan)} bg-transparent cursor-pointer focus:outline-none`}>
                    <option value="free">Free</option><option value="starter">Starter</option><option value="growth">Growth</option><option value="enterprise">Enterprise</option>
                  </select>
                  <span className={`text-[9px] font-mono px-2 py-1 rounded border ${statusColor(t.status)}`}>{t.status}</span>
                  <button onClick={() => toggleExpand(t.id)} className="p-1 rounded hover:bg-surface"><Eye className="w-3.5 h-3.5 text-text-muted" /></button>
                  {t.status === "active" ? <button onClick={() => updateStatus(t.id, "suspended")} className="p-1 rounded hover:bg-amber/10"><Ban className="w-3.5 h-3.5 text-text-muted hover:text-amber" /></button>
                  : <button onClick={() => updateStatus(t.id, "active")} className="p-1 rounded hover:bg-brand/10"><CheckCircle className="w-3.5 h-3.5 text-text-muted hover:text-brand" /></button>}
                  <button onClick={() => deleteTenant(t.id, t.name)} className="p-1 rounded hover:bg-red/10"><Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" /></button>
                </div>
              </div>
              {expandedId === t.id && <div className="px-5 pb-3"><div className="grid grid-cols-4 gap-3 p-3 rounded-lg bg-surface border border-border text-center">
                <div><div className="text-lg font-semibold text-blue">{stats[t.id]?.chain?.blocks ?? "—"}</div><div className="text-[9px] text-text-muted font-mono">Blocks</div></div>
                <div><div className="text-lg font-semibold text-blue">{stats[t.id]?.chain?.events ?? "—"}</div><div className="text-[9px] text-text-muted font-mono">Events</div></div>
                <div><div className="text-lg font-semibold text-brand">{stats[t.id]?.chain?.anchored ?? "—"}</div><div className="text-[9px] text-text-muted font-mono">Anchored</div></div>
                <div><div className="text-lg font-semibold text-violet">{stats[t.id]?.kv?.keys ?? "—"}</div><div className="text-[9px] text-text-muted font-mono">KV Keys</div></div>
              </div></div>}
            </div>
          ))}
        </div>}
      </div>
    </div>
  );
}
