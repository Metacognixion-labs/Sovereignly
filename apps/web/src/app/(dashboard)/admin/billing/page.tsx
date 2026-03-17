"use client";

import { useState } from "react";
import { toast } from "sonner";
import { fmt } from "@/lib/utils";
import {
  CreditCard, DollarSign, TrendingUp, Users, BarChart3, Edit3,
  Save, Plus, Trash2, Tag, Percent, Calendar, AlertTriangle,
  CheckCircle, ArrowUpRight, ArrowDownRight, Zap, RefreshCw,
} from "lucide-react";

interface PlanConfig {
  id: string; name: string; priceMonthly: number; priceAnnual: number;
  limits: { events: number; functions: number; storageGB: number; seats: number };
  features: string[];
  stripeMonthlyId: string; stripeAnnualId: string;
  active: boolean;
}

interface Subscription {
  tenantId: string; tenantName: string; plan: string; status: string;
  mrr: number; startDate: string; nextBilling: string;
}

interface Coupon {
  id: string; code: string; discount: number; type: "percent" | "fixed";
  maxUses: number; used: number; expiresAt: string; active: boolean;
}

export default function AdminBillingPage() {
  const [tab, setTab] = useState<"overview" | "plans" | "subscriptions" | "coupons">("overview");
  const [editingPlan, setEditingPlan] = useState<string | null>(null);

  const [plans, setPlans] = useState<PlanConfig[]>([
    { id: "free", name: "Free", priceMonthly: 0, priceAnnual: 0, limits: { events: 10000, functions: 3, storageGB: 0.5, seats: 1 }, features: ["Audit chain", "EAS/Base anchoring", "Community support"], stripeMonthlyId: "", stripeAnnualId: "", active: true },
    { id: "starter", name: "Starter", priceMonthly: 49, priceAnnual: 39, limits: { events: 1000000, functions: 20, storageGB: 20, seats: 3 }, features: ["SOC2 reports", "EAS + Arbitrum", "Email support"], stripeMonthlyId: "price_starter_mo", stripeAnnualId: "price_starter_yr", active: true },
    { id: "growth", name: "Growth", priceMonthly: 149, priceAnnual: 119, limits: { events: 10000000, functions: 100, storageGB: 100, seats: 10 }, features: ["Full omnichain (5 chains)", "SOC2 + ISO27001", "Quantum attestation", "Priority support"], stripeMonthlyId: "price_growth_mo", stripeAnnualId: "price_growth_yr", active: true },
    { id: "enterprise", name: "Enterprise", priceMonthly: 2000, priceAnnual: 1600, limits: { events: -1, functions: -1, storageGB: -1, seats: -1 }, features: ["Everything", "Dedicated infra", "Confidential compute", "Custom compliance", "24/7 SLA"], stripeMonthlyId: "price_ent_mo", stripeAnnualId: "price_ent_yr", active: true },
  ]);

  const [subscriptions] = useState<Subscription[]>([
    { tenantId: "org_5fa7beb396fe4029", tenantName: "MetaCognixion", plan: "enterprise", status: "active", mrr: 2000, startDate: "2026-03-17", nextBilling: "2026-04-17" },
  ]);

  const [coupons, setCoupons] = useState<Coupon[]>([
    { id: "1", code: "LAUNCH50", discount: 50, type: "percent", maxUses: 100, used: 3, expiresAt: "2026-06-30", active: true },
  ]);

  const [newCoupon, setNewCoupon] = useState({ code: "", discount: 0, type: "percent" as const, maxUses: 100, expiresAt: "" });

  const totalMRR = subscriptions.reduce((s, sub) => s + sub.mrr, 0);
  const totalARR = totalMRR * 12;
  const paidCount = subscriptions.filter(s => s.plan !== "free").length;

  function updatePlan(id: string, field: string, value: any) {
    setPlans(plans.map(p => {
      if (p.id !== id) return p;
      if (field.startsWith("limits.")) {
        const key = field.split(".")[1];
        return { ...p, limits: { ...p.limits, [key]: value } };
      }
      return { ...p, [field]: value };
    }));
  }

  function savePlan(id: string) {
    setEditingPlan(null);
    toast.success(`Plan "${id}" updated — sync with Stripe to apply`);
  }

  function addCoupon() {
    if (!newCoupon.code) { toast.error("Code required"); return; }
    setCoupons([...coupons, { ...newCoupon, id: crypto.randomUUID().slice(0, 8), used: 0, active: true }]);
    setNewCoupon({ code: "", discount: 0, type: "percent", maxUses: 100, expiresAt: "" });
    toast.success(`Coupon ${newCoupon.code} created`);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Billing Administration</h1>
          <p className="text-sm text-text-muted mt-0.5">Revenue, pricing, subscriptions, and coupons</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface border border-border w-fit">
        {(["overview", "plans", "subscriptions", "coupons"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded-md text-sm font-medium transition-all capitalize ${tab === t ? "bg-brand text-background" : "text-text-muted hover:text-text-primary"}`}>{t}</button>
        ))}
      </div>

      {/* Overview */}
      {tab === "overview" && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="rounded-xl border border-border bg-panel p-5">
              <div className="flex items-center gap-2 mb-2"><DollarSign className="w-4 h-4 text-brand" /><span className="text-[9px] font-mono text-text-muted uppercase">MRR</span></div>
              <div className="text-3xl font-bold text-brand">${fmt(totalMRR)}</div>
              <div className="flex items-center gap-1 mt-1 text-[10px] text-brand"><ArrowUpRight className="w-3 h-3" /> +12.5% vs last month</div>
            </div>
            <div className="rounded-xl border border-border bg-panel p-5">
              <div className="flex items-center gap-2 mb-2"><TrendingUp className="w-4 h-4 text-blue" /><span className="text-[9px] font-mono text-text-muted uppercase">ARR</span></div>
              <div className="text-3xl font-bold text-blue">${fmt(totalARR)}</div>
            </div>
            <div className="rounded-xl border border-border bg-panel p-5">
              <div className="flex items-center gap-2 mb-2"><Users className="w-4 h-4 text-violet" /><span className="text-[9px] font-mono text-text-muted uppercase">Paid Customers</span></div>
              <div className="text-3xl font-bold text-violet">{paidCount}</div>
            </div>
            <div className="rounded-xl border border-border bg-panel p-5">
              <div className="flex items-center gap-2 mb-2"><Tag className="w-4 h-4 text-amber" /><span className="text-[9px] font-mono text-text-muted uppercase">Active Coupons</span></div>
              <div className="text-3xl font-bold text-amber">{coupons.filter(c => c.active).length}</div>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-panel p-5">
            <h3 className="text-xs font-mono text-text-muted uppercase tracking-widest mb-3">Revenue by Plan</h3>
            <div className="space-y-3">
              {plans.filter(p => p.priceMonthly > 0).map(p => {
                const count = subscriptions.filter(s => s.plan === p.id).length;
                const rev = count * p.priceMonthly;
                const pct = totalMRR > 0 ? (rev / totalMRR) * 100 : 0;
                return (
                  <div key={p.id} className="flex items-center gap-3">
                    <span className="text-sm w-24">{p.name}</span>
                    <div className="flex-1 h-3 rounded-full bg-border overflow-hidden">
                      <div className="h-full rounded-full bg-brand transition-all" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-sm font-mono w-20 text-right">${fmt(rev)}/mo</span>
                    <span className="text-[10px] text-text-muted font-mono w-16 text-right">{count} subs</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Plans */}
      {tab === "plans" && (
        <div className="space-y-4">
          <p className="text-sm text-text-muted">Edit pricing, limits, and features for each plan. Changes apply after syncing with Stripe.</p>
          {plans.map(plan => (
            <div key={plan.id} className={`rounded-xl border bg-panel overflow-hidden ${editingPlan === plan.id ? "border-brand/40" : "border-border"}`}>
              <div className="px-5 py-3 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{plan.name}</span>
                  {plan.id === "growth" && <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-brand/10 text-brand border border-brand/20">Popular</span>}
                </div>
                {editingPlan === plan.id
                  ? <div className="flex gap-2"><button onClick={() => savePlan(plan.id)} className="flex items-center gap-1 px-3 py-1 rounded-lg bg-brand text-background text-xs"><Save className="w-3 h-3" /> Save</button><button onClick={() => setEditingPlan(null)} className="px-3 py-1 rounded-lg border border-border text-xs">Cancel</button></div>
                  : <button onClick={() => setEditingPlan(plan.id)} className="flex items-center gap-1 text-xs text-brand hover:text-brand-bright"><Edit3 className="w-3 h-3" /> Edit</button>}
              </div>
              <div className="p-5 grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Monthly Price</label>
                  <div className="flex items-center gap-1">
                    <span className="text-text-muted">$</span>
                    <input type="number" value={plan.priceMonthly} disabled={editingPlan !== plan.id}
                      onChange={e => updatePlan(plan.id, "priceMonthly", parseInt(e.target.value))}
                      className={`w-full px-2 py-1.5 rounded text-sm font-mono ${editingPlan === plan.id ? "bg-surface border border-border focus:border-brand" : "bg-transparent border-transparent"} outline-none`} />
                  </div>
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Annual Price /mo</label>
                  <div className="flex items-center gap-1">
                    <span className="text-text-muted">$</span>
                    <input type="number" value={plan.priceAnnual} disabled={editingPlan !== plan.id}
                      onChange={e => updatePlan(plan.id, "priceAnnual", parseInt(e.target.value))}
                      className={`w-full px-2 py-1.5 rounded text-sm font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent"} outline-none`} />
                  </div>
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Events/mo</label>
                  <input type="number" value={plan.limits.events} disabled={editingPlan !== plan.id}
                    onChange={e => updatePlan(plan.id, "limits.events", parseInt(e.target.value))}
                    className={`w-full px-2 py-1.5 rounded text-sm font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent"} outline-none`} />
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Functions</label>
                  <input type="number" value={plan.limits.functions} disabled={editingPlan !== plan.id}
                    onChange={e => updatePlan(plan.id, "limits.functions", parseInt(e.target.value))}
                    className={`w-full px-2 py-1.5 rounded text-sm font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent"} outline-none`} />
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Storage (GB)</label>
                  <input type="number" value={plan.limits.storageGB} disabled={editingPlan !== plan.id}
                    onChange={e => updatePlan(plan.id, "limits.storageGB", parseFloat(e.target.value))}
                    className={`w-full px-2 py-1.5 rounded text-sm font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent"} outline-none`} />
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Seats</label>
                  <input type="number" value={plan.limits.seats} disabled={editingPlan !== plan.id}
                    onChange={e => updatePlan(plan.id, "limits.seats", parseInt(e.target.value))}
                    className={`w-full px-2 py-1.5 rounded text-sm font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent"} outline-none`} />
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Stripe Monthly ID</label>
                  <input value={plan.stripeMonthlyId} disabled={editingPlan !== plan.id}
                    onChange={e => updatePlan(plan.id, "stripeMonthlyId", e.target.value)}
                    className={`w-full px-2 py-1.5 rounded text-xs font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent text-text-muted"} outline-none`} />
                </div>
                <div>
                  <label className="block text-[9px] font-mono text-text-muted uppercase mb-1">Stripe Annual ID</label>
                  <input value={plan.stripeAnnualId} disabled={editingPlan !== plan.id}
                    onChange={e => updatePlan(plan.id, "stripeAnnualId", e.target.value)}
                    className={`w-full px-2 py-1.5 rounded text-xs font-mono ${editingPlan === plan.id ? "bg-surface border border-border" : "bg-transparent border-transparent text-text-muted"} outline-none`} />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Subscriptions */}
      {tab === "subscriptions" && (
        <div className="rounded-xl border border-border bg-panel overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-border text-[9px] font-mono uppercase tracking-widest text-text-muted">
              <th className="text-left px-5 py-3">Tenant</th><th className="text-left px-5 py-3">Plan</th><th className="text-left px-5 py-3">Status</th>
              <th className="text-right px-5 py-3">MRR</th><th className="text-right px-5 py-3">Next Billing</th>
            </tr></thead>
            <tbody>
              {subscriptions.map(s => (
                <tr key={s.tenantId} className="border-b border-border/50 hover:bg-surface/30">
                  <td className="px-5 py-3"><div className="font-medium">{s.tenantName}</div><div className="text-[10px] text-text-muted font-mono">{s.tenantId}</div></td>
                  <td className="px-5 py-3"><span className="text-[9px] font-mono px-2 py-1 rounded bg-violet/10 text-violet border border-violet/20">{s.plan}</span></td>
                  <td className="px-5 py-3"><span className="text-[9px] font-mono px-2 py-1 rounded bg-brand/10 text-brand border border-brand/20">{s.status}</span></td>
                  <td className="px-5 py-3 text-right font-mono">${fmt(s.mrr)}</td>
                  <td className="px-5 py-3 text-right font-mono text-text-muted">{s.nextBilling}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Coupons */}
      {tab === "coupons" && (
        <div className="space-y-4">
          <div className="rounded-xl border border-brand/30 bg-brand/5 p-5 space-y-3">
            <h3 className="font-medium flex items-center gap-2"><Tag className="w-4 h-4 text-brand" /> Create Coupon</h3>
            <div className="grid grid-cols-5 gap-3">
              <input value={newCoupon.code} onChange={e => setNewCoupon({ ...newCoupon, code: e.target.value.toUpperCase() })} placeholder="CODE" className="px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono uppercase focus:border-brand outline-none" />
              <input type="number" value={newCoupon.discount || ""} onChange={e => setNewCoupon({ ...newCoupon, discount: parseInt(e.target.value) })} placeholder="Discount" className="px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
              <select value={newCoupon.type} onChange={e => setNewCoupon({ ...newCoupon, type: e.target.value as any })} className="px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none">
                <option value="percent">% Off</option><option value="fixed">$ Off</option>
              </select>
              <input type="number" value={newCoupon.maxUses} onChange={e => setNewCoupon({ ...newCoupon, maxUses: parseInt(e.target.value) })} placeholder="Max uses" className="px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
              <button onClick={addCoupon} className="px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright"><Plus className="w-4 h-4 inline mr-1" /> Create</button>
            </div>
          </div>
          <div className="rounded-xl border border-border bg-panel overflow-hidden">
            <div className="divide-y divide-border/50">
              {coupons.map(c => (
                <div key={c.id} className="px-5 py-3 flex items-center justify-between hover:bg-surface/30">
                  <div className="flex items-center gap-4">
                    <code className="font-mono text-sm font-bold text-brand">{c.code}</code>
                    <span className="text-sm">{c.discount}{c.type === "percent" ? "%" : "$"} off</span>
                    <span className="text-[10px] text-text-muted font-mono">{c.used}/{c.maxUses} used</span>
                    {c.expiresAt && <span className="text-[10px] text-text-muted">expires {c.expiresAt}</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${c.active ? "bg-brand/10 text-brand border-brand/20" : "bg-surface text-text-muted border-border"}`}>{c.active ? "Active" : "Disabled"}</span>
                    <button onClick={() => setCoupons(coupons.filter(x => x.id !== c.id))} className="p-1 rounded hover:bg-red/10"><Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" /></button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
