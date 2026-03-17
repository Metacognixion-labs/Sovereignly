"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import { toast } from "sonner";
import {
  CreditCard, Zap, ArrowUpRight, Check, Crown, Sparkles,
  BarChart3, Database as DbIcon, Blocks, Users,
} from "lucide-react";

const PLANS = [
  { id: "free", name: "Free", price: 0, color: "text-text-secondary",
    limits: { events: "10K/mo", functions: 3, storage: "0.5 GB", seats: 1 } },
  { id: "starter", name: "Starter", price: 49, color: "text-blue",
    limits: { events: "1M/mo", functions: 20, storage: "20 GB", seats: 3 } },
  { id: "growth", name: "Growth", price: 149, color: "text-brand", featured: true,
    limits: { events: "10M/mo", functions: 100, storage: "100 GB", seats: 10 } },
  { id: "enterprise", name: "Enterprise", price: -1, color: "text-violet",
    limits: { events: "Unlimited", functions: "Unlimited", storage: "Unlimited", seats: "Unlimited" } },
];

export default function BillingPage() {
  const [currentPlan, setCurrentPlan] = useState("free");
  const [usage, setUsage] = useState<any>(null);

  useEffect(() => {
    api("/_sovereign/metrics").then(r => {
      if (r.ok && r.data) setUsage(r.data);
    });
  }, []);

  async function upgrade(planId: string) {
    const { ok, data } = await api<{ url?: string }>("/_sovereign/billing/checkout", {
      method: "POST",
      body: JSON.stringify({ plan: planId, tenantId: "platform" }),
    });
    if (ok && data?.url) {
      window.location.href = data.url;
    } else {
      toast.error("Billing not configured. Set STRIPE_SECRET_KEY to enable payments.");
    }
  }

  async function openPortal() {
    const { ok, data } = await api<{ url?: string }>("/_sovereign/billing/portal", {
      method: "POST",
      body: JSON.stringify({ tenantId: "platform", returnUrl: window.location.href }),
    });
    if (ok && data?.url) {
      window.location.href = data.url;
    } else {
      toast.error("Billing portal not configured. Set STRIPE_SECRET_KEY.");
    }
  }

  const plan = PLANS.find(p => p.id === currentPlan) ?? PLANS[0];

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Billing & Usage</h1>
        <p className="text-sm text-text-muted mt-0.5">Manage your plan and monitor usage</p>
      </div>

      {/* Current Plan */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Crown className="w-4 h-4 text-brand" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Current Plan</span>
          </div>
          <button onClick={openPortal}
            className="text-xs text-blue hover:text-blue-bright transition-colors">
            <CreditCard className="w-3 h-3 inline mr-1" /> Manage Payment
          </button>
        </div>
        <div className="p-5 flex items-center justify-between">
          <div>
            <div className="text-2xl font-bold">{plan.name}</div>
            <div className="text-sm text-text-muted mt-0.5">
              {plan.price === 0 ? "Free forever" : plan.price === -1 ? "Custom pricing" : `$${plan.price}/month`}
            </div>
          </div>
          {plan.id !== "enterprise" && (
            <button onClick={() => upgrade(plan.id === "free" ? "starter" : "growth")}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
              <Sparkles className="w-4 h-4" /> Upgrade
            </button>
          )}
        </div>
      </div>

      {/* Usage Meters */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-blue" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-blue">Usage This Period</span>
        </div>
        <div className="p-5 space-y-5">
          {[
            { label: "Events", icon: Zap, current: usage?.chain?.events ?? 0, limit: plan.limits.events, color: "bg-brand" },
            { label: "Functions", icon: Blocks, current: usage?.functions ?? 0, limit: plan.limits.functions, color: "bg-blue" },
            { label: "Storage", icon: DbIcon, current: "0.1 GB", limit: plan.limits.storage, color: "bg-violet" },
            { label: "Team Seats", icon: Users, current: 1, limit: plan.limits.seats, color: "bg-amber" },
          ].map(m => {
            const numLimit = typeof m.limit === "number" ? m.limit : null;
            const numCurrent = typeof m.current === "number" ? m.current : 0;
            const pct = numLimit ? Math.min(100, (numCurrent / numLimit) * 100) : 5;
            return (
              <div key={m.label}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm flex items-center gap-2">
                    <m.icon className="w-3.5 h-3.5 text-text-muted" /> {m.label}
                  </span>
                  <span className="text-xs font-mono text-text-muted">
                    {typeof m.current === "number" ? fmt(m.current) : m.current} / {typeof m.limit === "number" ? fmt(m.limit) : m.limit}
                  </span>
                </div>
                <div className="h-2 rounded-full bg-border overflow-hidden">
                  <div className={`h-full rounded-full ${m.color} transition-all duration-500`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Plan Comparison */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border">
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Compare Plans</span>
        </div>
        <div className="p-5 grid grid-cols-4 gap-4">
          {PLANS.map(p => (
            <div key={p.id} className={`rounded-lg border p-4 ${p.featured ? "border-brand/30 bg-brand/5" : "border-border"} ${currentPlan === p.id ? "ring-2 ring-brand/30" : ""}`}>
              <div className={`font-semibold ${p.color}`}>{p.name}</div>
              <div className="text-xl font-bold mt-1">
                {p.price === 0 ? "Free" : p.price === -1 ? "Custom" : `$${p.price}`}
                {p.price > 0 && <span className="text-xs text-text-muted font-normal">/mo</span>}
              </div>
              <div className="mt-3 space-y-1.5 text-xs text-text-muted">
                <div>{p.limits.events} events</div>
                <div>{p.limits.functions} functions</div>
                <div>{p.limits.storage} storage</div>
                <div>{p.limits.seats} seats</div>
              </div>
              {currentPlan === p.id ? (
                <div className="mt-3 text-[10px] font-mono text-brand text-center">Current Plan</div>
              ) : p.price > (PLANS.find(x => x.id === currentPlan)?.price ?? 0) ? (
                <button onClick={() => upgrade(p.id)}
                  className="mt-3 w-full py-1.5 rounded text-[10px] font-medium bg-brand text-background hover:bg-brand-bright transition-colors">
                  Upgrade
                </button>
              ) : null}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
