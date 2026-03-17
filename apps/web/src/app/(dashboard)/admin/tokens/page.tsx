"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import { toast } from "sonner";
import {
  Coins, Shield, Zap, ArrowRight, Lock, Unlock, AlertTriangle,
  Save, RefreshCw, Send, Award, TrendingUp, Wallet, PiggyBank,
  ChevronRight, CheckCircle, XCircle, Clock, Rocket,
} from "lucide-react";

interface TokenConfig {
  status: string; isFrozen: boolean;
  tokenName: string; tokenSymbol: string;
  transferFeePercent: number; withdrawalFeePercent: number;
  dailyWithdrawLimit: number; weeklyWithdrawLimit: number;
  baseStakingApy: number; minStakeDays: number;
  pointsToTokenRate: number;
}

interface Supply {
  circulating: number; staked: number; inTreasury: number; inFeePool: number;
  totalMinted: number; totalBurned: number;
}

interface Gates {
  canTransfer: boolean; canWithdraw: boolean; canStake: boolean;
  canEarn: boolean; canView: boolean;
}

export default function TokensAdminPage() {
  const [config, setConfig] = useState<TokenConfig | null>(null);
  const [supply, setSupply] = useState<Supply | null>(null);
  const [gates, setGates] = useState<Gates | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<Partial<TokenConfig>>({});

  // Award
  const [awardUser, setAwardUser] = useState("");
  const [awardAmount, setAwardAmount] = useState("");
  const [awardMemo, setAwardMemo] = useState("");

  async function load() {
    setLoading(true);
    const [cfgR, supR] = await Promise.all([
      api<{ config: TokenConfig; gates: Gates }>("/_sovereign/tokens/config"),
      api<Supply>("/_sovereign/tokens/supply"),
    ]);
    if (cfgR.ok && cfgR.data) { setConfig(cfgR.data.config); setGates(cfgR.data.gates); setDraft(cfgR.data.config); }
    if (supR.ok && supR.data) setSupply(supR.data);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  async function saveConfig() {
    const { ok } = await api("/_sovereign/tokens/config", { method: "PUT", body: JSON.stringify(draft) });
    if (ok) { toast.success("Token config saved"); setEditing(false); load(); }
    else toast.error("Failed to save");
  }

  async function setStatus(newStatus: string) {
    if (!confirm(`Transition token system to ${newStatus}? This changes what users can do.`)) return;
    const { ok, data } = await api("/_sovereign/tokens/status", { method: "PUT", body: JSON.stringify({ status: newStatus }) });
    if (ok) { toast.success(`Status → ${newStatus}`); load(); }
    else toast.error((data as any)?.error ?? "Failed");
  }

  async function freeze() {
    const reason = prompt("Freeze reason (shown to users):");
    if (!reason) return;
    const { ok } = await api("/_sovereign/tokens/freeze", { method: "POST", body: JSON.stringify({ reason }) });
    if (ok) { toast.error("TOKEN SYSTEM FROZEN"); load(); }
    else toast.error("Failed to freeze");
  }

  async function unfreeze() {
    if (!confirm("Unfreeze the token system? All operations will resume.")) return;
    const { ok } = await api("/_sovereign/tokens/unfreeze", { method: "POST", body: JSON.stringify({ reason: "Admin unfreeze" }) });
    if (ok) { toast.success("Token system unfrozen"); load(); }
    else toast.error("Failed");
  }

  async function award() {
    if (!awardUser || !awardAmount) { toast.error("User ID and amount required"); return; }
    const { ok } = await api("/_sovereign/tokens/award", {
      method: "POST", body: JSON.stringify({ userId: awardUser, amount: parseFloat(awardAmount), memo: awardMemo || "Admin award" }),
    });
    if (ok) { toast.success(`Awarded ${awardAmount} ${config?.tokenSymbol ?? "SVRN"} to ${awardUser}`); setAwardUser(""); setAwardAmount(""); setAwardMemo(""); load(); }
    else toast.error("Failed to award");
  }

  if (loading) return <div className="space-y-4">{[1,2,3,4].map(i => <div key={i} className="skeleton h-40 rounded-xl" />)}</div>;

  const STATUS_FLOW = ["CLOSED", "PRE_PUBLIC", "PUBLIC"] as const;
  const currentIdx = STATUS_FLOW.indexOf(config?.status as any) ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber/10 border border-amber/20 flex items-center justify-center">
            <Coins className="w-5 h-5 text-amber" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{config?.tokenName ?? "SVRN"} Tokenomics</h1>
            <p className="text-xs text-text-muted font-mono">{config?.tokenSymbol ?? "SVRN"} Token Administration</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {config?.isFrozen && (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-mono bg-red/10 text-red border border-red/20 animate-pulse">
              <AlertTriangle className="w-3 h-3" /> FROZEN
            </span>
          )}
          <span className={`px-3 py-1 rounded-full text-[10px] font-mono border ${
            config?.status === "PUBLIC" ? "bg-brand/10 text-brand border-brand/20" :
            config?.status === "PRE_PUBLIC" ? "bg-amber/10 text-amber border-amber/20" :
            "bg-surface text-text-muted border-border"
          }`}>{config?.status}</span>
        </div>
      </div>

      {/* Status Control */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2"><Rocket className="w-4 h-4 text-amber" /><span className="text-[10px] font-mono uppercase tracking-widest text-amber">Launch Status</span></div>
          <div className="flex gap-2">
            {config?.isFrozen
              ? <button onClick={unfreeze} className="flex items-center gap-1 px-3 py-1 rounded-lg bg-brand text-background text-xs font-medium hover:bg-brand-bright"><Unlock className="w-3 h-3" /> Unfreeze</button>
              : <button onClick={freeze} className="flex items-center gap-1 px-3 py-1 rounded-lg border border-red/30 text-red text-xs hover:bg-red/10"><Lock className="w-3 h-3" /> Emergency Freeze</button>}
          </div>
        </div>
        <div className="p-5">
          <div className="flex items-center gap-4 mb-6">
            {STATUS_FLOW.map((s, i) => (
              <div key={s} className="flex items-center gap-3 flex-1">
                <button onClick={() => setStatus(s)}
                  className={`flex-1 p-4 rounded-xl border text-center transition-all ${
                    config?.status === s
                      ? s === "PUBLIC" ? "border-brand/40 bg-brand/10 ring-2 ring-brand/20" : "border-amber/40 bg-amber/10 ring-2 ring-amber/20"
                      : i <= currentIdx ? "border-brand/20 bg-brand/5" : "border-border hover:border-border-bright"
                  }`}>
                  <div className={`text-xs font-mono font-bold mb-1 ${config?.status === s ? (s === "PUBLIC" ? "text-brand" : "text-amber") : "text-text-muted"}`}>{s}</div>
                  <div className="text-[9px] text-text-muted">{s === "CLOSED" ? "Internal only" : s === "PRE_PUBLIC" ? "Limited access" : "Full access"}</div>
                </button>
                {i < 2 && <ChevronRight className="w-4 h-4 text-text-muted shrink-0" />}
              </div>
            ))}
          </div>

          {/* Feature Gates */}
          <div className="text-[9px] font-mono text-text-muted uppercase tracking-widest mb-2">Feature Gates</div>
          <div className="grid grid-cols-5 gap-2">
            {gates && Object.entries(gates).map(([k, v]) => (
              <div key={k} className={`p-2 rounded-lg text-center text-[10px] font-mono border ${v ? "bg-brand/10 text-brand border-brand/20" : "bg-surface text-text-muted border-border"}`}>
                {v ? <CheckCircle className="w-3 h-3 inline mr-1" /> : <XCircle className="w-3 h-3 inline mr-1" />}
                {k.replace("can", "")}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Supply Dashboard */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        {[
          { label: "Circulating", value: supply?.circulating ?? 0, icon: Coins, color: "text-brand" },
          { label: "Staked", value: supply?.staked ?? 0, icon: Lock, color: "text-blue" },
          { label: "Treasury", value: supply?.inTreasury ?? 0, icon: PiggyBank, color: "text-amber" },
          { label: "Fee Pool", value: supply?.inFeePool ?? 0, icon: Wallet, color: "text-violet" },
          { label: "Minted", value: supply?.totalMinted ?? 0, icon: TrendingUp, color: "text-brand" },
          { label: "Burned", value: supply?.totalBurned ?? 0, icon: Zap, color: "text-red" },
        ].map(s => (
          <div key={s.label} className="rounded-xl border border-border bg-panel p-4">
            <div className="flex items-center gap-1.5 mb-2"><s.icon className={`w-3 h-3 ${s.color}`} /><span className="text-[9px] font-mono text-text-muted uppercase">{s.label}</span></div>
            <div className={`text-lg font-bold ${s.color}`}>{fmt(s.value)}</div>
          </div>
        ))}
      </div>

      {/* Config Editor */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Configuration</span>
          {!editing
            ? <button onClick={() => setEditing(true)} className="text-xs text-brand hover:text-brand-bright">Edit</button>
            : <div className="flex gap-2">
                <button onClick={saveConfig} className="flex items-center gap-1 px-3 py-1 rounded-lg bg-brand text-background text-xs font-medium"><Save className="w-3 h-3" /> Save</button>
                <button onClick={() => { setEditing(false); setDraft(config!); }} className="px-3 py-1 rounded-lg border border-border text-xs hover:bg-surface">Cancel</button>
              </div>}
        </div>
        <div className="p-5 grid grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { key: "tokenName", label: "Token Name", type: "text" },
            { key: "tokenSymbol", label: "Symbol", type: "text" },
            { key: "transferFeePercent", label: "Transfer Fee %", type: "number" },
            { key: "withdrawalFeePercent", label: "Withdrawal Fee %", type: "number" },
            { key: "dailyWithdrawLimit", label: "Daily Withdraw Limit", type: "number" },
            { key: "weeklyWithdrawLimit", label: "Weekly Withdraw Limit", type: "number" },
            { key: "baseStakingApy", label: "Staking APY %", type: "number" },
            { key: "minStakeDays", label: "Min Stake Days", type: "number" },
            { key: "pointsToTokenRate", label: "Points:Token Rate", type: "number" },
          ].map(f => (
            <div key={f.key}>
              <label className="block text-[9px] font-mono text-text-muted uppercase tracking-widest mb-1">{f.label}</label>
              <input type={f.type} value={(draft as any)?.[f.key] ?? ""} disabled={!editing}
                onChange={e => setDraft({ ...draft, [f.key]: f.type === "number" ? parseFloat(e.target.value) : e.target.value })}
                className={`w-full px-3 py-2 rounded-lg border text-sm font-mono outline-none transition-colors ${
                  editing ? "bg-surface border-border focus:border-brand" : "bg-transparent border-transparent text-text-secondary"
                }`} />
            </div>
          ))}
        </div>
      </div>

      {/* Award Tokens */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Award className="w-4 h-4 text-brand" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Award Tokens</span>
        </div>
        <div className="p-5 flex gap-3">
          <input value={awardUser} onChange={e => setAwardUser(e.target.value)} placeholder="User ID or email"
            className="flex-1 px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
          <input value={awardAmount} onChange={e => setAwardAmount(e.target.value)} placeholder="Amount" type="number"
            className="w-28 px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
          <input value={awardMemo} onChange={e => setAwardMemo(e.target.value)} placeholder="Memo (optional)"
            className="flex-1 px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
          <button onClick={award} className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright">
            <Send className="w-3.5 h-3.5" /> Award
          </button>
        </div>
      </div>

      {/* Public Launch Checklist */}
      {config?.status !== "PUBLIC" && (
        <div className="rounded-xl border border-amber/20 bg-amber/5 p-5">
          <h3 className="font-medium text-amber flex items-center gap-2 mb-4"><Rocket className="w-4 h-4" /> Public Launch Checklist</h3>
          <div className="space-y-2">
            {[
              { label: "Legal review completed", done: false },
              { label: "Terms & conditions published", done: false },
              { label: "KYC/AML compliance verified", done: false },
              { label: "Fee structure finalized", done: config?.transferFeePercent !== undefined },
              { label: "Withdrawal limits tested", done: config?.dailyWithdrawLimit !== undefined },
              { label: "Smart contract audited (if on-chain)", done: false },
              { label: "Staking APY confirmed", done: config?.baseStakingApy !== undefined },
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-3">
                {item.done ? <CheckCircle className="w-4 h-4 text-brand" /> : <XCircle className="w-4 h-4 text-text-muted" />}
                <span className={`text-sm ${item.done ? "text-text-primary" : "text-text-muted"}`}>{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
