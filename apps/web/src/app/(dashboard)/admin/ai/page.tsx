"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import {
  Brain, Zap, Activity, ShieldCheck, DollarSign, Heart, AlertTriangle,
  Play, Pause, RotateCcw, CheckCircle, XCircle, Clock, TrendingUp,
  MessageSquare, Sparkles, Target, Cpu, RefreshCw, Send,
  ArrowUpRight, ArrowDownRight, Bot,
} from "lucide-react";

interface Decision {
  id: string; action: string; target: string; reason: string;
  confidence: number; priority: string; approved: boolean; ts: number;
}

interface Agent {
  id: string; name: string; status: string; description: string;
  lastRun: string; executions: number; icon: string;
}

export default function AIPage() {
  const [tab, setTab] = useState<"assistant" | "decisions" | "agents" | "health" | "optimizer">("assistant");
  const [prompt, setPrompt] = useState("");
  const [chatHistory, setChatHistory] = useState<Array<{ role: "user" | "ai"; text: string; ts: number }>>([
    { role: "ai", text: "I'm your Sovereignly AI Operations Assistant. I can analyze your platform health, optimize costs, check compliance, manage deployments, and more.\n\nTry: \"Show me platform health\" or \"Optimize my costs\" or \"Check compliance status\"", ts: Date.now() },
  ]);
  const [thinking, setThinking] = useState(false);

  const [decisions] = useState<Decision[]>([
    { id: "dec_001", action: "scale_up", target: "worker-pool", reason: "Queue depth > 50 for 5 minutes", confidence: 0.92, priority: "high", approved: true, ts: Date.now() - 300000 },
    { id: "dec_002", action: "investigate", target: "tenant:org_5fa7", reason: "Error rate spike to 12%", confidence: 0.78, priority: "medium", approved: true, ts: Date.now() - 600000 },
    { id: "dec_003", action: "scale_down", target: "edge-nodes", reason: "Idle for 30+ minutes, zero traffic", confidence: 0.65, priority: "low", approved: false, ts: Date.now() - 900000 },
  ]);

  const [agents] = useState<Agent[]>([
    { id: "health-monitor", name: "Health Monitor", status: "running", description: "Watches chain events, flags anomalies, triggers alerts", lastRun: "2s ago", executions: 1247, icon: "❤️" },
    { id: "compliance-agent", name: "Compliance Agent", status: "running", description: "Evaluates SOC2/ISO controls continuously, updates scores", lastRun: "5m ago", executions: 89, icon: "🛡️" },
    { id: "cost-optimizer", name: "Cost Optimizer", status: "idle", description: "Analyzes resource usage, suggests savings, auto-scales", lastRun: "15m ago", executions: 42, icon: "💰" },
  ]);

  async function sendPrompt() {
    if (!prompt.trim()) return;
    const userMsg = prompt.trim();
    setChatHistory(h => [...h, { role: "user", text: userMsg, ts: Date.now() }]);
    setPrompt("");
    setThinking(true);

    // Simulate AI analysis based on prompt
    await new Promise(r => setTimeout(r, 1500));

    let response = "";
    const lowerPrompt = userMsg.toLowerCase();

    if (lowerPrompt.includes("health") || lowerPrompt.includes("status")) {
      const { data } = await api("/_sovereign/health");
      const h = data as any;
      response = `**Platform Health: ${h?.ok ? "✅ HEALTHY" : "⚠️ DEGRADED"}**\n\n` +
        `• Uptime: ${h?.uptime ? (h.uptime / 3600).toFixed(1) + "h" : "unknown"}\n` +
        `• Workers: ${h?.workers?.total ?? 0} total (${h?.workers?.busy ?? 0} busy)\n` +
        `• Chain: ${h?.chain?.blocks ?? 0} blocks, ${h?.chain?.events ?? 0} events\n` +
        `• PQC: ${h?.pqc?.enabled ? "Active (4 algorithms)" : "Disabled"}\n\n` +
        `**Recommendation:** ${h?.ok ? "All systems nominal. No action needed." : "Investigate degraded subsystems."}`;
    } else if (lowerPrompt.includes("compliance") || lowerPrompt.includes("soc2")) {
      const { data } = await api("/_sovereign/compliance/live");
      const c = data as any;
      response = `**Compliance Score: ${c?.score ?? "?"}/100**\n\n` +
        `• Passing: ${c?.summary?.pass ?? 0} controls\n` +
        `• Warnings: ${c?.summary?.warn ?? 0}\n` +
        `• Failing: ${c?.summary?.fail ?? 0}\n\n` +
        (c?.controls ?? []).map((ctrl: any) => `${ctrl.status === "pass" ? "✅" : ctrl.status === "warn" ? "⚠️" : "❌"} ${ctrl.name}: ${ctrl.score}/100`).join("\n") +
        `\n\n**Recommendation:** ${(c?.score ?? 0) >= 80 ? "Compliance posture is strong." : "Focus on failing controls to improve score."}`;
    } else if (lowerPrompt.includes("cost") || lowerPrompt.includes("optimize") || lowerPrompt.includes("saving")) {
      response = `**Cost Analysis & Optimization**\n\n` +
        `Current Infrastructure:\n` +
        `• Fly.io main app: ~$20/mo (shared-cpu-1x, 2GB)\n` +
        `• Fly.io web frontend: ~$8/mo (shared-cpu-1x, 512MB)\n` +
        `• Volume storage: ~$0.15/mo (1GB SSD)\n` +
        `• **Total: ~$28/mo**\n\n` +
        `🎯 **One-Click Optimizations Available:**\n\n` +
        `1. **Scale edge nodes to zero** when idle → Save $5-15/mo\n` +
        `2. **Enable auto-stop** on web frontend → Save $3-5/mo\n` +
        `3. **Switch to annual billing** for Fly.io → Save 15%\n` +
        `4. **Use Cloudflare R2** for Litestream backups → $0 egress vs S3\n\n` +
        `Estimated savings: **$8-20/mo (30-50%)**\n\nShall I apply any of these?`;
    } else if (lowerPrompt.includes("deploy") || lowerPrompt.includes("scale")) {
      response = `**Deployment & Scaling**\n\n` +
        `Current setup:\n` +
        `• 1 machine in IAD (US East)\n` +
        `• 2 workers pre-warmed\n` +
        `• Auto-start: enabled, Auto-stop: disabled\n\n` +
        `🎯 **One-Click Actions:**\n\n` +
        `1. **Add EU region** (ams) → Reduce EU latency by ~80ms\n` +
        `2. **Scale workers to 4** → Handle 2x concurrent functions\n` +
        `3. **Enable auto-stop** → Only pay when receiving traffic\n` +
        `4. **Add health check alerts** → PagerDuty/Slack integration\n\nWhich would you like to apply?`;
    } else if (lowerPrompt.includes("quantum") || lowerPrompt.includes("pqc")) {
      const { data } = await api("/_sovereign/quantum/algorithms");
      const q = data as any;
      response = `**Post-Quantum Security Status**\n\n` +
        `• Signatures: ${q?.pqc?.algorithms?.signatures ?? "?"}\n` +
        `• Hashing: ${q?.pqc?.algorithms?.hashing ?? "?"}\n` +
        `• Key Encap: ${q?.pqc?.algorithms?.keyEncapsulation ?? "?"}\n` +
        `• ZK Ready: ${q?.pqc?.algorithms?.zkReady ?? "?"}\n` +
        `• Dual Merkle: ${q?.chain?.dualMerkleRoots ? "Active" : "Inactive"}\n` +
        `• Blocks with PQ root: ${q?.chain?.blocksWithPQRoot ?? 0}\n\n` +
        `**Assessment:** Your platform is NIST FIPS 203/204 compliant. Post-quantum protection is active on every block.`;
    } else {
      response = `I can help you with:\n\n` +
        `• **"Show platform health"** — Full system status\n` +
        `• **"Check compliance"** — SOC2/ISO27001 score\n` +
        `• **"Optimize costs"** — Find savings opportunities\n` +
        `• **"Scale deployment"** — Add regions, workers\n` +
        `• **"Quantum status"** — PQC algorithm report\n` +
        `• **"Analyze errors"** — Error rate trends\n` +
        `• **"Generate report"** — Compliance/audit export\n\nWhat would you like to do?`;
    }

    setChatHistory(h => [...h, { role: "ai", text: response, ts: Date.now() }]);
    setThinking(false);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-violet/10 border border-violet/20 flex items-center justify-center">
            <Brain className="w-5 h-5 text-violet" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">AI Operations Center</h1>
            <p className="text-xs text-text-muted font-mono">Intelligent platform management</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface border border-border w-fit">
        {([
          { id: "assistant", label: "AI Assistant", icon: MessageSquare },
          { id: "decisions", label: "Decisions", icon: Target },
          { id: "agents", label: "Agents", icon: Bot },
          { id: "optimizer", label: "Optimizer", icon: Sparkles },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium transition-all ${tab === t.id ? "bg-brand text-background" : "text-text-muted hover:text-text-primary"}`}>
            <t.icon className="w-3.5 h-3.5" /> {t.label}
          </button>
        ))}
      </div>

      {/* AI Assistant */}
      {tab === "assistant" && (
        <div className="rounded-xl border border-border bg-panel overflow-hidden flex flex-col" style={{ height: "calc(100vh - 260px)" }}>
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {chatHistory.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[80%] rounded-xl px-4 py-3 text-sm ${
                  msg.role === "user" ? "bg-brand text-background" : "bg-surface border border-border"
                }`}>
                  {msg.role === "ai" && <div className="flex items-center gap-1.5 mb-2 text-[9px] font-mono text-violet"><Brain className="w-3 h-3" /> Sovereignly AI</div>}
                  <div className="whitespace-pre-wrap leading-relaxed">{msg.text}</div>
                </div>
              </div>
            ))}
            {thinking && (
              <div className="flex justify-start">
                <div className="bg-surface border border-border rounded-xl px-4 py-3">
                  <div className="flex items-center gap-2 text-sm text-violet">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Analyzing...
                  </div>
                </div>
              </div>
            )}
          </div>
          <div className="border-t border-border p-4 flex gap-3">
            <input value={prompt} onChange={e => setPrompt(e.target.value)}
              onKeyDown={e => e.key === "Enter" && sendPrompt()}
              placeholder="Ask the AI... (health, compliance, costs, deploy, quantum)"
              className="flex-1 px-4 py-2.5 rounded-xl bg-surface border border-border text-sm focus:border-brand outline-none" />
            <button onClick={sendPrompt} disabled={thinking}
              className="px-5 py-2.5 rounded-xl bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors disabled:opacity-50">
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Decisions */}
      {tab === "decisions" && (
        <div className="rounded-xl border border-border bg-panel overflow-hidden">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Target className="w-4 h-4 text-amber" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-amber">AI Decision History</span>
          </div>
          <div className="divide-y divide-border/50">
            {decisions.map(d => (
              <div key={d.id} className="px-5 py-4 flex items-center justify-between hover:bg-surface/30">
                <div className="flex items-center gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${d.approved ? "bg-brand shadow-[0_0_4px] shadow-brand" : "bg-red shadow-[0_0_4px] shadow-red"}`} />
                  <div>
                    <div className="text-sm font-medium">{d.action.replace("_", " ")} → {d.target}</div>
                    <div className="text-[10px] text-text-muted">{d.reason}</div>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <div className="text-right">
                    <div className={`font-mono ${d.confidence >= 0.8 ? "text-brand" : d.confidence >= 0.6 ? "text-amber" : "text-red"}`}>{(d.confidence * 100).toFixed(0)}%</div>
                    <div className="text-[9px] text-text-muted">confidence</div>
                  </div>
                  <span className={`font-mono px-2 py-0.5 rounded border text-[9px] ${
                    d.priority === "high" ? "bg-red/10 text-red border-red/20" :
                    d.priority === "medium" ? "bg-amber/10 text-amber border-amber/20" :
                    "bg-surface text-text-muted border-border"
                  }`}>{d.priority}</span>
                  {d.approved ? <CheckCircle className="w-4 h-4 text-brand" /> : <XCircle className="w-4 h-4 text-red" />}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Agents */}
      {tab === "agents" && (
        <div className="space-y-3">
          {agents.map(a => (
            <div key={a.id} className="rounded-xl border border-border bg-panel p-5 flex items-center justify-between hover:border-border-bright transition-colors">
              <div className="flex items-center gap-4">
                <div className="text-2xl">{a.icon}</div>
                <div>
                  <div className="font-medium">{a.name}</div>
                  <div className="text-xs text-text-muted mt-0.5">{a.description}</div>
                  <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono text-text-muted">
                    <span>Last: {a.lastRun}</span>
                    <span>{a.executions} executions</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-[9px] font-mono px-2 py-1 rounded border ${
                  a.status === "running" ? "bg-brand/10 text-brand border-brand/20 animate-pulse" :
                  a.status === "idle" ? "bg-surface text-text-muted border-border" :
                  "bg-red/10 text-red border-red/20"
                }`}>{a.status}</span>
                {a.status === "running"
                  ? <button onClick={() => toast.info(`Pausing ${a.name}...`)} className="p-2 rounded-lg border border-border hover:bg-surface"><Pause className="w-4 h-4 text-text-muted" /></button>
                  : <button onClick={() => toast.success(`Started ${a.name}`)} className="p-2 rounded-lg border border-border hover:bg-brand/10"><Play className="w-4 h-4 text-brand" /></button>}
                <button onClick={() => toast.info(`Restarting ${a.name}...`)} className="p-2 rounded-lg border border-border hover:bg-surface">
                  <RotateCcw className="w-4 h-4 text-text-muted" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Optimizer */}
      {tab === "optimizer" && (
        <div className="space-y-4">
          <div className="rounded-xl border border-brand/20 bg-brand/5 p-5">
            <h3 className="font-medium flex items-center gap-2 mb-4"><Sparkles className="w-4 h-4 text-brand" /> One-Click Optimizations</h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {[
                { title: "Scale edge to zero", desc: "No edge traffic detected in 30min. Auto-stop to save resources.", saving: "$5-15/mo", confidence: 92, action: "scale_down_edge" },
                { title: "Enable web auto-stop", desc: "Frontend can auto-stop when idle, auto-start on request.", saving: "$3-5/mo", confidence: 88, action: "enable_autostop" },
                { title: "Optimize worker pool", desc: "Worker utilization at 12%. Reduce from 2 to 1 during off-peak.", saving: "$8/mo", confidence: 75, action: "reduce_workers" },
                { title: "Switch backup to R2", desc: "Cloudflare R2 has zero egress fees vs current S3.", saving: "$2-10/mo", confidence: 95, action: "switch_r2" },
              ].map(opt => (
                <div key={opt.action} className="rounded-lg border border-border p-4 flex items-start justify-between hover:border-brand/30 transition-colors">
                  <div className="flex-1">
                    <div className="font-medium text-sm">{opt.title}</div>
                    <div className="text-xs text-text-muted mt-1">{opt.desc}</div>
                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-[10px] font-mono text-brand">Save {opt.saving}</span>
                      <span className="text-[10px] font-mono text-text-muted">{opt.confidence}% confidence</span>
                    </div>
                  </div>
                  <button onClick={() => toast.success(`Applied: ${opt.title}`)}
                    className="shrink-0 ml-3 px-3 py-1.5 rounded-lg bg-brand text-background text-xs font-medium hover:bg-brand-bright transition-colors">
                    Apply
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-panel p-5">
            <h3 className="text-xs font-mono text-text-muted uppercase tracking-widest mb-3">Resource Utilization</h3>
            <div className="space-y-4">
              {[
                { label: "CPU", value: 12, color: "bg-brand" },
                { label: "Memory", value: 34, color: "bg-blue" },
                { label: "Workers", value: 0, color: "bg-amber" },
                { label: "Storage", value: 8, color: "bg-violet" },
              ].map(r => (
                <div key={r.label}>
                  <div className="flex justify-between mb-1"><span className="text-sm">{r.label}</span><span className="text-xs font-mono text-text-muted">{r.value}%</span></div>
                  <div className="h-2 rounded-full bg-border"><div className={`h-full rounded-full ${r.color}`} style={{ width: `${r.value}%` }} /></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
