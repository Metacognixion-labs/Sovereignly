"use client";

import { useEffect, useState, useRef } from "react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import {
  Blocks, Activity, AlertTriangle, Clock, Cpu, Link2,
  ShieldCheck, ArrowUpRight, ArrowDownRight, TrendingUp,
} from "lucide-react";

// Animated counter
function AnimatedValue({ value, format = "int" }: { value: number; format?: "int" | "float" | "fmt" }) {
  const [display, setDisplay] = useState(value);
  const prev = useRef(value);

  useEffect(() => {
    const start = prev.current;
    const end = value;
    prev.current = value;
    if (start === end) { setDisplay(end); return; }

    const startTime = performance.now();
    const duration = 600;
    function tick(now: number) {
      const p = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(start + (end - start) * eased);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }, [value]);

  if (format === "fmt") return <>{fmt(Math.round(display))}</>;
  if (format === "float") return <>{display.toFixed(1)}</>;
  return <>{Math.round(display)}</>;
}

// Sparkline
function Sparkline({ data, color, className }: { data: number[]; color: string; className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || data.length < 2) return;
    const ctx = canvas.getContext("2d")!;
    const w = canvas.width, h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const max = Math.max(...data, 1);
    const step = w / (data.length - 1);

    // Fill
    ctx.beginPath();
    ctx.moveTo(0, h);
    data.forEach((v, i) => ctx.lineTo(i * step, h - (v / max) * h * 0.85));
    ctx.lineTo(w, h);
    ctx.closePath();
    ctx.fillStyle = color + "20";
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((v, i) => {
      const x = i * step, y = h - (v / max) * h * 0.85;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }, [data, color]);

  return <canvas ref={canvasRef} width={120} height={28} className={className} aria-hidden />;
}

// Metric Card
function MetricCard({
  label, value, unit, icon: Icon, color, trend, sparkData,
}: {
  label: string; value: number; unit: string;
  icon: typeof Activity; color: string;
  trend?: number; sparkData?: number[];
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-border bg-panel p-5 hover:border-border-bright transition-colors group">
      <div className="absolute top-0 left-0 right-0 h-0.5 opacity-60" style={{ background: color }} />
      <div className="flex items-start justify-between mb-3">
        <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">{label}</span>
        <Icon className="w-4 h-4 text-text-muted group-hover:text-text-secondary transition-colors" />
      </div>
      <div className="text-3xl font-semibold tracking-tight" style={{ color }}>
        <AnimatedValue value={value} format={typeof value === "number" && value < 100 && String(value).includes(".") ? "float" : "fmt"} />
      </div>
      <div className="flex items-center justify-between mt-1">
        <span className="text-[10px] font-mono text-text-muted">{unit}</span>
        {trend !== undefined && (
          <span className={`flex items-center gap-0.5 text-[10px] font-mono ${trend >= 0 ? "text-green" : "text-red"}`}>
            {trend >= 0 ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
            {Math.abs(trend).toFixed(1)}%
          </span>
        )}
      </div>
      {sparkData && sparkData.length > 1 && (
        <Sparkline data={sparkData} color={color} className="mt-2 opacity-70" />
      )}
    </div>
  );
}

interface Metrics {
  functions?: number;
  requests?: number;
  rps?: number;
  errorRate?: number;
  uptime?: number;
  workers?: { total?: number; busy?: number; queued?: number };
  bunVersion?: string;
  node?: string;
}

export default function OverviewPage() {
  const [data, setData] = useState<Metrics>({});
  const [loading, setLoading] = useState(true);
  const [history, setHistory] = useState<{ rps: number[]; err: number[]; wk: number[] }>({ rps: [], err: [], wk: [] });

  useEffect(() => {
    async function load() {
      const { ok, data: d } = await api<Metrics>("/_sovereign/metrics");
      if (ok && d) {
        setData(d);
        setHistory(prev => ({
          rps: [...prev.rps.slice(-29), d.rps ?? 0],
          err: [...prev.err.slice(-29), (d.errorRate ?? 0) * 100],
          wk: [...prev.wk.slice(-29), ((d.workers?.busy ?? 0) / Math.max(d.workers?.total ?? 1, 1)) * 100],
        }));
      }
      setLoading(false);
    }
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <div><h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1></div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-border bg-panel p-5">
              <div className="skeleton h-3 w-20 mb-4" />
              <div className="skeleton h-8 w-16 mb-2" />
              <div className="skeleton h-2 w-12" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const ws = data.workers ?? {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-text-muted font-mono mt-0.5">
            {data.node ?? "primary"} &middot; Bun {data.bunVersion ?? "?"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono bg-green/10 text-green border border-green/20">
            <span className="w-1.5 h-1.5 rounded-full bg-green shadow-[0_0_4px] shadow-green animate-pulse" />
            ONLINE
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        <MetricCard label="Functions" value={data.functions ?? 0} unit="deployed" icon={Blocks} color="#0df23b" />
        <MetricCard label="Requests" value={data.requests ?? 0} unit="total" icon={Activity} color="#00d4ff" sparkData={history.rps} />
        <MetricCard label="RPS" value={data.rps ?? 0} unit="req/sec" icon={TrendingUp} color="#00d4ff" sparkData={history.rps} />
        <MetricCard label="Error Rate" value={(data.errorRate ?? 0) * 100} unit="%" icon={AlertTriangle} color="#ff3b55" sparkData={history.err} />
        <MetricCard label="Uptime" value={(data.uptime ?? 0) / 3600} unit="hours" icon={Clock} color="#a855f7" />
        <MetricCard label="Workers" value={ws.total ?? 0} unit={`${ws.busy ?? 0} busy · ${ws.queued ?? 0} queued`} icon={Cpu} color="#ffcc00" sparkData={history.wk} />
      </div>

      {/* Chain Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChainPanel />
        <CompliancePanel />
      </div>
    </div>
  );
}

function ChainPanel() {
  const [stats, setStats] = useState<{ blocks?: number; events?: number; anchored?: number } | null>(null);
  useEffect(() => {
    api<typeof stats>("/_sovereign/chain/stats").then(r => r.ok && setStats(r.data));
  }, []);

  return (
    <div className="rounded-xl border border-border bg-panel">
      <div className="px-5 py-3 border-b border-border flex items-center gap-2">
        <Link2 className="w-4 h-4 text-cyan" />
        <span className="text-[10px] font-mono uppercase tracking-widest text-cyan">Audit Chain</span>
      </div>
      <div className="p-5 grid grid-cols-3 gap-4">
        <div>
          <div className="text-2xl font-semibold text-cyan">{fmt(stats?.blocks ?? 0)}</div>
          <div className="text-[10px] font-mono text-text-muted mt-0.5">Blocks</div>
        </div>
        <div>
          <div className="text-2xl font-semibold text-cyan">{fmt(stats?.events ?? 0)}</div>
          <div className="text-[10px] font-mono text-text-muted mt-0.5">Events</div>
        </div>
        <div>
          <div className="text-2xl font-semibold text-green">{fmt(stats?.anchored ?? 0)}</div>
          <div className="text-[10px] font-mono text-text-muted mt-0.5">Anchored</div>
        </div>
      </div>
    </div>
  );
}

function CompliancePanel() {
  const [report, setReport] = useState<{ score?: number; summary?: { pass: number; fail: number; warn: number } } | null>(null);
  useEffect(() => {
    api<typeof report>("/_sovereign/compliance/live").then(r => r.ok && setReport(r.data));
  }, []);

  const score = report?.score ?? 0;
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (score / 100) * circumference;
  const scoreColor = score >= 80 ? "#0df23b" : score >= 50 ? "#ffcc00" : "#ff3b55";

  return (
    <div className="rounded-xl border border-border bg-panel">
      <div className="px-5 py-3 border-b border-border flex items-center gap-2">
        <ShieldCheck className="w-4 h-4 text-green" />
        <span className="text-[10px] font-mono uppercase tracking-widest text-green">Compliance Score</span>
      </div>
      <div className="p-5 flex items-center gap-8">
        <div className="relative w-24 h-24">
          <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none" stroke="var(--color-border)" strokeWidth="6" />
            <circle cx="50" cy="50" r="42" fill="none" stroke={scoreColor} strokeWidth="6"
              strokeDasharray={circumference} strokeDashoffset={offset}
              strokeLinecap="round" className="transition-all duration-1000" />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center text-2xl font-semibold" style={{ color: scoreColor }}>
            {score}
          </div>
        </div>
        <div className="flex-1 space-y-2">
          {[
            { label: "Passing", value: report?.summary?.pass ?? 0, color: "bg-green" },
            { label: "Warning", value: report?.summary?.warn ?? 0, color: "bg-amber" },
            { label: "Failing",  value: report?.summary?.fail ?? 0, color: "bg-red" },
          ].map(row => (
            <div key={row.label} className="flex items-center gap-2 text-xs">
              <span className={`w-2 h-2 rounded-full ${row.color}`} />
              <span className="text-text-muted w-16">{row.label}</span>
              <span className="font-mono">{row.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
