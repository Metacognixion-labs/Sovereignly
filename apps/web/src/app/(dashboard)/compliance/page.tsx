"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ShieldCheck, CheckCircle, XCircle, AlertTriangle } from "lucide-react";

interface ControlResult {
  id: string; name: string; framework: string; reference: string;
  status: "pass" | "fail" | "warn" | "skip"; score: number; evidence: string;
}

export default function CompliancePage() {
  const [report, setReport] = useState<{ score: number; controls: ControlResult[]; summary: { pass: number; fail: number; warn: number } } | null>(null);

  useEffect(() => {
    api<typeof report>("/_sovereign/compliance/live").then(r => r.ok && setReport(r.data));
  }, []);

  const score = report?.score ?? 0;
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;
  const scoreColor = score >= 80 ? "#0df23b" : score >= 50 ? "#ffcc00" : "#ff3b55";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Compliance</h1>
        <p className="text-sm text-text-muted mt-0.5">Real-time control evaluation (SOC2, ISO 27001)</p>
      </div>

      {/* Score + Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="rounded-xl border border-border bg-panel p-6 flex flex-col items-center justify-center">
          <div className="relative w-32 h-32 mb-3">
            <svg className="w-32 h-32 -rotate-90" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="54" fill="none" stroke="var(--color-border)" strokeWidth="8" />
              <circle cx="60" cy="60" r="54" fill="none" stroke={scoreColor} strokeWidth="8"
                strokeDasharray={circumference} strokeDashoffset={offset}
                strokeLinecap="round" className="transition-all duration-1000" />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <div className="text-4xl font-bold" style={{ color: scoreColor }}>{score}</div>
              <div className="text-[9px] font-mono text-text-muted uppercase tracking-widest">Score</div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 rounded-xl border border-border bg-panel p-6">
          <h3 className="text-xs font-mono uppercase tracking-widest text-text-muted mb-4">Control Summary</h3>
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: "Passing", value: report?.summary?.pass ?? 0, icon: CheckCircle, color: "text-green", bg: "bg-green/10" },
              { label: "Warning", value: report?.summary?.warn ?? 0, icon: AlertTriangle, color: "text-amber", bg: "bg-amber/10" },
              { label: "Failing", value: report?.summary?.fail ?? 0, icon: XCircle, color: "text-red", bg: "bg-red/10" },
            ].map(s => (
              <div key={s.label} className={`${s.bg} rounded-lg p-4 flex items-center gap-3`}>
                <s.icon className={`w-6 h-6 ${s.color}`} />
                <div>
                  <div className={`text-2xl font-semibold ${s.color}`}>{s.value}</div>
                  <div className="text-[10px] font-mono text-text-muted">{s.label}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Control List */}
      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <div className="px-5 py-3 border-b border-border">
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Controls</span>
        </div>
        <div className="divide-y divide-border/50">
          {(report?.controls ?? []).map(ctrl => (
            <div key={ctrl.id} className="px-5 py-4 flex items-start gap-4 hover:bg-surface/30 transition-colors">
              <span className={`w-2.5 h-2.5 rounded-full mt-1 shrink-0 ${
                ctrl.status === "pass" ? "bg-green shadow-[0_0_4px] shadow-green" :
                ctrl.status === "fail" ? "bg-red shadow-[0_0_4px] shadow-red" :
                "bg-amber shadow-[0_0_4px] shadow-amber"
              }`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm">{ctrl.name}</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface text-text-muted">{ctrl.framework} {ctrl.reference}</span>
                </div>
                <p className="text-xs text-text-muted mt-1 font-mono">{ctrl.evidence}</p>
              </div>
              <div className="text-right shrink-0">
                <div className={`text-lg font-semibold ${
                  ctrl.score >= 80 ? "text-green" : ctrl.score >= 50 ? "text-amber" : "text-red"
                }`}>{ctrl.score}</div>
                <div className="text-[9px] font-mono text-text-muted">/ 100</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
