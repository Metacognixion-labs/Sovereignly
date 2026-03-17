"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Blocks, Plus, Trash2, Play, ExternalLink } from "lucide-react";

interface FnEntry {
  id: string; route: string; methods: string[];
  invocations: number; avgMs: number; p95Ms: number; errors: number;
}

export default function FunctionsPage() {
  const [fns, setFns] = useState<FnEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<FnEntry[]>("/_sovereign/functions").then(r => {
      if (r.ok && r.data) setFns(r.data);
      setLoading(false);
    });
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Functions</h1>
          <p className="text-sm text-text-muted mt-0.5">{fns.length} deployed</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
          <Plus className="w-4 h-4" /> Deploy Function
        </button>
      </div>

      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-[10px] font-mono uppercase tracking-widest text-text-muted">
              <th className="text-left px-5 py-3">ID</th>
              <th className="text-left px-5 py-3">Route</th>
              <th className="text-left px-5 py-3">Methods</th>
              <th className="text-right px-5 py-3">Invocations</th>
              <th className="text-right px-5 py-3">Avg</th>
              <th className="text-right px-5 py-3">P95</th>
              <th className="text-right px-5 py-3">Errors</th>
              <th className="text-right px-5 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 3 }).map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {Array.from({ length: 8 }).map((_, j) => (
                    <td key={j} className="px-5 py-3"><div className="skeleton h-4 w-16" /></td>
                  ))}
                </tr>
              ))
            ) : fns.length === 0 ? (
              <tr><td colSpan={8} className="text-center py-12 text-text-muted">
                <Blocks className="w-8 h-8 mx-auto mb-2 opacity-30" />
                No functions deployed yet
              </td></tr>
            ) : (
              fns.map(fn => (
                <tr key={fn.id} className="border-b border-border/50 hover:bg-surface/50 transition-colors">
                  <td className="px-5 py-3 font-mono text-cyan text-xs">{fn.id}</td>
                  <td className="px-5 py-3 font-mono text-xs">{fn.route}</td>
                  <td className="px-5 py-3">
                    {fn.methods.map(m => (
                      <span key={m} className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-mono font-bold mr-1 ${
                        m === "GET" ? "bg-green/10 text-green border border-green/20" :
                        m === "POST" ? "bg-cyan/10 text-cyan border border-cyan/20" :
                        m === "PUT" ? "bg-amber/10 text-amber border border-amber/20" :
                        "bg-red/10 text-red border border-red/20"
                      }`}>{m}</span>
                    ))}
                  </td>
                  <td className="px-5 py-3 text-right font-mono text-xs">{fn.invocations}</td>
                  <td className="px-5 py-3 text-right font-mono text-xs text-amber">{fn.avgMs.toFixed(1)}ms</td>
                  <td className="px-5 py-3 text-right font-mono text-xs text-violet">{fn.p95Ms.toFixed(1)}ms</td>
                  <td className="px-5 py-3 text-right font-mono text-xs">
                    {fn.errors > 0 ? <span className="text-red">{fn.errors}</span> : <span className="text-green">0</span>}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button className="p-1 rounded hover:bg-surface" title="Test"><Play className="w-3.5 h-3.5 text-text-muted" /></button>
                      <button className="p-1 rounded hover:bg-red/10" title="Delete"><Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" /></button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
