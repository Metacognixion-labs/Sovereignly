"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Database, Plus } from "lucide-react";
import { fmt } from "@/lib/utils";

export default function KVPage() {
  const [namespaces, setNamespaces] = useState<Array<{ namespace: string; keyCount: number; sizeBytes: number }>>([]);

  useEffect(() => {
    api<{ kv?: typeof namespaces }>("/_sovereign/metrics").then(r => {
      if (r.ok && r.data?.kv) setNamespaces(r.data.kv);
    });
  }, []);

  const totalKeys = namespaces.reduce((s, n) => s + n.keyCount, 0);
  const totalSize = namespaces.reduce((s, n) => s + n.sizeBytes, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">KV Store</h1>
          <p className="text-sm text-text-muted mt-0.5">{fmt(totalKeys)} keys across {namespaces.length} namespaces</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
          <Plus className="w-4 h-4" /> New Key
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-border bg-panel p-5">
          <div className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-2">Total Keys</div>
          <div className="text-3xl font-semibold text-cyan">{fmt(totalKeys)}</div>
        </div>
        <div className="rounded-xl border border-border bg-panel p-5">
          <div className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-2">Storage</div>
          <div className="text-3xl font-semibold text-violet">{(totalSize / 1024).toFixed(1)} KB</div>
        </div>
        <div className="rounded-xl border border-border bg-panel p-5">
          <div className="text-[10px] font-mono uppercase tracking-widest text-text-muted mb-2">Namespaces</div>
          <div className="text-3xl font-semibold text-green">{namespaces.length}</div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <div className="px-5 py-3 border-b border-border">
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Namespaces</span>
        </div>
        <div className="divide-y divide-border/50">
          {namespaces.length === 0 ? (
            <div className="py-12 text-center text-text-muted text-sm">
              <Database className="w-8 h-8 mx-auto mb-2 opacity-30" />
              No namespaces yet
            </div>
          ) : namespaces.map(ns => (
            <div key={ns.namespace} className="px-5 py-4 flex items-center justify-between hover:bg-surface/30 transition-colors">
              <div className="flex items-center gap-3">
                <Database className="w-4 h-4 text-cyan" />
                <span className="font-mono text-sm text-cyan">{ns.namespace}</span>
              </div>
              <div className="flex items-center gap-6 text-xs font-mono text-text-muted">
                <span>{fmt(ns.keyCount)} keys</span>
                <span>{(ns.sizeBytes / 1024).toFixed(1)} KB</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
