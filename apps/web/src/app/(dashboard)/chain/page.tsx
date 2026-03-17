"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Link2, ShieldCheck, Hash, Clock } from "lucide-react";

export default function ChainPage() {
  const [stats, setStats] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    api("/_sovereign/chain/stats").then(r => r.ok && setStats(r.data));
    api<{ events: any[] }>("/_sovereign/chain/events?limit=20").then(r => r.ok && r.data && setEvents(r.data.events ?? []));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit Chain</h1>
        <p className="text-sm text-text-muted mt-0.5">Immutable, cryptographically signed event log</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Blocks", value: stats?.blocks ?? 0, icon: Hash, color: "text-cyan" },
          { label: "Events", value: stats?.events ?? 0, icon: Link2, color: "text-cyan" },
          { label: "Anchored", value: stats?.anchored ?? 0, icon: ShieldCheck, color: "text-green" },
          { label: "Critical", value: stats?.critical ?? 0, icon: Clock, color: "text-red" },
        ].map(s => (
          <div key={s.label} className="rounded-xl border border-border bg-panel p-4">
            <div className="flex items-center gap-2 mb-2">
              <s.icon className={`w-4 h-4 ${s.color}`} />
              <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">{s.label}</span>
            </div>
            <div className={`text-2xl font-semibold ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Recent Events */}
      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Link2 className="w-4 h-4 text-cyan" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-cyan">Recent Events</span>
        </div>
        <div className="divide-y divide-border/50">
          {events.length === 0 ? (
            <div className="py-12 text-center text-text-muted text-sm">No events yet</div>
          ) : events.map((ev: any) => (
            <div key={ev.id} className="px-5 py-3 flex items-center gap-4 hover:bg-surface/30 transition-colors">
              <span className={`w-2 h-2 rounded-full shrink-0 ${
                ev.severity === "CRITICAL" ? "bg-red shadow-[0_0_4px] shadow-red" :
                ev.severity === "HIGH" ? "bg-amber shadow-[0_0_4px] shadow-amber" :
                "bg-cyan shadow-[0_0_4px] shadow-cyan"
              }`} />
              <span className="font-mono text-xs text-cyan min-w-[140px]">{ev.type}</span>
              <span className="text-xs text-text-muted flex-1 truncate font-mono">{ev.id}</span>
              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                ev.severity === "CRITICAL" ? "bg-red/10 text-red" :
                ev.severity === "HIGH" ? "bg-amber/10 text-amber" :
                ev.severity === "MEDIUM" ? "bg-cyan/10 text-cyan" :
                "bg-surface text-text-muted"
              }`}>{ev.severity}</span>
              <span className="text-[10px] font-mono text-text-muted">{new Date(ev.ts).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
