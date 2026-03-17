"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard, Blocks, Link2, ShieldCheck, ScrollText,
  Database, Settings, Activity, Coins, Cpu, Globe,
  Search, ChevronRight,
} from "lucide-react";
import { useState, useEffect, useCallback } from "react";

const NAV = [
  { section: "Overview" },
  { label: "Dashboard",   href: "/overview",   icon: LayoutDashboard },
  { label: "Functions",   href: "/functions",  icon: Blocks },
  { label: "Chain",       href: "/chain",      icon: Link2 },

  { section: "Data" },
  { label: "KV Store",    href: "/kv",         icon: Database },

  { section: "Observability" },
  { label: "Logs",        href: "/logs",       icon: ScrollText },
  { label: "Compliance",  href: "/compliance", icon: ShieldCheck },

  { section: "System" },
  { label: "Settings",    href: "/settings",   icon: Settings },
] as const;

// Connection status indicator
function ConnectionStatus() {
  const [status, setStatus] = useState<"connected"|"reconnecting"|"offline">("offline");

  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource("/_sovereign/chain/stream");
      es.onopen = () => setStatus("connected");
      es.onerror = () => setStatus("reconnecting");
    } catch { setStatus("offline"); }
    return () => es?.close();
  }, []);

  return (
    <div className={cn(
      "flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono",
      status === "connected" && "bg-green/10 text-green border border-green/20",
      status === "reconnecting" && "bg-amber/10 text-amber border border-amber/20 animate-pulse",
      status === "offline" && "bg-red/10 text-red border border-red/20",
    )}>
      <span className={cn("w-1.5 h-1.5 rounded-full",
        status === "connected" && "bg-green shadow-[0_0_4px] shadow-green",
        status === "reconnecting" && "bg-amber",
        status === "offline" && "bg-red",
      )} />
      {status === "connected" ? "Live" : status === "reconnecting" ? "Reconnecting" : "Offline"}
    </div>
  );
}

// Command palette
function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const filtered = (NAV.filter((n): n is Extract<typeof n, {label: string}> => "label" in n))
    .filter(n => n.label.toLowerCase().includes(query.toLowerCase()));

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-start justify-center pt-[18vh]" onClick={onClose}>
      <div className="w-full max-w-lg bg-panel border border-border-bright rounded-xl shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 px-4 border-b border-border">
          <Search className="w-4 h-4 text-text-muted" />
          <input
            autoFocus
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search pages..."
            className="flex-1 py-3 bg-transparent text-sm outline-none placeholder:text-text-muted"
          />
          <kbd className="text-[10px] font-mono text-text-muted bg-surface px-1.5 py-0.5 rounded border border-border">ESC</kbd>
        </div>
        <div className="p-1.5 max-h-72 overflow-y-auto">
          {filtered.map(n => (
            <Link
              key={n.href}
              href={n.href}
              onClick={onClose}
              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm hover:bg-brand/10 hover:text-brand transition-colors"
            >
              <n.icon className="w-4 h-4 text-text-muted" />
              {n.label}
              <ChevronRight className="w-3 h-3 text-text-muted ml-auto" />
            </Link>
          ))}
          {filtered.length === 0 && <p className="text-center text-text-muted text-xs py-6">No results</p>}
        </div>
      </div>
    </div>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [cmdOpen, setCmdOpen] = useState(false);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setCmdOpen(true); }
    if (e.key === "Escape") setCmdOpen(false);
  }, []);

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  return (
    <div className="flex h-screen overflow-hidden">
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />

      {/* Sidebar */}
      <aside className="w-56 shrink-0 border-r border-border bg-surface/80 flex flex-col overflow-y-auto">
        {/* Logo */}
        <div className="px-4 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-brand/15 border border-brand/25 flex items-center justify-center">
              <Globe className="w-4 h-4 text-brand" />
            </div>
            <div>
              <div className="text-xs font-semibold tracking-wider text-brand">SOVEREIGNLY</div>
              <div className="text-[9px] font-mono text-text-muted">v4.0.0</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-2 px-2" aria-label="Main navigation">
          {NAV.map((item, i) => {
            if ("section" in item) {
              return <div key={i} className="px-3 pt-5 pb-1 text-[9px] font-mono uppercase tracking-[0.15em] text-text-muted">{item.section}</div>;
            }
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] transition-all my-0.5",
                  active
                    ? "bg-brand/10 text-brand border border-brand/15"
                    : "text-text-secondary hover:bg-surface hover:text-text-primary border border-transparent"
                )}
                aria-current={active ? "page" : undefined}
              >
                <item.icon className="w-4 h-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Bottom */}
        <div className="p-3 border-t border-border">
          <button
            onClick={() => setCmdOpen(true)}
            className="w-full flex items-center gap-2 px-3 py-1.5 rounded-md text-xs text-text-muted hover:text-text-primary hover:bg-surface transition-colors border border-border"
          >
            <Search className="w-3 h-3" />
            <span>Search</span>
            <kbd className="ml-auto text-[9px] font-mono bg-surface px-1 rounded border border-border">⌘K</kbd>
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="h-12 shrink-0 border-b border-border bg-surface/60 backdrop-blur-md flex items-center px-5 gap-3">
          <div className="flex-1" />
          <ConnectionStatus />
          <div className="font-mono text-[10px] text-text-muted px-2 py-0.5 border border-border rounded">
            <Cpu className="w-3 h-3 inline mr-1" />Bun Runtime
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto p-6" id="main-content">
          {children}
        </main>
      </div>
    </div>
  );
}
