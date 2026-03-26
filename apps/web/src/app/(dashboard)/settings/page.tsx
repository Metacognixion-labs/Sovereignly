"use client";

import { useState } from "react";
import { useStore } from "@/stores/config";
import { toast } from "sonner";
import { Settings, Save, Trash2, ExternalLink, LogOut } from "lucide-react";
import { api } from "@/lib/api";

export default function SettingsPage() {
  const { endpoint, setEndpoint, clear } = useStore();
  const [url, setUrl] = useState(endpoint);

  async function save() {
    setEndpoint(url);
    try {
      const res = await fetch(`${url}/_sovereign/health`, { signal: AbortSignal.timeout(5000) });
      if (res.ok) toast.success("Connected to " + (url || "local server"));
      else toast.error("Server responded with " + res.status);
    } catch {
      toast.error("Cannot reach server at " + (url || "current origin"));
    }
  }

  async function logout() {
    await api("/_sovereign/auth/logout", { method: "POST" });
    clear();
    toast.info("Signed out");
    window.location.href = "/login";
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-text-muted mt-0.5">Configure your Sovereignly connection</p>
      </div>

      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border">
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Connection</span>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Server URL</label>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="Leave blank for same-origin"
              className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand focus:ring-1 focus:ring-brand/20 outline-none transition-colors"
            />
            <p className="text-[10px] text-text-muted mt-1">Leave empty if dashboard is served from the same server</p>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <button onClick={save} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
              <Save className="w-4 h-4" /> Save & Test
            </button>
            <button onClick={logout}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-sm text-text-muted hover:text-red hover:border-red/30 transition-colors">
              <LogOut className="w-4 h-4" /> Sign Out
            </button>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border">
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">About</span>
        </div>
        <div className="p-5 space-y-2 text-sm font-mono text-text-secondary">
          <div className="flex justify-between"><span className="text-text-muted">Product</span><span>Sovereignly v4.0.0</span></div>
          <div className="flex justify-between"><span className="text-text-muted">Runtime</span><span>Bun + Hono</span></div>
          <div className="flex justify-between"><span className="text-text-muted">Database</span><span>SQLite (bun:sqlite)</span></div>
          <div className="flex justify-between"><span className="text-text-muted">License</span><span>MIT (OSS) / BSL 1.1 (Cloud)</span></div>
          <div className="flex justify-between">
            <span className="text-text-muted">Source</span>
            <a href="https://github.com/Metacognixion-labs/Sovereignly" target="_blank" rel="noopener"
              className="flex items-center gap-1 text-brand hover:text-brand-bright transition-colors">
              GitHub <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
