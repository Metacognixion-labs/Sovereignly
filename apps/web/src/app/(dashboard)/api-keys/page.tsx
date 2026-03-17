"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Key, Plus, Copy, Trash2, Eye, EyeOff, Shield } from "lucide-react";

interface ApiKey { id: string; name: string; prefix: string; scope: string; createdAt: string; lastUsed: string }

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newScope, setNewScope] = useState("full");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);

  function createKey() {
    if (!newName) { toast.error("Name required"); return; }
    const keyValue = `sk_live_${crypto.randomUUID().replace(/-/g, "").slice(0, 32)}`;
    const key: ApiKey = {
      id: crypto.randomUUID().slice(0, 8),
      name: newName,
      prefix: keyValue.slice(0, 12) + "...",
      scope: newScope,
      createdAt: new Date().toISOString().slice(0, 10),
      lastUsed: "Never",
    };
    setKeys([key, ...keys]);
    setNewKey(keyValue);
    setNewName("");
    toast.success("API key created — copy it now, it won't be shown again");
  }

  function deleteKey(id: string) {
    if (!confirm("Revoke this API key? This cannot be undone.")) return;
    setKeys(keys.filter(k => k.id !== id));
    toast.success("API key revoked");
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">API Keys</h1>
          <p className="text-sm text-text-muted mt-0.5">Manage programmatic access to your project</p>
        </div>
        <button onClick={() => { setShowCreate(true); setNewKey(null); }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
          <Plus className="w-4 h-4" /> Create Key
        </button>
      </div>

      {/* Create Key Modal */}
      {showCreate && (
        <div className="rounded-xl border border-brand/30 bg-brand/5 p-5 space-y-4">
          {!newKey ? (
            <>
              <h3 className="font-medium">Create API Key</h3>
              <div>
                <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Key Name</label>
                <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Production API key"
                  autoFocus className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
              </div>
              <div>
                <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Scope</label>
                <select value={newScope} onChange={e => setNewScope(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none">
                  <option value="full">Full Access</option>
                  <option value="read">Read Only (events, chain, metrics)</option>
                  <option value="write">Write Only (emit events, deploy functions)</option>
                  <option value="deploy">Deploy Only (functions, KV)</option>
                </select>
              </div>
              <div className="flex gap-3">
                <button onClick={createKey} className="px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright">Create</button>
                <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-surface">Cancel</button>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2 text-brand">
                <Shield className="w-5 h-5" />
                <span className="font-medium">Key Created — Copy Now</span>
              </div>
              <p className="text-xs text-text-muted">This key will not be shown again. Store it securely.</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 px-3 py-2.5 rounded-lg bg-surface border border-border text-xs font-mono break-all">
                  {showKey ? newKey : newKey.slice(0, 12) + "•".repeat(24)}
                </code>
                <button onClick={() => setShowKey(!showKey)} className="p-2 rounded-lg border border-border hover:bg-surface">
                  {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button onClick={() => { navigator.clipboard.writeText(newKey); toast.info("Copied!"); }}
                  className="p-2 rounded-lg border border-border hover:bg-surface">
                  <Copy className="w-4 h-4" />
                </button>
              </div>
              <button onClick={() => setShowCreate(false)} className="w-full py-2 rounded-lg border border-border text-sm hover:bg-surface">Done</button>
            </>
          )}
        </div>
      )}

      {/* Keys List */}
      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Key className="w-4 h-4 text-text-muted" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Active Keys</span>
        </div>
        {keys.length === 0 ? (
          <div className="p-12 text-center text-text-muted">
            <Key className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <div className="text-sm">No API keys yet</div>
            <button onClick={() => { setShowCreate(true); setNewKey(null); }}
              className="mt-2 text-brand hover:text-brand-bright text-sm">Create your first key →</button>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {keys.map(k => (
              <div key={k.id} className="px-5 py-4 flex items-center justify-between hover:bg-surface/30 transition-colors">
                <div>
                  <div className="text-sm font-medium">{k.name}</div>
                  <div className="flex items-center gap-3 mt-1 text-[10px] text-text-muted font-mono">
                    <span>{k.prefix}</span>
                    <span className="px-1.5 py-0.5 rounded bg-surface border border-border">{k.scope}</span>
                    <span>Created {k.createdAt}</span>
                    <span>Last used: {k.lastUsed}</span>
                  </div>
                </div>
                <button onClick={() => deleteKey(k.id)} className="p-1.5 rounded hover:bg-red/10">
                  <Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Usage Info */}
      <div className="rounded-xl border border-border bg-panel p-5 text-xs text-text-muted">
        <h3 className="font-mono uppercase tracking-widest mb-2">SDK Usage</h3>
        <pre className="bg-[#0a0e14] rounded-lg p-4 font-mono text-[11px] leading-relaxed overflow-x-auto text-text-secondary">
{`import { SovereignChain } from '@metacognixion/chain-sdk';

const chain = new SovereignChain({
  endpoint: 'https://sovereignly.fly.dev',
  orgId:    'your-org-id',
  apiKey:   'sk_live_...',  // your API key
});

await chain.emit('USER_LOGIN', { userId: 'u1' });`}
        </pre>
      </div>
    </div>
  );
}
