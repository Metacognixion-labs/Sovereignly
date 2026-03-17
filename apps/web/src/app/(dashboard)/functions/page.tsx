"use client";

import { useEffect, useState, useRef } from "react";
import { api } from "@/lib/api";
import { Blocks, Plus, Trash2, Play, X, Loader2, Rocket, CheckCircle, Code2, Globe } from "lucide-react";
import { toast } from "sonner";

interface FnEntry {
  id: string; route: string; methods: string[];
  invocations: number; avgMs: number; p95Ms: number; errors: number;
}

const TEMPLATES = [
  { name: "Hello World", id: "hello", route: "/hello", methods: ["GET"],
    code: `// Hello World function\nasync function handler(req, env) {\n  return Response.json({\n    message: "Hello from Sovereignly!",\n    ts: Date.now(),\n  });\n}` },
  { name: "Echo", id: "echo", route: "/echo", methods: ["GET", "POST"],
    code: `// Echo — returns request details\nasync function handler(req, env) {\n  const body = req.method !== "GET" ? await req.text() : null;\n  return Response.json({\n    method: req.method,\n    url: req.url,\n    headers: Object.fromEntries(req.headers),\n    body,\n  });\n}` },
  { name: "KV Counter", id: "counter", route: "/counter", methods: ["GET", "POST"],
    code: `// Persistent counter using KV store\nasync function handler(req, env) {\n  if (req.method === "POST") {\n    const count = KV.incr("visits");\n    return Response.json({ count, action: "incremented" });\n  }\n  const count = KV.get("visits") ?? 0;\n  return Response.json({ count });\n}` },
  { name: "Webhook Receiver", id: "webhook", route: "/webhook", methods: ["POST"],
    code: `// Webhook receiver — logs payload to KV\nasync function handler(req, env) {\n  const body = await req.json();\n  const id = crypto.randomUUID().slice(0, 8);\n  KV.set(\`webhook:\${id}\`, JSON.stringify(body));\n  return Response.json({ received: id, ts: Date.now() });\n}` },
];

// Deploy Modal
function DeployModal({ open, onClose, onDeployed }: { open: boolean; onClose: () => void; onDeployed: () => void }) {
  const [step, setStep] = useState<"template" | "configure" | "deploying" | "done">("template");
  const [selected, setSelected] = useState<typeof TEMPLATES[0] | null>(null);
  const [id, setId] = useState("");
  const [route, setRoute] = useState("");
  const [methods, setMethods] = useState("GET");
  const [code, setCode] = useState("");
  const [timeout, setTimeout_] = useState(30000);
  const codeRef = useRef<HTMLTextAreaElement>(null);

  function selectTemplate(t: typeof TEMPLATES[0]) {
    setSelected(t);
    setId(t.id);
    setRoute(t.route);
    setMethods(t.methods.join(","));
    setCode(t.code);
    setStep("configure");
  }

  function startBlank() {
    setSelected(null);
    setId("");
    setRoute("/");
    setMethods("GET");
    setCode('async function handler(req, env) {\n  return Response.json({ ok: true });\n}');
    setStep("configure");
  }

  async function deploy() {
    if (!id || !route || !code) { toast.error("ID, route, and code are required"); return; }
    setStep("deploying");

    const { ok, data } = await api("/_sovereign/functions", {
      method: "POST",
      body: JSON.stringify({
        id, name: id, route,
        methods: methods.split(",").map(m => m.trim().toUpperCase()),
        code, timeoutMs: timeout,
      }),
    });

    if (ok) {
      setStep("done");
      toast.success(`Deployed ${id} → ${route}`);
      onDeployed();
    } else {
      setStep("configure");
      toast.error((data as any)?.error ?? "Deploy failed");
    }
  }

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="w-full max-w-2xl bg-panel border border-border-bright rounded-xl shadow-2xl max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <div className="flex items-center gap-3">
            <Rocket className="w-5 h-5 text-brand" />
            <h2 className="text-lg font-semibold">Deploy Function</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-surface"><X className="w-5 h-5 text-text-muted" /></button>
        </div>

        {/* Step: Template Selection */}
        {step === "template" && (
          <div className="p-6 space-y-4">
            <p className="text-sm text-text-muted">Choose a template or start from scratch</p>
            <div className="grid grid-cols-2 gap-3">
              {TEMPLATES.map(t => (
                <button key={t.id} onClick={() => selectTemplate(t)}
                  className="text-left rounded-lg border border-border p-4 hover:border-brand/40 hover:bg-brand/5 transition-all group">
                  <div className="font-medium text-sm group-hover:text-brand transition-colors">{t.name}</div>
                  <div className="text-xs text-text-muted font-mono mt-1">{t.route} · {t.methods.join(", ")}</div>
                </button>
              ))}
            </div>
            <button onClick={startBlank}
              className="w-full rounded-lg border border-dashed border-border p-4 text-sm text-text-muted hover:border-brand/40 hover:text-brand transition-all">
              <Code2 className="w-4 h-4 inline mr-2" /> Start from blank
            </button>
          </div>
        )}

        {/* Step: Configure */}
        {step === "configure" && (
          <div className="p-6 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Function ID</label>
                <input value={id} onChange={e => setId(e.target.value)} placeholder="my-function"
                  className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Route</label>
                <input value={route} onChange={e => setRoute(e.target.value)} placeholder="/api/hello"
                  className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Methods</label>
                <input value={methods} onChange={e => setMethods(e.target.value)} placeholder="GET,POST"
                  className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Timeout (ms)</label>
                <input type="number" value={timeout} onChange={e => setTimeout_(parseInt(e.target.value) || 30000)}
                  className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Code</label>
              <textarea ref={codeRef} value={code} onChange={e => setCode(e.target.value)} rows={12}
                className="w-full px-4 py-3 rounded-lg bg-[#0a0e14] border border-border text-sm font-mono text-cyan leading-relaxed focus:border-brand outline-none resize-y"
                spellCheck={false} />
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button onClick={() => setStep("template")} className="px-4 py-2 rounded-lg border border-border text-sm text-text-muted hover:text-text-primary transition-colors">
                Back
              </button>
              <button onClick={deploy}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
                <Rocket className="w-4 h-4" /> Deploy Function
              </button>
            </div>
          </div>
        )}

        {/* Step: Deploying */}
        {step === "deploying" && (
          <div className="p-12 flex flex-col items-center justify-center text-center">
            <Loader2 className="w-10 h-10 text-brand animate-spin mb-4" />
            <div className="font-medium">Deploying {id}...</div>
            <div className="text-xs text-text-muted mt-1 font-mono">Scanning code → Isolating worker → Registering route</div>
          </div>
        )}

        {/* Step: Done */}
        {step === "done" && (
          <div className="p-12 flex flex-col items-center justify-center text-center">
            <CheckCircle className="w-10 h-10 text-green mb-4" />
            <div className="font-medium text-green">Deployed!</div>
            <div className="mt-3 flex items-center gap-2 px-4 py-2 rounded-lg bg-surface border border-border font-mono text-sm">
              <Globe className="w-4 h-4 text-text-muted" />
              {route}
            </div>
            <div className="mt-2 text-xs text-text-muted font-mono">
              curl http://localhost:8787{route}
            </div>
            <button onClick={() => { onClose(); setStep("template"); }}
              className="mt-6 px-6 py-2 rounded-lg border border-border text-sm hover:bg-surface transition-colors">
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function FunctionsPage() {
  const [fns, setFns] = useState<FnEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [deployOpen, setDeployOpen] = useState(false);

  function loadFns() {
    api<FnEntry[]>("/_sovereign/functions").then(r => {
      if (r.ok && r.data) setFns(r.data);
      setLoading(false);
    });
  }

  useEffect(() => { loadFns(); }, []);

  async function deleteFn(id: string) {
    if (!confirm(`Delete function "${id}"?`)) return;
    const { ok } = await api(`/_sovereign/functions/${id}`, { method: "DELETE" });
    if (ok) { toast.success(`Deleted ${id}`); loadFns(); }
    else toast.error("Delete failed");
  }

  async function testFn(route: string) {
    toast.info(`Testing ${route}...`);
    const { ok, data } = await api(route);
    if (ok) toast.success(`${route} → 200 OK`);
    else toast.error(`${route} → failed`);
  }

  return (
    <div className="space-y-6">
      <DeployModal open={deployOpen} onClose={() => setDeployOpen(false)} onDeployed={loadFns} />

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Functions</h1>
          <p className="text-sm text-text-muted mt-0.5">{fns.length} deployed</p>
        </div>
        <button onClick={() => setDeployOpen(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
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
                <div>No functions deployed yet</div>
                <button onClick={() => setDeployOpen(true)}
                  className="mt-3 text-brand hover:text-brand-bright text-sm transition-colors">
                  Deploy your first function →
                </button>
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
                      <button onClick={() => testFn(fn.route)} className="p-1.5 rounded hover:bg-surface" title="Test">
                        <Play className="w-3.5 h-3.5 text-text-muted hover:text-green" />
                      </button>
                      <button onClick={() => deleteFn(fn.id)} className="p-1.5 rounded hover:bg-red/10" title="Delete">
                        <Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" />
                      </button>
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
