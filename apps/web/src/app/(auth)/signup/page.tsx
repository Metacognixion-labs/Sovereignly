"use client";

import { useState } from "react";
import { useStore } from "@/stores/config";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Loader2, ArrowRight, Building2, Mail } from "lucide-react";
import { toast } from "sonner";

export default function SignupPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const { setJwtToken, endpoint } = useStore();
  const router = useRouter();

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${endpoint}/_sovereign/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email }),
      });
      const data = await res.json();
      if (data.ok && data.token) {
        setJwtToken(data.token);
        toast.success(`Welcome! Tenant "${data.tenant.name}" created.`);
        router.push("/overview");
      } else {
        toast.error(data.error || "Signup failed");
      }
    } catch {
      toast.error("Cannot reach server");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-xl border border-border bg-panel p-6">
      <h2 className="text-lg font-semibold mb-1">Create account</h2>
      <p className="text-sm text-text-muted mb-6">Start with the free tier — no credit card required</p>

      <form onSubmit={handleSignup} className="space-y-4">
        <div>
          <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Organization Name</label>
          <div className="relative">
            <Building2 className="absolute left-3 top-2.5 w-4 h-4 text-text-muted" />
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="My Company"
              required
              autoFocus
              className="w-full pl-10 pr-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand focus:ring-1 focus:ring-brand/20 outline-none transition-colors"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Email</label>
          <div className="relative">
            <Mail className="absolute left-3 top-2.5 w-4 h-4 text-text-muted" />
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="you@company.com"
              required
              className="w-full pl-10 pr-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand focus:ring-1 focus:ring-brand/20 outline-none transition-colors"
            />
          </div>
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors disabled:opacity-50"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
          Create Free Account
        </button>
      </form>

      <div className="mt-4 text-center text-[10px] text-text-muted font-mono">
        Free: 10K events/mo · 3 functions · 0.5GB storage
      </div>

      <div className="mt-6 pt-4 border-t border-border text-center">
        <Link href="/login" className="text-sm text-brand hover:text-brand-bright transition-colors">
          Already have an account? Sign in
        </Link>
      </div>
    </div>
  );
}
