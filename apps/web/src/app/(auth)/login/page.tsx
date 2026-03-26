"use client";

import { useState } from "react";
import { useStore } from "@/stores/config";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Loader2, ArrowRight, Key, Mail } from "lucide-react";
import { toast } from "sonner";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<"email" | "code">("email");
  const [code, setCode] = useState("");
  const { endpoint } = useStore();
  const router = useRouter();

  async function handleEmail(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${endpoint}/_sovereign/signin`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "sovereignly" },
        credentials: "include",
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (data.requiresCode) {
        setStep("code");
        toast.info("Check your email for a verification code");
      } else if (data.token) {
        // Cookie is set by backend; token in body is for API client compat
        toast.success("Signed in!");
        router.push("/overview");
      } else {
        toast.error(data.error || "Sign in failed");
      }
    } catch {
      toast.error("Cannot reach server");
    } finally {
      setLoading(false);
    }
  }

  async function handleCode(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${endpoint}/_sovereign/signin/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "sovereignly" },
        credentials: "include",
        body: JSON.stringify({ email, code }),
      });
      const data = await res.json();
      if (data.token) {
        toast.success("Signed in!");
        router.push("/overview");
      } else {
        toast.error(data.error || "Invalid code");
      }
    } catch {
      toast.error("Verification failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-xl border border-border bg-panel p-6">
      <h2 className="text-lg font-semibold mb-1">Sign in</h2>
      <p className="text-sm text-text-muted mb-6">Enter your email to continue</p>

      {step === "email" ? (
        <form onSubmit={handleEmail} className="space-y-4">
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
                autoFocus
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
            Continue
          </button>
        </form>
      ) : (
        <form onSubmit={handleCode} className="space-y-4">
          <p className="text-sm text-text-secondary">We sent a code to <strong className="text-text-primary">{email}</strong></p>
          <div>
            <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Verification Code</label>
            <div className="relative">
              <Key className="absolute left-3 top-2.5 w-4 h-4 text-text-muted" />
              <input
                type="text"
                value={code}
                onChange={e => setCode(e.target.value)}
                placeholder="000000"
                required
                autoFocus
                maxLength={6}
                className="w-full pl-10 pr-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono text-center tracking-[0.3em] focus:border-brand focus:ring-1 focus:ring-brand/20 outline-none transition-colors"
              />
            </div>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
            Verify
          </button>
          <button type="button" onClick={() => setStep("email")} className="w-full text-xs text-text-muted hover:text-text-primary transition-colors">
            Use a different email
          </button>
        </form>
      )}

      <div className="mt-4 text-center">
        <Link href="/signup" className="text-sm text-brand hover:text-brand-bright transition-colors">
          Create an account
        </Link>
      </div>
    </div>
  );
}
