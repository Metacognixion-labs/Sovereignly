"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import {
  User, Mail, Shield, ShieldCheck, ShieldOff, Key, Loader2,
  Copy, Eye, EyeOff, Smartphone, QrCode, CheckCircle,
} from "lucide-react";

interface UserProfile {
  id: string; email?: string; displayName: string; role: string;
  plan: string; authMethods: string[]; createdAt: number; lastSeenAt: number;
}

interface TOTPStatus { enabled: boolean; remainingBackupCodes?: number }

export default function AccountPage() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [totp, setTotp] = useState<TOTPStatus | null>(null);
  const [loading, setLoading] = useState(true);

  // 2FA setup state
  const [setupStep, setSetupStep] = useState<"idle" | "setup" | "confirm" | "done">("idle");
  const [totpSecret, setTotpSecret] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [confirmCode, setConfirmCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [showBackup, setShowBackup] = useState(false);
  const [disableCode, setDisableCode] = useState("");

  useEffect(() => {
    Promise.all([
      api<{ user: UserProfile }>("/_sovereign/auth/me").then(r => r.ok && r.data ? setUser(r.data.user) : null),
      api<TOTPStatus>("/_sovereign/auth/totp/status").then(r => r.ok && r.data ? setTotp(r.data) : null),
    ]).finally(() => setLoading(false));
  }, []);

  async function setupTOTP() {
    setSetupStep("setup");
    const { ok, data } = await api<{ secret: string; otpauthUri: string }>("/_sovereign/auth/totp/setup", { method: "POST" });
    if (ok && data) {
      setTotpSecret(data.secret);
      setTotpUri(data.otpauthUri);
      setSetupStep("confirm");
    } else {
      toast.error("Failed to initialize 2FA setup");
      setSetupStep("idle");
    }
  }

  async function confirmTOTP() {
    if (!confirmCode || confirmCode.length < 6) { toast.error("Enter the 6-digit code"); return; }
    const { ok, data } = await api<{ ok: boolean; backupCodes: string[] }>("/_sovereign/auth/totp/confirm", {
      method: "POST", body: JSON.stringify({ code: confirmCode }),
    });
    if (ok && data?.ok) {
      setBackupCodes(data.backupCodes);
      setTotp({ enabled: true, remainingBackupCodes: data.backupCodes.length });
      setSetupStep("done");
      toast.success("2FA enabled!");
    } else {
      toast.error("Invalid code — try again");
    }
  }

  async function disableTOTP() {
    if (!disableCode) { toast.error("Enter your authenticator code to disable"); return; }
    const { ok } = await api("/_sovereign/auth/totp/disable", {
      method: "POST", body: JSON.stringify({ code: disableCode }),
    });
    if (ok) {
      setTotp({ enabled: false });
      setDisableCode("");
      toast.success("2FA disabled");
    } else {
      toast.error("Invalid code");
    }
  }

  if (loading) return <div className="space-y-4">{[1,2,3].map(i => <div key={i} className="skeleton h-32 rounded-xl" />)}</div>;

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Account</h1>
        <p className="text-sm text-text-muted mt-0.5">Manage your profile and security</p>
      </div>

      {/* Profile */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <User className="w-4 h-4 text-blue" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-blue">Profile</span>
        </div>
        <div className="p-5 space-y-3 text-sm">
          <div className="flex justify-between items-center">
            <span className="text-text-muted">Email</span>
            <span className="font-mono flex items-center gap-2">
              <Mail className="w-3.5 h-3.5 text-text-muted" />
              {user?.email ?? "Not set"}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-text-muted">Display Name</span>
            <span className="font-mono">{user?.displayName ?? "—"}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-text-muted">Role</span>
            <span className={`font-mono text-xs px-2 py-0.5 rounded ${
              user?.role === "admin" ? "bg-red/10 text-red border border-red/20" :
              user?.role === "owner" ? "bg-brand/10 text-brand border border-brand/20" :
              "bg-surface text-text-muted border border-border"
            }`}>{user?.role ?? "—"}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-text-muted">Plan</span>
            <span className="font-mono text-brand">{user?.plan ?? "free"}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-text-muted">Auth Methods</span>
            <div className="flex gap-1.5">
              {(user?.authMethods ?? []).map(m => (
                <span key={m} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface border border-border">{m}</span>
              ))}
            </div>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-text-muted">Member since</span>
            <span className="font-mono text-xs">{user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : "—"}</span>
          </div>
        </div>
      </div>

      {/* 2FA / TOTP */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-brand" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Two-Factor Authentication</span>
          </div>
          {totp?.enabled && (
            <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-brand/10 text-brand border border-brand/20">
              <ShieldCheck className="w-3 h-3" /> Enabled
            </span>
          )}
        </div>
        <div className="p-5">
          {/* Not enabled */}
          {!totp?.enabled && setupStep === "idle" && (
            <div className="text-center py-4">
              <ShieldOff className="w-10 h-10 text-text-muted mx-auto mb-3 opacity-40" />
              <p className="text-sm text-text-muted mb-4">Add an extra layer of security with an authenticator app</p>
              <button onClick={setupTOTP}
                className="px-5 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
                <Smartphone className="w-4 h-4 inline mr-1.5" /> Enable 2FA
              </button>
            </div>
          )}

          {/* Step: Confirm code */}
          {setupStep === "confirm" && (
            <div className="space-y-4">
              <p className="text-sm text-text-secondary">Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password):</p>
              <div className="flex items-center justify-center p-4 bg-white rounded-lg mx-auto w-fit">
                <QrCode className="w-32 h-32 text-black" />
              </div>
              <div>
                <p className="text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Manual Entry Key</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-3 py-2 rounded-lg bg-surface border border-border text-xs font-mono break-all">{totpSecret}</code>
                  <button onClick={() => { navigator.clipboard.writeText(totpSecret); toast.info("Copied!"); }}
                    className="p-2 rounded-lg border border-border hover:bg-surface"><Copy className="w-4 h-4 text-text-muted" /></button>
                </div>
              </div>
              <div>
                <p className="text-[10px] font-mono text-text-muted uppercase tracking-widest mb-1">Verification Code</p>
                <input value={confirmCode} onChange={e => setConfirmCode(e.target.value)} placeholder="000000"
                  maxLength={6} autoFocus
                  className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono text-center tracking-[0.3em] focus:border-brand outline-none" />
              </div>
              <button onClick={confirmTOTP}
                className="w-full py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
                Verify & Enable
              </button>
            </div>
          )}

          {/* Step: Done — show backup codes */}
          {setupStep === "done" && backupCodes.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-brand">
                <CheckCircle className="w-5 h-5" />
                <span className="font-medium">2FA Enabled!</span>
              </div>
              <div className="p-4 rounded-lg bg-amber/5 border border-amber/20">
                <p className="text-sm text-amber font-medium mb-2">Save your backup codes</p>
                <p className="text-xs text-text-muted mb-3">If you lose access to your authenticator, use these one-time codes to sign in. Each code can only be used once.</p>
                <div className="grid grid-cols-2 gap-2">
                  {backupCodes.map(code => (
                    <code key={code} className="px-3 py-1.5 rounded bg-surface border border-border text-xs font-mono text-center">{code}</code>
                  ))}
                </div>
                <button onClick={() => { navigator.clipboard.writeText(backupCodes.join("\n")); toast.info("Backup codes copied"); }}
                  className="mt-3 text-xs text-brand hover:text-brand-bright"><Copy className="w-3 h-3 inline mr-1" /> Copy all codes</button>
              </div>
              <button onClick={() => setSetupStep("idle")} className="w-full py-2 rounded-lg border border-border text-sm hover:bg-surface">Done</button>
            </div>
          )}

          {/* Already enabled — show disable */}
          {totp?.enabled && setupStep === "idle" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-text-muted">Remaining backup codes</span>
                <span className="font-mono text-brand">{totp.remainingBackupCodes ?? "—"}</span>
              </div>
              <div className="pt-3 border-t border-border">
                <p className="text-xs text-text-muted mb-2">To disable 2FA, enter your current authenticator code:</p>
                <div className="flex gap-2">
                  <input value={disableCode} onChange={e => setDisableCode(e.target.value)} placeholder="000000"
                    maxLength={6} className="flex-1 px-3 py-2 rounded-lg bg-surface border border-border text-sm font-mono text-center tracking-[0.3em] focus:border-brand outline-none" />
                  <button onClick={disableTOTP}
                    className="px-4 py-2 rounded-lg border border-red/30 text-red text-sm hover:bg-red/10 transition-colors">
                    Disable 2FA
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Sessions */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Key className="w-4 h-4 text-text-muted" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Sessions</span>
        </div>
        <div className="p-5">
          <button onClick={async () => {
            await api("/_sovereign/auth/logout", { method: "POST" });
            toast.success("Signed out");
            window.location.href = "/login";
          }} className="px-4 py-2 rounded-lg border border-red/30 text-red text-sm hover:bg-red/10 transition-colors">
            Sign out of all sessions
          </button>
        </div>
      </div>
    </div>
  );
}
