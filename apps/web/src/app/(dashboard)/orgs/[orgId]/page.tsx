"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { toast } from "sonner";
import {
  Building2, Users, Blocks, Plus, Settings, Shield, Link2,
  UserPlus, ChevronRight, Crown, Trash2, GitBranch, Globe, ShieldCheck,
} from "lucide-react";

interface Project { id: string; name: string; framework: string; status: string; url: string; lastDeploy: string; functions: number }
interface Member { id: string; email: string; role: string; joinedAt: string; lastSeen: string }

const ROLES = [
  { id: "owner", label: "Owner", desc: "Full access including billing, danger zone, and org deletion", color: "text-amber", perms: ["*"] },
  { id: "admin", label: "Admin", desc: "Manage projects, members, settings. Cannot delete org or transfer ownership", color: "text-red", perms: ["projects:*", "members:*", "settings:*", "deploy:*", "chain:read"] },
  { id: "developer", label: "Developer", desc: "Deploy code, manage functions, KV, storage. Cannot manage members", color: "text-blue", perms: ["projects:read", "deploy:*", "functions:*", "kv:*", "storage:*", "chain:read", "logs:read"] },
  { id: "viewer", label: "Viewer", desc: "Read-only access to dashboard, logs, chain, and compliance reports", color: "text-text-muted", perms: ["projects:read", "chain:read", "logs:read", "compliance:read"] },
];

export default function OrgDetailPage() {
  const { orgId } = useParams();
  const [tab, setTab] = useState<"projects" | "members" | "settings">("projects");
  const [projects, setProjects] = useState<Project[]>([]);
  const [members, setMembers] = useState<Member[]>([
    { id: "1", email: "jp@metacognixion.com", role: "owner", joinedAt: "2026-03-17", lastSeen: "Just now" },
  ]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("developer");
  const [showInvite, setShowInvite] = useState(false);

  function invite() {
    if (!inviteEmail.includes("@")) { toast.error("Valid email required"); return; }
    setMembers([...members, {
      id: crypto.randomUUID().slice(0, 8), email: inviteEmail, role: inviteRole,
      joinedAt: new Date().toISOString().slice(0, 10), lastSeen: "Pending",
    }]);
    toast.success(`Invited ${inviteEmail} as ${inviteRole}`);
    setInviteEmail("");
    setShowInvite(false);
  }

  function changeRole(memberId: string, newRole: string) {
    setMembers(members.map(m => m.id === memberId ? { ...m, role: newRole } : m));
    toast.success("Role updated");
  }

  function removeMember(id: string) {
    if (!confirm("Remove this member from the organization?")) return;
    setMembers(members.filter(m => m.id !== id));
    toast.success("Member removed");
  }

  const roleBadge = (role: string) => {
    const r = ROLES.find(r => r.id === role);
    return `${r?.color ?? "text-text-muted"}`;
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-shield-gradient flex items-center justify-center">
            <Building2 className="w-5 h-5 text-brand" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Organization</h1>
            <p className="text-xs text-text-muted font-mono">{orgId}</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 p-1 rounded-lg bg-surface border border-border w-fit">
        {([
          { id: "projects", label: "Projects", icon: Blocks, count: projects.length },
          { id: "members", label: "Members", icon: Users, count: members.length },
          { id: "settings", label: "Settings", icon: Settings },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
              tab === t.id ? "bg-brand text-background" : "text-text-muted hover:text-text-primary"
            }`}>
            <t.icon className="w-4 h-4" />
            {t.label}
            {"count" in t && <span className="text-[10px] font-mono opacity-70">{t.count}</span>}
          </button>
        ))}
      </div>

      {/* Projects Tab */}
      {tab === "projects" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Projects</h2>
            <Link href="/projects/new"
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
              <Plus className="w-4 h-4" /> New Project
            </Link>
          </div>

          {projects.length === 0 ? (
            <div className="rounded-xl border border-border bg-panel p-12 text-center">
              <Blocks className="w-10 h-10 text-text-muted mx-auto mb-3 opacity-30" />
              <h3 className="font-medium mb-1">No projects yet</h3>
              <p className="text-sm text-text-muted mb-4">Deploy your first project to this organization</p>
              <Link href="/projects/new"
                className="px-5 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors inline-flex items-center gap-2">
                <GitBranch className="w-4 h-4" /> Connect Repository
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {projects.map(p => (
                <div key={p.id} className="rounded-xl border border-border bg-panel p-5 hover:border-border-bright transition-all">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Globe className="w-5 h-5 text-blue" />
                      <div>
                        <div className="font-medium">{p.name}</div>
                        <div className="text-xs text-text-muted font-mono">{p.url} · {p.framework} · {p.functions} functions</div>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-brand/10 text-brand border border-brand/20">{p.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Members Tab */}
      {tab === "members" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Members & RBAC</h2>
            <button onClick={() => setShowInvite(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
              <UserPlus className="w-4 h-4" /> Invite Member
            </button>
          </div>

          {/* Invite Form */}
          {showInvite && (
            <div className="rounded-xl border border-brand/30 bg-brand/5 p-5 space-y-4">
              <h3 className="font-medium flex items-center gap-2"><UserPlus className="w-4 h-4 text-brand" /> Invite to Organization</h3>
              <div className="flex gap-3">
                <input value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="member@company.com" type="email" autoFocus
                  className="flex-1 px-3 py-2.5 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
                <select value={inviteRole} onChange={e => setInviteRole(e.target.value)}
                  className="px-3 py-2.5 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none">
                  {ROLES.filter(r => r.id !== "owner").map(r => (
                    <option key={r.id} value={r.id}>{r.label}</option>
                  ))}
                </select>
              </div>
              {/* Role description */}
              <div className="text-xs text-text-muted p-3 rounded-lg bg-surface border border-border">
                <span className="font-medium text-text-secondary">{ROLES.find(r => r.id === inviteRole)?.label}:</span>{" "}
                {ROLES.find(r => r.id === inviteRole)?.desc}
              </div>
              <div className="flex gap-3">
                <button onClick={invite} className="px-5 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright">Send Invite</button>
                <button onClick={() => setShowInvite(false)} className="px-5 py-2.5 rounded-lg border border-border text-sm hover:bg-surface">Cancel</button>
              </div>
            </div>
          )}

          {/* Members List */}
          <div className="rounded-xl border border-border bg-panel overflow-hidden">
            <div className="divide-y divide-border/50">
              {members.map(m => (
                <div key={m.id} className="px-5 py-4 flex items-center justify-between hover:bg-surface/30 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-surface border border-border flex items-center justify-center">
                      {m.role === "owner" ? <Crown className="w-4 h-4 text-amber" /> :
                       m.role === "admin" ? <Shield className="w-4 h-4 text-red" /> :
                       <Users className="w-4 h-4 text-text-muted" />}
                    </div>
                    <div>
                      <div className="text-sm font-medium">{m.email}</div>
                      <div className="text-[10px] text-text-muted font-mono">Joined {m.joinedAt} · {m.lastSeen}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {m.role === "owner" ? (
                      <span className="text-[10px] font-mono px-2 py-1 rounded bg-amber/10 text-amber border border-amber/20">Owner</span>
                    ) : (
                      <select value={m.role} onChange={e => changeRole(m.id, e.target.value)}
                        className="text-[10px] font-mono px-2 py-1 rounded bg-surface border border-border focus:border-brand outline-none">
                        {ROLES.filter(r => r.id !== "owner").map(r => (
                          <option key={r.id} value={r.id}>{r.label}</option>
                        ))}
                      </select>
                    )}
                    {m.role !== "owner" && (
                      <button onClick={() => removeMember(m.id)} className="p-1.5 rounded hover:bg-red/10">
                        <Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* RBAC Reference */}
          <div className="rounded-xl border border-border bg-panel">
            <div className="px-5 py-3 border-b border-border flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-brand" />
              <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Role-Based Access Control</span>
            </div>
            <div className="p-5">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[9px] font-mono uppercase tracking-widest text-text-muted border-b border-border">
                    <th className="text-left pb-3 pr-4">Permission</th>
                    {ROLES.map(r => <th key={r.id} className={`text-center pb-3 ${r.color}`}>{r.label}</th>)}
                  </tr>
                </thead>
                <tbody className="text-text-secondary">
                  {[
                    { perm: "View dashboard & logs", owner: true, admin: true, dev: true, viewer: true },
                    { perm: "View audit chain & compliance", owner: true, admin: true, dev: true, viewer: true },
                    { perm: "Deploy functions", owner: true, admin: true, dev: true, viewer: false },
                    { perm: "Manage KV & storage", owner: true, admin: true, dev: true, viewer: false },
                    { perm: "Manage environment variables", owner: true, admin: true, dev: true, viewer: false },
                    { perm: "Invite & remove members", owner: true, admin: true, dev: false, viewer: false },
                    { perm: "Change member roles", owner: true, admin: true, dev: false, viewer: false },
                    { perm: "Manage billing & plan", owner: true, admin: false, dev: false, viewer: false },
                    { perm: "Delete organization", owner: true, admin: false, dev: false, viewer: false },
                    { perm: "Transfer ownership", owner: true, admin: false, dev: false, viewer: false },
                  ].map(row => (
                    <tr key={row.perm} className="border-b border-border/30">
                      <td className="py-2.5 pr-4 text-text-muted">{row.perm}</td>
                      <td className="text-center py-2.5">{row.owner ? <span className="text-brand">&#10003;</span> : "—"}</td>
                      <td className="text-center py-2.5">{row.admin ? <span className="text-brand">&#10003;</span> : "—"}</td>
                      <td className="text-center py-2.5">{row.dev ? <span className="text-brand">&#10003;</span> : "—"}</td>
                      <td className="text-center py-2.5">{row.viewer ? <span className="text-brand">&#10003;</span> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Settings Tab */}
      {tab === "settings" && (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Organization Settings</h2>
          <div className="rounded-xl border border-border bg-panel p-5 space-y-4">
            <div>
              <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Organization Name</label>
              <input defaultValue="My Organization" className="w-full px-3 py-2.5 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
            </div>
            <div>
              <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">URL Slug</label>
              <input defaultValue="" className="w-full px-3 py-2.5 rounded-lg bg-surface border border-border text-sm font-mono focus:border-brand outline-none" />
            </div>
            <button className="px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">Save Changes</button>
          </div>

          <div className="rounded-xl border border-red/20 bg-red/5 p-5 space-y-3">
            <h3 className="text-sm font-medium text-red">Danger Zone</h3>
            <p className="text-xs text-text-muted">Deleting an organization removes all projects, data, audit chains, and member access. This action cannot be undone.</p>
            <button className="px-4 py-2 rounded-lg border border-red/30 text-red text-sm hover:bg-red/10 transition-colors">
              <Trash2 className="w-3.5 h-3.5 inline mr-1.5" /> Delete Organization
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
