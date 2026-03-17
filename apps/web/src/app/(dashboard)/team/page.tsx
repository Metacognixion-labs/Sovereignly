"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Users, UserPlus, Shield, Mail, Trash2, Crown } from "lucide-react";

interface Member { id: string; email: string; role: string; joinedAt: string; lastSeen: string }

const MOCK_MEMBERS: Member[] = [
  { id: "1", email: "jp@metacognixion.com", role: "owner", joinedAt: "2026-03-10", lastSeen: "Just now" },
];

export default function TeamPage() {
  const [members, setMembers] = useState<Member[]>(MOCK_MEMBERS);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("developer");

  function invite() {
    if (!inviteEmail || !inviteEmail.includes("@")) { toast.error("Valid email required"); return; }
    setMembers([...members, {
      id: crypto.randomUUID().slice(0, 8),
      email: inviteEmail,
      role: inviteRole,
      joinedAt: new Date().toISOString().slice(0, 10),
      lastSeen: "Pending invite",
    }]);
    toast.success(`Invitation sent to ${inviteEmail}`);
    setInviteEmail("");
  }

  function remove(id: string) {
    if (!confirm("Remove this team member?")) return;
    setMembers(members.filter(m => m.id !== id));
    toast.success("Member removed");
  }

  const roleColor = (r: string) =>
    r === "owner" ? "bg-brand/10 text-brand border-brand/20" :
    r === "admin" ? "bg-red/10 text-red border-red/20" :
    r === "developer" ? "bg-blue/10 text-blue border-blue/20" :
    "bg-surface text-text-muted border-border";

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Team</h1>
        <p className="text-sm text-text-muted mt-0.5">{members.length} member{members.length !== 1 ? "s" : ""}</p>
      </div>

      {/* Invite */}
      <div className="rounded-xl border border-border bg-panel">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <UserPlus className="w-4 h-4 text-brand" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-brand">Invite Member</span>
        </div>
        <div className="p-5 flex gap-3">
          <div className="flex-1">
            <input value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="team@company.com" type="email"
              className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
          </div>
          <select value={inviteRole} onChange={e => setInviteRole(e.target.value)}
            className="px-3 py-2 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none">
            <option value="developer">Developer</option>
            <option value="admin">Admin</option>
            <option value="viewer">Viewer</option>
          </select>
          <button onClick={invite}
            className="px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors whitespace-nowrap">
            Send Invite
          </button>
        </div>
      </div>

      {/* Members List */}
      <div className="rounded-xl border border-border bg-panel overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <Users className="w-4 h-4 text-text-muted" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">Members</span>
        </div>
        <div className="divide-y divide-border/50">
          {members.map(m => (
            <div key={m.id} className="px-5 py-4 flex items-center justify-between hover:bg-surface/30 transition-colors">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-full bg-surface border border-border flex items-center justify-center">
                  {m.role === "owner" ? <Crown className="w-4 h-4 text-brand" /> : <Mail className="w-4 h-4 text-text-muted" />}
                </div>
                <div>
                  <div className="text-sm font-medium">{m.email}</div>
                  <div className="text-[10px] text-text-muted">Joined {m.joinedAt} · {m.lastSeen}</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${roleColor(m.role)}`}>{m.role}</span>
                {m.role !== "owner" && (
                  <button onClick={() => remove(m.id)} className="p-1.5 rounded hover:bg-red/10">
                    <Trash2 className="w-3.5 h-3.5 text-text-muted hover:text-red" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Roles */}
      <div className="rounded-xl border border-border bg-panel p-5">
        <h3 className="text-xs font-mono text-text-muted uppercase tracking-widest mb-3">Role Permissions</h3>
        <div className="grid grid-cols-4 gap-3 text-xs">
          {[
            { role: "Owner", perms: "Full access, billing, team management, delete project" },
            { role: "Admin", perms: "Deploy, configure, manage functions, view billing" },
            { role: "Developer", perms: "Deploy, view logs, manage functions and KV" },
            { role: "Viewer", perms: "View dashboard, logs, and chain events (read-only)" },
          ].map(r => (
            <div key={r.role} className="p-3 rounded-lg border border-border">
              <div className="font-medium mb-1">{r.role}</div>
              <div className="text-text-muted text-[10px] leading-relaxed">{r.perms}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
