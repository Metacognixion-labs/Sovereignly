"use client";

import { useState } from "react";
import { toast } from "sonner";
import Link from "next/link";
import { Building2, Plus, Users, Blocks, ChevronRight, Crown, Globe, ArrowRight } from "lucide-react";

interface Org {
  id: string;
  name: string;
  slug: string;
  plan: string;
  role: string;
  members: number;
  projects: number;
  createdAt: string;
}

export default function OrgsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newSlug, setNewSlug] = useState("");

  function createOrg() {
    if (!newName.trim()) { toast.error("Organization name required"); return; }
    const slug = newSlug || newName.toLowerCase().replace(/[^a-z0-9]/g, "-").replace(/-+/g, "-");
    const org: Org = {
      id: `org_${crypto.randomUUID().slice(0, 12)}`,
      name: newName.trim(),
      slug,
      plan: "free",
      role: "owner",
      members: 1,
      projects: 0,
      createdAt: new Date().toISOString().slice(0, 10),
    };
    setOrgs([org, ...orgs]);
    setShowCreate(false);
    setNewName("");
    setNewSlug("");
    toast.success(`Organization "${org.name}" created`);
  }

  const planBadge = (plan: string) => {
    const colors: Record<string, string> = {
      free: "bg-surface text-text-muted border-border",
      starter: "bg-blue/10 text-blue border-blue/20",
      growth: "bg-brand/10 text-brand border-brand/20",
      enterprise: "bg-violet/10 text-violet border-violet/20",
    };
    return colors[plan] ?? colors.free;
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Organizations</h1>
          <p className="text-sm text-text-muted mt-0.5">Create organizations to manage projects and team access</p>
        </div>
        <button onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
          <Plus className="w-4 h-4" /> New Organization
        </button>
      </div>

      {/* Create Org */}
      {showCreate && (
        <div className="rounded-xl border border-brand/30 bg-brand/5 p-6 space-y-4">
          <h3 className="font-medium flex items-center gap-2"><Building2 className="w-4 h-4 text-brand" /> Create Organization</h3>
          <div>
            <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">Organization Name</label>
            <input value={newName} onChange={e => { setNewName(e.target.value); setNewSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]/g, "-").replace(/-+/g, "-")); }}
              placeholder="My Company" autoFocus
              className="w-full px-3 py-2.5 rounded-lg bg-surface border border-border text-sm focus:border-brand outline-none" />
          </div>
          <div>
            <label className="block text-xs font-mono text-text-muted uppercase tracking-widest mb-1.5">URL Slug</label>
            <div className="flex items-center gap-0 rounded-lg border border-border overflow-hidden">
              <span className="px-3 py-2.5 bg-surface text-xs text-text-muted font-mono border-r border-border">sovereignly.io/</span>
              <input value={newSlug} onChange={e => setNewSlug(e.target.value)}
                className="flex-1 px-3 py-2.5 bg-surface text-sm font-mono focus:outline-none" />
            </div>
          </div>
          <div className="flex gap-3">
            <button onClick={createOrg} className="px-5 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
              Create Organization
            </button>
            <button onClick={() => setShowCreate(false)} className="px-5 py-2.5 rounded-lg border border-border text-sm hover:bg-surface transition-colors">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Org List */}
      {orgs.length === 0 && !showCreate ? (
        <div className="rounded-xl border border-border bg-panel p-12 text-center">
          <Building2 className="w-12 h-12 text-text-muted mx-auto mb-4 opacity-30" />
          <h3 className="font-medium mb-1">No organizations yet</h3>
          <p className="text-sm text-text-muted mb-4">Create an organization to start deploying projects with your team.</p>
          <button onClick={() => setShowCreate(true)}
            className="px-5 py-2.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
            <Plus className="w-4 h-4 inline mr-1.5" /> Create Your First Organization
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {orgs.map(org => (
            <Link key={org.id} href={`/orgs/${org.id}`}
              className="block rounded-xl border border-border bg-panel p-5 hover:border-border-bright transition-all group">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-11 h-11 rounded-xl bg-shield-gradient flex items-center justify-center">
                    <Building2 className="w-5 h-5 text-brand" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">{org.name}</span>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${planBadge(org.plan)}`}>{org.plan}</span>
                      {org.role === "owner" && <Crown className="w-3 h-3 text-amber" />}
                    </div>
                    <div className="text-xs text-text-muted font-mono mt-0.5">{org.slug} · Created {org.createdAt}</div>
                  </div>
                </div>
                <div className="flex items-center gap-6">
                  <div className="text-center">
                    <div className="text-sm font-semibold">{org.projects}</div>
                    <div className="text-[9px] text-text-muted font-mono">Projects</div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm font-semibold">{org.members}</div>
                    <div className="text-[9px] text-text-muted font-mono">Members</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-text-muted group-hover:text-brand transition-colors" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      {/* Info */}
      <div className="rounded-xl border border-border bg-panel p-5">
        <h3 className="text-xs font-mono text-text-muted uppercase tracking-widest mb-3">How Organizations Work</h3>
        <div className="grid grid-cols-3 gap-4 text-xs text-text-muted">
          <div className="flex items-start gap-2">
            <Building2 className="w-4 h-4 text-brand shrink-0 mt-0.5" />
            <div><span className="text-text-primary font-medium">Isolated tenants</span> — each org gets its own encrypted audit chain, KV store, and storage.</div>
          </div>
          <div className="flex items-start gap-2">
            <Users className="w-4 h-4 text-blue shrink-0 mt-0.5" />
            <div><span className="text-text-primary font-medium">RBAC</span> — invite members as Owner, Admin, Developer, or Viewer with granular permissions.</div>
          </div>
          <div className="flex items-start gap-2">
            <Blocks className="w-4 h-4 text-violet shrink-0 mt-0.5" />
            <div><span className="text-text-primary font-medium">Multi-project</span> — deploy unlimited projects under one org with shared billing.</div>
          </div>
        </div>
      </div>
    </div>
  );
}
