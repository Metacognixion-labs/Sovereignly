// Sovereignly Plugin System -- MIT License
//
// From DEVELOPER_ECOSYSTEM.md: Developers can publish agents, skills, plugins, workflows.
// The plugin registry is the foundation of the marketplace.

import type { EventBus } from "../events/bus.ts";
import type { PolicyEngine } from "../policies/engine.ts";

export type PluginType = "agent" | "skill" | "plugin" | "workflow" | "template";
export type PluginStatus = "published" | "draft" | "deprecated" | "suspended";

export interface PluginManifest {
  id:           string;
  name:         string;
  type:         PluginType;
  version:      string;
  description:  string;
  author:       string;
  authorId:     string;
  license:      string;
  homepage?:    string;
  repository?:  string;
  tags:         string[];
  permissions:  string[];         // platform actions this plugin requires
  entrypoint:   string;           // relative path to handler
  config?:      Record<string, { type: string; required: boolean; default?: unknown; description: string }>;
}

export interface InstalledPlugin {
  manifest:    PluginManifest;
  status:      PluginStatus;
  tenantId?:   string;            // null = platform-wide
  installedAt: number;
  installedBy: string;
  config:      Record<string, unknown>;
  stats:       { invocations: number; errors: number; lastUsed?: number };
}

export class PluginRegistry {
  private published = new Map<string, PluginManifest>();
  private installed = new Map<string, InstalledPlugin>();

  constructor(
    private bus:    EventBus,
    private policy: PolicyEngine,
  ) {}

  // ── Publish ──

  publish(manifest: Omit<PluginManifest, "id">): PluginManifest {
    const id = `plg_${manifest.type}_${crypto.randomUUID().slice(0, 10)}`;
    const full: PluginManifest = { ...manifest, id };
    this.published.set(id, full);

    void this.bus.emit("CONFIG_CHANGE", {
      event: "plugin_published", pluginId: id, name: manifest.name,
      type: manifest.type, author: manifest.author,
    }, { source: "plugin-registry" });

    return full;
  }

  // ── Install ──

  install(pluginId: string, opts: {
    tenantId?:   string;
    installedBy: string;
    config?:     Record<string, unknown>;
  }): InstalledPlugin {
    const manifest = this.published.get(pluginId);
    if (!manifest) throw new Error(`Plugin ${pluginId} not found`);

    // Policy check: does the tenant's plan allow this plugin type?
    const eval_ = this.policy.evaluate(`plugin.install.${manifest.type}`, {
      tenantId: opts.tenantId, pluginPermissions: manifest.permissions,
    });
    if (!eval_.allowed) throw new Error(eval_.reason ?? "Policy denied plugin install");

    const installed: InstalledPlugin = {
      manifest,
      status: "published",
      tenantId: opts.tenantId,
      installedAt: Date.now(),
      installedBy: opts.installedBy,
      config: opts.config ?? {},
      stats: { invocations: 0, errors: 0 },
    };

    const key = `${pluginId}:${opts.tenantId ?? "platform"}`;
    this.installed.set(key, installed);

    void this.bus.emit("CONFIG_CHANGE", {
      event: "plugin_installed", pluginId, name: manifest.name,
      tenantId: opts.tenantId, installedBy: opts.installedBy,
    }, { source: "plugin-registry", tenantId: opts.tenantId });

    return installed;
  }

  // ── Uninstall ──

  uninstall(pluginId: string, tenantId?: string): boolean {
    const key = `${pluginId}:${tenantId ?? "platform"}`;
    return this.installed.delete(key);
  }

  // ── Invoke ──

  recordInvocation(pluginId: string, tenantId?: string, error = false) {
    const key = `${pluginId}:${tenantId ?? "platform"}`;
    const inst = this.installed.get(key);
    if (inst) {
      inst.stats.invocations++;
      inst.stats.lastUsed = Date.now();
      if (error) inst.stats.errors++;
    }
  }

  // ── Query ──

  listPublished(opts?: { type?: PluginType; tag?: string }): PluginManifest[] {
    let results = Array.from(this.published.values());
    if (opts?.type) results = results.filter(p => p.type === opts.type);
    if (opts?.tag)  results = results.filter(p => p.tags.includes(opts.tag!));
    return results;
  }

  listInstalled(tenantId?: string): InstalledPlugin[] {
    return Array.from(this.installed.values())
      .filter(p => tenantId ? p.tenantId === tenantId : true);
  }

  getManifest(pluginId: string): PluginManifest | undefined {
    return this.published.get(pluginId);
  }

  // ── Marketplace stats ──

  stats() {
    const all = Array.from(this.published.values());
    return {
      published:  all.length,
      installed:  this.installed.size,
      byType: {
        agent:    all.filter(p => p.type === "agent").length,
        skill:    all.filter(p => p.type === "skill").length,
        plugin:   all.filter(p => p.type === "plugin").length,
        workflow:  all.filter(p => p.type === "workflow").length,
        template: all.filter(p => p.type === "template").length,
      },
      totalInvocations: Array.from(this.installed.values())
        .reduce((s, p) => s + p.stats.invocations, 0),
    };
  }
}
