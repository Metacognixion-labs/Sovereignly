// Sovereignly Gamification -- MIT License
//
// From DEVELOPER_ECOSYSTEM.md: Gamification
// Developers earn XP for publishing plugins, running workflows, etc.

import type { EventBus } from "../events/bus.ts";

export interface DeveloperProfile {
  id:        string;
  name:      string;
  xp:        number;
  level:     number;
  badges:    string[];
  stats: {
    pluginsPublished:  number;
    workflowsRun:      number;
    agentsCreated:     number;
    eventsEmitted:     number;
  };
  joinedAt:  number;
}

const XP_TABLE: Record<string, number> = {
  plugin_published:   100,
  plugin_installed:    10,
  workflow_completed:  25,
  agent_executed:      15,
  first_event:         50,
  first_plugin:       200,
  first_workflow:     150,
  streak_7_days:      300,
};

const LEVEL_THRESHOLDS = [0, 100, 300, 600, 1000, 1500, 2500, 4000, 6000, 10000];
const BADGES: Record<string, { name: string; description: string; condition: (p: DeveloperProfile) => boolean }> = {
  early_adopter:    { name: "Early Adopter",     description: "Joined during beta",           condition: () => true },
  plugin_author:    { name: "Plugin Author",     description: "Published first plugin",       condition: p => p.stats.pluginsPublished >= 1 },
  power_builder:    { name: "Power Builder",     description: "Published 5+ plugins",         condition: p => p.stats.pluginsPublished >= 5 },
  workflow_master:  { name: "Workflow Master",   description: "Completed 100+ workflows",     condition: p => p.stats.workflowsRun >= 100 },
  agent_smith:      { name: "Agent Smith",       description: "Created 10+ agents",           condition: p => p.stats.agentsCreated >= 10 },
  event_storm:      { name: "Event Storm",       description: "Emitted 10,000+ events",       condition: p => p.stats.eventsEmitted >= 10000 },
  level_10:         { name: "Sovereign",         description: "Reached level 10",             condition: p => p.level >= 10 },
};

export class GamificationEngine {
  private profiles = new Map<string, DeveloperProfile>();
  private subIds: string[] = [];

  constructor(private bus: EventBus) {
    // Auto-track events
    this.subIds.push(bus.on("CONFIG_CHANGE", (e) => {
      const event = e.payload.event as string;
      if (!event) return;
      const userId = (e.payload.installedBy ?? e.payload.publishedBy ?? e.payload.ownerId ?? e.source) as string;
      if (!userId || userId === "platform") return;

      if (event === "plugin_published")  this.award(userId, "plugin_published");
      if (event === "plugin_installed")  this.award(userId, "plugin_installed");
    }, "gamification"));

    this.subIds.push(bus.on("WORKFLOW_COMPLETED", (e) => {
      const userId = (e.payload.triggeredBy ?? e.source) as string;
      if (userId && userId !== "system") this.award(userId, "workflow_completed");
    }, "gamification"));

    this.subIds.push(bus.on("AGENT_EXECUTED", (e) => {
      const userId = e.source;
      if (userId) this.award(userId, "agent_executed");
    }, "gamification"));
  }

  // Get or create profile
  profile(userId: string, name?: string): DeveloperProfile {
    let p = this.profiles.get(userId);
    if (!p) {
      p = {
        id: userId, name: name ?? userId, xp: 0, level: 1, badges: ["early_adopter"],
        stats: { pluginsPublished: 0, workflowsRun: 0, agentsCreated: 0, eventsEmitted: 0 },
        joinedAt: Date.now(),
      };
      this.profiles.set(userId, p);
    }
    return p;
  }

  // Award XP
  award(userId: string, action: string) {
    const p = this.profile(userId);
    const xp = XP_TABLE[action] ?? 5;
    p.xp += xp;

    // Update stats
    if (action === "plugin_published") p.stats.pluginsPublished++;
    if (action === "workflow_completed") p.stats.workflowsRun++;
    if (action === "agent_executed") p.stats.agentsCreated++;

    // Level up
    p.level = LEVEL_THRESHOLDS.filter(t => p.xp >= t).length;

    // Check badges
    for (const [id, badge] of Object.entries(BADGES)) {
      if (!p.badges.includes(id) && badge.condition(p)) {
        p.badges.push(id);
        void this.bus.emit("CONFIG_CHANGE", {
          event: "badge_earned", userId, badge: id, badgeName: badge.name,
        }, { source: "gamification" });
      }
    }
  }

  // Leaderboard
  leaderboard(limit = 20): DeveloperProfile[] {
    return Array.from(this.profiles.values())
      .sort((a, b) => b.xp - a.xp)
      .slice(0, limit);
  }

  stats() {
    return {
      developers: this.profiles.size,
      totalXP:    Array.from(this.profiles.values()).reduce((s, p) => s + p.xp, 0),
      topLevel:   Math.max(0, ...Array.from(this.profiles.values()).map(p => p.level)),
      badgesEarned: Array.from(this.profiles.values()).reduce((s, p) => s + p.badges.length, 0),
    };
  }

  close() { for (const id of this.subIds) this.bus.off(id); }
}
