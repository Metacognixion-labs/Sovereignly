// Sovereignly Kernel -- BSL License
//
// Modular kernel runtime. Manages module lifecycle, service registry, and event bus.
// Converts the monolithic server into a composable system.
//
// Usage:
//   const kernel = new SovereignKernel();
//   kernel.register(new ChainModule());
//   kernel.register(new TenantModule());
//   await kernel.start();

import type { SovereignModule } from "./module.ts";
import { ServiceRegistry } from "./registry.ts";
import type { EventBus } from "../../../oss/src/events/bus.ts";

export interface KernelConfig {
  nodeId:   string;
  region?:  string;
  role:     "control" | "cluster" | "edge";
  version:  string;
  dataDir:  string;
}

export class SovereignKernel {
  private modules: SovereignModule[] = [];
  private started = false;
  readonly services: ServiceRegistry;
  readonly config: KernelConfig;

  constructor(config: KernelConfig, bus: EventBus) {
    this.config = config;
    this.services = new ServiceRegistry();
    // Register the kernel itself and event bus as services
    this.services.register("kernel", this);
    this.services.register("bus", bus);
    this.services.register("config", config);
  }

  /** Register a module. Must be called before start(). */
  register(module: SovereignModule): void {
    if (this.started) {
      throw new Error(`[Kernel] Cannot register module "${module.name}" after kernel start`);
    }
    if (this.modules.some(m => m.name === module.name)) {
      throw new Error(`[Kernel] Module "${module.name}" already registered`);
    }
    this.modules.push(module);
  }

  /** Initialize and start all modules in registration order. */
  async start(): Promise<void> {
    console.log(`[Kernel] Starting ${this.modules.length} modules...`);
    const startTime = Date.now();

    for (const mod of this.modules) {
      try {
        await mod.init();
        await mod.start();
        console.log(`[Kernel]   ${mod.name}`);
      } catch (err: any) {
        console.error(`[Kernel]   ${mod.name} FAILED: ${err.message}`);
        throw new Error(`Module "${mod.name}" failed to start: ${err.message}`);
      }
    }

    this.started = true;
    const elapsed = Date.now() - startTime;
    console.log(`[Kernel] All modules started in ${elapsed}ms`);

    // Emit kernel boot event
    const bus = this.services.get<EventBus>("bus");
    await bus.emit("CONFIG_CHANGE", {
      event: "kernel_started",
      nodeId: this.config.nodeId,
      role: this.config.role,
      region: this.config.region,
      modules: this.modules.map(m => m.name),
      bootTimeMs: elapsed,
    }, { source: "kernel" });
  }

  /** Stop all modules in reverse order (graceful shutdown). */
  async stop(): Promise<void> {
    console.log("[Kernel] Shutting down...");
    for (const mod of [...this.modules].reverse()) {
      try {
        await mod.stop();
      } catch (err: any) {
        console.warn(`[Kernel] ${mod.name} stop error: ${err.message}`);
      }
    }
    this.started = false;
    this.services.clear();
    console.log("[Kernel] Shutdown complete");
  }

  /** Health check -- all modules must be healthy */
  healthy(): boolean {
    return this.modules.every(m => m.healthy());
  }

  /** Get a registered module by name */
  module<T extends SovereignModule>(name: string): T | undefined {
    return this.modules.find(m => m.name === name) as T | undefined;
  }

  /** List all module names and statuses */
  status(): Array<{ name: string; status: string; healthy: boolean }> {
    return this.modules.map(m => ({
      name: m.name,
      status: m.status,
      healthy: m.healthy(),
    }));
  }

  /** Kernel stats */
  stats() {
    return {
      nodeId:   this.config.nodeId,
      role:     this.config.role,
      region:   this.config.region,
      version:  this.config.version,
      started:  this.started,
      modules:  this.status(),
      services: this.services.list(),
    };
  }
}
