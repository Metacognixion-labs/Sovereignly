// Sovereignly Kernel Module Base -- BSL License
//
// All kernel subsystems implement this interface.
// The kernel manages module lifecycle: init -> start -> stop.

export type ModuleStatus = "created" | "initializing" | "running" | "stopped" | "failed";

export interface SovereignModule {
  /** Unique module name (e.g. "chain", "tenants", "auth") */
  readonly name: string;

  /** Current lifecycle status */
  status: ModuleStatus;

  /** Initialize resources (open DBs, allocate memory). Called once. */
  init(): Promise<void>;

  /** Start processing (begin intervals, subscribe to events). Called after init. */
  start(): Promise<void>;

  /** Graceful shutdown. Flush state, close connections. */
  stop(): Promise<void>;

  /** Health check -- returns true if module is operational */
  healthy(): boolean;
}

/**
 * Base class for kernel modules. Provides default lifecycle scaffolding.
 * Subclasses override onInit(), onStart(), onStop() for their logic.
 */
export abstract class BaseModule implements SovereignModule {
  status: ModuleStatus = "created";

  constructor(public readonly name: string) {}

  async init(): Promise<void> {
    this.status = "initializing";
    try {
      await this.onInit();
      this.status = "running";
    } catch (err) {
      this.status = "failed";
      throw err;
    }
  }

  async start(): Promise<void> {
    if (this.status !== "running") await this.init();
    await this.onStart();
  }

  async stop(): Promise<void> {
    await this.onStop();
    this.status = "stopped";
  }

  healthy(): boolean {
    return this.status === "running";
  }

  protected async onInit(): Promise<void> {}
  protected async onStart(): Promise<void> {}
  protected async onStop(): Promise<void> {}
}
