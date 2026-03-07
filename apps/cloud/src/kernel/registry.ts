// Sovereignly Service Registry -- BSL License
//
// Centralized service registry for the kernel.
// Modules register services they provide; other modules look them up.
// Replaces scattered singletons with a typed dependency container.

export class ServiceRegistry {
  private services = new Map<string, unknown>();

  /** Register a service by name */
  register<T>(name: string, instance: T): void {
    if (this.services.has(name)) {
      throw new Error(`[ServiceRegistry] Service "${name}" already registered`);
    }
    this.services.set(name, instance);
  }

  /** Get a service by name. Throws if not found. */
  get<T>(name: string): T {
    const svc = this.services.get(name);
    if (!svc) {
      throw new Error(`[ServiceRegistry] Service "${name}" not found. Available: ${this.list().join(", ")}`);
    }
    return svc as T;
  }

  /** Get a service or null if not registered */
  tryGet<T>(name: string): T | null {
    return (this.services.get(name) as T) ?? null;
  }

  /** Check if a service is registered */
  has(name: string): boolean {
    return this.services.has(name);
  }

  /** List all registered service names */
  list(): string[] {
    return Array.from(this.services.keys());
  }

  /** Total registered services */
  count(): number {
    return this.services.size;
  }

  /** Remove a service */
  remove(name: string): boolean {
    return this.services.delete(name);
  }

  /** Clear all services */
  clear(): void {
    this.services.clear();
  }
}
