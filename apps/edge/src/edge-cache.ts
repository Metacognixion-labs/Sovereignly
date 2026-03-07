// Sovereignly Edge Cache -- BSL License
//
// In-memory LRU cache for edge nodes.
// Caches responses from cluster nodes to reduce latency.
// Entries expire based on TTL. Max entries configurable.

export interface CacheEntry {
  key:       string;
  value:     unknown;
  createdAt: number;
  expiresAt: number;
  hits:      number;
}

export class EdgeCache {
  private cache = new Map<string, CacheEntry>();
  private maxEntries: number;
  private defaultTTL: number;
  private totalHits = 0;
  private totalMisses = 0;
  private gcInterval: ReturnType<typeof setInterval>;

  constructor(opts: { maxEntries?: number; defaultTTLMs?: number } = {}) {
    this.maxEntries = opts.maxEntries ?? 10_000;
    this.defaultTTL = opts.defaultTTLMs ?? 60_000; // 1 minute default
    this.gcInterval = setInterval(() => this.gc(), 30_000);
  }

  /** Get a cached value */
  get<T = unknown>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) {
      this.totalMisses++;
      return null;
    }
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.totalMisses++;
      return null;
    }
    entry.hits++;
    this.totalHits++;
    return entry.value as T;
  }

  /** Set a cached value */
  set(key: string, value: unknown, ttlMs?: number): void {
    // Evict if at capacity (LRU-ish: remove oldest)
    if (this.cache.size >= this.maxEntries) {
      const oldest = this.cache.keys().next().value;
      if (oldest) this.cache.delete(oldest);
    }

    const now = Date.now();
    this.cache.set(key, {
      key,
      value,
      createdAt: now,
      expiresAt: now + (ttlMs ?? this.defaultTTL),
      hits: 0,
    });
  }

  /** Delete a cached value */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /** Check if a key exists and is not expired */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }

  /** Invalidate entries matching a prefix */
  invalidatePrefix(prefix: string): number {
    let count = 0;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
        count++;
      }
    }
    return count;
  }

  /** Clear all entries */
  clear(): void {
    this.cache.clear();
  }

  /** Garbage collect expired entries */
  private gc() {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  stats() {
    const hitRate = this.totalHits + this.totalMisses > 0
      ? Number((this.totalHits / (this.totalHits + this.totalMisses) * 100).toFixed(1))
      : 0;
    return {
      entries:     this.cache.size,
      maxEntries:  this.maxEntries,
      hits:        this.totalHits,
      misses:      this.totalMisses,
      hitRate:     `${hitRate}%`,
      defaultTTL:  this.defaultTTL,
    };
  }

  close() { clearInterval(this.gcInterval); }
}
