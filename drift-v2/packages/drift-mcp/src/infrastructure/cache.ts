/**
 * ResponseCache — L1 in-memory LRU cache with project isolation and TTL.
 *
 * - Max 100 entries, 5-minute default TTL
 * - Key format: `${projectRoot}:${toolName}:${paramsHash}`
 * - Project-isolated: different projects never share entries
 * - Uses Map insertion order for LRU eviction
 *
 * PH-INFRA-02
 */

import { createHash } from 'node:crypto';

export interface CacheEntry<T = unknown> {
  data: T;
  createdAt: number;
  ttlMs: number;
  tokenEstimate: number;
}

export interface CacheConfig {
  maxEntries: number;
  defaultTtlMs: number;
}

const DEFAULT_CACHE_CONFIG: CacheConfig = {
  maxEntries: 100,
  defaultTtlMs: 5 * 60 * 1000, // 5 minutes
};

export class ResponseCache {
  private readonly store = new Map<string, CacheEntry>();
  private readonly config: CacheConfig;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CACHE_CONFIG, ...config };
  }

  /** Build a cache key from project root, tool name, and params. */
  static buildKey(projectRoot: string, toolName: string, params: Record<string, unknown>): string {
    const paramsHash = createHash('sha256')
      .update(JSON.stringify(params))
      .digest('hex')
      .slice(0, 16);
    return `${projectRoot}:${toolName}:${paramsHash}`;
  }

  /** Get a cached entry. Returns undefined if missing or expired. */
  get<T = unknown>(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;

    const now = Date.now();
    if (now - entry.createdAt > entry.ttlMs) {
      this.store.delete(key);
      return undefined;
    }

    // Move to end (most recently used) by re-inserting
    this.store.delete(key);
    this.store.set(key, entry);

    return entry.data as T;
  }

  /** Set a cache entry. Undefined values are ignored (no-op). */
  set<T = unknown>(key: string, data: T, ttlMs?: number, tokenEstimate = 0): void {
    if (data === undefined) return;

    // Evict oldest if at capacity
    if (this.store.size >= this.config.maxEntries && !this.store.has(key)) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) {
        this.store.delete(oldest);
      }
    }

    this.store.set(key, {
      data,
      createdAt: Date.now(),
      ttlMs: ttlMs ?? this.config.defaultTtlMs,
      tokenEstimate,
    });
  }

  /** Invalidate entries matching a glob pattern on the key. */
  invalidate(pattern: string): number {
    let count = 0;
    const regex = globToRegex(pattern);
    for (const key of [...this.store.keys()]) {
      if (regex.test(key)) {
        this.store.delete(key);
        count++;
      }
    }
    return count;
  }

  /** Invalidate all entries for a specific project root. */
  invalidateProject(projectRoot: string): number {
    let count = 0;
    const prefix = `${projectRoot}:`;
    for (const key of [...this.store.keys()]) {
      if (key.startsWith(prefix)) {
        this.store.delete(key);
        count++;
      }
    }
    return count;
  }

  /** Current number of entries. */
  get size(): number {
    return this.store.size;
  }

  /** Clear all entries. */
  clear(): void {
    this.store.clear();
  }
}

/** Convert a simple glob pattern to a regex. Supports * and **. */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^:]*')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');
  return new RegExp(`^${escaped}$`);
}
