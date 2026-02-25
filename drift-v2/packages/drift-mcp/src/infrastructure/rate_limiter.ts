/**
 * RateLimiter — sliding window rate limiting for MCP tool calls.
 *
 * - Global: 100 calls per 60s across all tools
 * - Expensive: 10 calls per 60s for scan, simulate, taint_analysis, impact_analysis
 * - Returns { allowed: true } or { allowed: false, retryAfterMs, reason }
 *
 * PH-INFRA-03
 */

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs?: number;
  reason?: string;
}

export interface RateLimiterConfig {
  globalLimit: number;
  globalWindowMs: number;
  expensiveLimit: number;
  expensiveWindowMs: number;
  expensiveTools: ReadonlySet<string>;
}

const DEFAULT_RATE_LIMITER_CONFIG: RateLimiterConfig = {
  globalLimit: 100,
  globalWindowMs: 60_000,
  expensiveLimit: 10,
  expensiveWindowMs: 60_000,
  expensiveTools: new Set([
    'drift_scan',
    'driftScan',
    'drift_simulate',
    'drift_taint_analysis',
    'drift_impact_analysis',
  ]),
};

export class RateLimiter {
  private readonly globalTimestamps: number[] = [];
  private readonly expensiveTimestamps: number[] = [];
  private readonly config: RateLimiterConfig;

  constructor(config: Partial<RateLimiterConfig> = {}) {
    this.config = { ...DEFAULT_RATE_LIMITER_CONFIG, ...config };
  }

  /** Check if a tool call is allowed. */
  check(toolName: string): RateLimitResult {
    const now = Date.now();

    // Prune expired timestamps
    this.pruneTimestamps(this.globalTimestamps, now, this.config.globalWindowMs);

    // Check global limit
    if (this.globalTimestamps.length >= this.config.globalLimit) {
      const oldest = this.globalTimestamps[0]!;
      const retryAfterMs = Math.min(
        oldest + this.config.globalWindowMs - now,
        this.config.globalWindowMs,
      );
      return {
        allowed: false,
        retryAfterMs,
        reason: `Global rate limit exceeded (${this.config.globalLimit}/${this.config.globalWindowMs / 1000}s)`,
      };
    }

    // Check expensive limit
    if (this.config.expensiveTools.has(toolName)) {
      this.pruneTimestamps(this.expensiveTimestamps, now, this.config.expensiveWindowMs);

      if (this.expensiveTimestamps.length >= this.config.expensiveLimit) {
        const oldest = this.expensiveTimestamps[0]!;
        const retryAfterMs = Math.min(
          oldest + this.config.expensiveWindowMs - now,
          this.config.expensiveWindowMs,
        );
        return {
          allowed: false,
          retryAfterMs,
          reason: `Expensive tool rate limit exceeded (${this.config.expensiveLimit}/${this.config.expensiveWindowMs / 1000}s)`,
        };
      }

      this.expensiveTimestamps.push(now);
    }

    this.globalTimestamps.push(now);
    return { allowed: true };
  }

  /** Reset all rate limit state. */
  reset(): void {
    this.globalTimestamps.length = 0;
    this.expensiveTimestamps.length = 0;
  }

  private pruneTimestamps(timestamps: number[], now: number, windowMs: number): void {
    const cutoff = now - windowMs;
    while (timestamps.length > 0 && timestamps[0]! < cutoff) {
      timestamps.shift();
    }
  }
}
