/**
 * Rate Limiter Tests — TH-RATE-01 through TH-RATE-06
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter } from '../../src/infrastructure/rate_limiter.js';

describe('Rate Limiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter();
  });

  // TH-RATE-01: 100 calls in 60s all allowed
  it('TH-RATE-01: 100 calls in 60s all allowed', () => {
    for (let i = 0; i < 100; i++) {
      const result = limiter.check('drift_status');
      expect(result.allowed, `Call ${i + 1} should be allowed`).toBe(true);
    }
  });

  // TH-RATE-02: 101st call blocked with retryAfterMs
  it('TH-RATE-02: 101st call blocked with retryAfterMs', () => {
    for (let i = 0; i < 100; i++) {
      limiter.check('drift_status');
    }
    const result = limiter.check('drift_status');
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeDefined();
    expect(result.retryAfterMs).toBeGreaterThan(0);
    expect(result.reason).toContain('Global');
  });

  // TH-RATE-03: expensive tool 10-call limit
  it('TH-RATE-03: expensive tool 10-call limit', () => {
    for (let i = 0; i < 10; i++) {
      const result = limiter.check('drift_simulate');
      expect(result.allowed, `Expensive call ${i + 1} should be allowed`).toBe(true);
    }
    const result = limiter.check('drift_simulate');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Expensive');
  });

  // TH-RATE-04: window sliding — 100 calls, wait 60s, 100 more all allowed
  it('TH-RATE-04: window sliding — calls allowed after window expires', () => {
    // Use a very short window for testing
    const fastLimiter = new RateLimiter({
      globalLimit: 5,
      globalWindowMs: 100,
    });

    for (let i = 0; i < 5; i++) {
      expect(fastLimiter.check('drift_status').allowed).toBe(true);
    }
    expect(fastLimiter.check('drift_status').allowed).toBe(false);

    // Wait for window to expire
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        // After window expires, calls should be allowed again
        expect(fastLimiter.check('drift_status').allowed).toBe(true);
        resolve();
      }, 150);
    });
  });

  // TH-RATE-05: retryAfterMs ≤ 60000
  it('TH-RATE-05: retryAfterMs ≤ 60000', () => {
    for (let i = 0; i < 100; i++) {
      limiter.check('drift_status');
    }
    const result = limiter.check('drift_status');
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeLessThanOrEqual(60000);
  });

  // TH-RATE-06: non-expensive tool not subject to expensive limit
  it('TH-RATE-06: non-expensive tool not subject to expensive limit', () => {
    // Fill up expensive limit
    for (let i = 0; i < 10; i++) {
      limiter.check('drift_simulate');
    }
    // Expensive is now blocked
    expect(limiter.check('drift_simulate').allowed).toBe(false);

    // Non-expensive should still work (under global limit)
    const result = limiter.check('drift_status');
    expect(result.allowed).toBe(true);
  });
});
