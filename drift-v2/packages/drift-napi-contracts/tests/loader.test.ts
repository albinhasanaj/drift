/**
 * Loader Tests — TH-NAPI-12 through TH-NAPI-17
 * Verifies loadNapi() singleton lifecycle, test injection, and error handling.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { loadNapi, setNapi, resetNapi, NapiLoadError } from '../src/loader.js';
import { createStubNapi } from '../src/stub.js';
import { DRIFT_NAPI_METHOD_NAMES } from '../src/interface.js';

describe('Loader — Lifecycle & Injection', () => {
  beforeEach(() => {
    resetNapi();
  });

  // TH-NAPI-12: loadNapi() returns stub when native binary unavailable — no throw
  it('TH-NAPI-12: loadNapi() returns stub when native binary unavailable — no throw', () => {
    // drift-napi native binary is not available in test environment
    const napi = loadNapi();
    expect(napi).toBeDefined();
    expect(typeof napi.driftIsInitialized).toBe('function');
    expect(typeof napi.driftCheck).toBe('function');
    expect(typeof napi.driftViolations).toBe('function');

    // Verify it's the stub (returns false for isInitialized)
    expect(napi.driftIsInitialized()).toBe(false);
  });

  // TH-NAPI-13: loadNapi() is idempotent — 10 calls return same instance
  it('TH-NAPI-13: loadNapi() is idempotent — 10 calls return same instance', () => {
    const first = loadNapi();
    for (let i = 0; i < 10; i++) {
      const next = loadNapi();
      expect(next).toBe(first); // Same reference
    }
  });

  // TH-NAPI-14: setNapi() overrides singleton for tests
  it('TH-NAPI-14: setNapi() overrides singleton for tests', () => {
    const custom = createStubNapi();
    // Mark the custom instance so we can identify it
    (custom as unknown as Record<string, unknown>).__test_marker = true;

    setNapi(custom);
    const loaded = loadNapi();
    expect((loaded as unknown as Record<string, unknown>).__test_marker).toBe(true);
  });

  // TH-NAPI-15: resetNapi() clears singleton — next loadNapi() re-initializes
  it('TH-NAPI-15: resetNapi() clears singleton — next loadNapi() re-initializes', () => {
    // Inject a custom instance with a marker
    const custom = createStubNapi();
    (custom as unknown as Record<string, unknown>).__reset_test = true;
    setNapi(custom);
    expect((loadNapi() as unknown as Record<string, unknown>).__reset_test).toBe(true);

    // Reset should clear the injected instance
    resetNapi();
    const reloaded = loadNapi();
    // After reset, the marker should be gone (fresh instance loaded)
    expect((reloaded as unknown as Record<string, unknown>).__reset_test).toBeUndefined();
    // The reloaded instance should still have all required methods
    expect(typeof reloaded.driftIsInitialized).toBe('function');
  });

  // TH-NAPI-16: setNapi() with incomplete object — throws NapiLoadError listing missing functions
  it('TH-NAPI-16: setNapi() with incomplete object — throws NapiLoadError listing missing functions', () => {
    const incomplete = {
      driftInitialize: () => {},
      driftShutdown: () => {},
      // Missing 36 other functions
    };

    expect(() => setNapi(incomplete as never)).toThrow(NapiLoadError);

    try {
      setNapi(incomplete as never);
    } catch (err) {
      expect(err).toBeInstanceOf(NapiLoadError);
      const napiErr = err as NapiLoadError;
      expect(napiErr.missingFunctions.length).toBeGreaterThan(0);
      // Should list specific missing function names
      expect(napiErr.missingFunctions).toContain('driftIsInitialized');
      expect(napiErr.missingFunctions).toContain('driftCheck');
      expect(napiErr.missingFunctions).toContain('driftViolations');
      expect(napiErr.message).toContain('missing');
    }
  });

  // TH-NAPI-17: Concurrent loadNapi() from Promise.all(5) — no race, all get same instance
  it('TH-NAPI-17: concurrent loadNapi() from Promise.all(5) — no race, all get same instance', async () => {
    const results = await Promise.all([
      Promise.resolve(loadNapi()),
      Promise.resolve(loadNapi()),
      Promise.resolve(loadNapi()),
      Promise.resolve(loadNapi()),
      Promise.resolve(loadNapi()),
    ]);

    const first = results[0];
    for (const result of results) {
      expect(result).toBe(first); // All same reference
    }

    // Verify all 40 methods are present on every returned instance
    for (const result of results) {
      for (const name of DRIFT_NAPI_METHOD_NAMES) {
        expect(typeof result[name]).toBe('function');
      }
    }
  });
});
