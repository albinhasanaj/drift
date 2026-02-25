/**
 * Phase E Tests — Concurrent Requests (PH-PARITY-03)
 * TH-CONC-01 through TH-CONC-04
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createStubNapi, setNapi } from '@drift/napi-contracts';
import { handleDriftTool, buildToolCatalog } from '../../src/tools/drift_tool.js';
import { handleDriftStatus } from '../../src/tools/drift_status.js';
import { RateLimiter } from '../../src/infrastructure/rate_limiter.js';
import type { InternalTool } from '../../src/types.js';

let catalog: Map<string, InternalTool>;

beforeEach(() => {
  const napi = createStubNapi();
  setNapi(napi);
  catalog = buildToolCatalog();
});

describe('Concurrent Requests — No Mixing', () => {
  // TH-CONC-01: 5 simultaneous drift_status → identical results
  it('TH-CONC-01: 5 simultaneous drift_status return identical results', async () => {
    const results = await Promise.all(
      Array.from({ length: 5 }, () => handleDriftStatus()),
    );
    const first = JSON.stringify(results[0]);
    for (const r of results.slice(1)) {
      expect(JSON.stringify(r)).toBe(first);
    }
  });

  // TH-CONC-02: mixed tool calls return correct types
  it('TH-CONC-02: mixed concurrent tool calls return correct types', async () => {
    const [a1, a2, a3, p1, p2] = await Promise.all([
      handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog),
      handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog),
      handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog),
      handleDriftTool({ tool: 'drift_patterns_list', params: {} }, catalog),
      handleDriftTool({ tool: 'drift_patterns_list', params: {} }, catalog),
    ]);
    // Audit results should be objects
    expect(typeof a1).toBe('object');
    expect(typeof a2).toBe('object');
    expect(typeof a3).toBe('object');
    // Patterns should be objects
    expect(typeof p1).toBe('object');
    expect(typeof p2).toBe('object');
  });

  // TH-CONC-03: concurrent scan + status → status returns immediately
  it('TH-CONC-03: concurrent scan + status complete independently', async () => {
    const [scanResult, statusResult] = await Promise.all([
      handleDriftTool({ tool: 'drift_quality_gate', params: { root: '.' } }, catalog),
      handleDriftStatus(),
    ]);
    expect(scanResult).toBeDefined();
    expect(statusResult).toBeDefined();
  });

  // TH-CONC-04: rate limiter under burst
  it('TH-CONC-04: rate limiter allows first 100 calls, blocks excess', () => {
    const limiter = new RateLimiter({ globalLimit: 100, globalWindowMs: 1000 });
    let allowed = 0;
    let blocked = 0;

    for (let i = 0; i < 150; i++) {
      const result = limiter.check('drift_status');
      if (result.allowed) {
        allowed++;
      } else {
        blocked++;
        expect(result.retryAfterMs).toBeGreaterThan(0);
      }
    }

    expect(allowed).toBe(100);
    expect(blocked).toBe(50);
  });
});
