/**
 * Stub Completeness Tests — TH-NAPI-06 through TH-NAPI-11
 * Verifies createStubNapi() returns structurally valid typed data for every method.
 */

import { describe, it, expect } from 'vitest';
import { createStubNapi } from '../src/stub.js';
import { DRIFT_NAPI_METHOD_NAMES } from '../src/interface.js';

describe('Stub Completeness', () => {
  // TH-NAPI-06: createStubNapi() implements every DriftNapi method
  it('TH-NAPI-06: createStubNapi() implements every DriftNapi method', () => {
    const stub = createStubNapi();
    const stubKeys = Object.keys(stub);

    for (const name of DRIFT_NAPI_METHOD_NAMES) {
      expect(stubKeys, `Missing stub method: ${name}`).toContain(name);
      expect(typeof stub[name], `${name} is not a function`).toBe('function');
    }
  });

  // TH-NAPI-07: Every stub returns value matching declared return type (not {})
  it('TH-NAPI-07: every stub returns value matching declared return type (not {})', () => {
    const stub = createStubNapi();

    // Sync methods — verify non-empty typed shapes
    const check = stub.driftCheck('.');
    expect(Object.keys(check).length).toBeGreaterThan(0);
    expect(check).toHaveProperty('overallPassed');
    expect(check).toHaveProperty('totalViolations');
    expect(check).toHaveProperty('gates');
    expect(check).toHaveProperty('sarif');

    const audit = stub.driftAudit('.');
    expect(Object.keys(audit).length).toBeGreaterThan(0);
    expect(audit).toHaveProperty('healthScore');
    expect(audit).toHaveProperty('breakdown');

    const coupling = stub.driftCouplingAnalysis('.');
    expect(Object.keys(coupling).length).toBeGreaterThan(0);
    expect(coupling).toHaveProperty('metrics');
    expect(coupling).toHaveProperty('cycles');
    expect(coupling).toHaveProperty('moduleCount');

    const patterns = stub.driftPatterns();
    expect(Object.keys(patterns).length).toBeGreaterThan(0);
    expect(patterns).toHaveProperty('patterns');
    expect(patterns).toHaveProperty('hasMore');
    expect(patterns).toHaveProperty('nextCursor');

    const reachability = stub.driftReachability('fn', 'forward');
    expect(Object.keys(reachability).length).toBeGreaterThan(0);
    expect(reachability).toHaveProperty('source');
    expect(reachability).toHaveProperty('reachableCount');
    expect(reachability).toHaveProperty('engine');

    const feedback = stub.driftDismissViolation({
      violationId: 'v1',
      action: 'dismiss',
    });
    expect(Object.keys(feedback).length).toBeGreaterThan(0);
    expect(feedback).toHaveProperty('success');
    expect(feedback).toHaveProperty('message');
  });

  // TH-NAPI-08: Async stubs return resolved Promises
  it('TH-NAPI-08: async stubs return resolved Promises', async () => {
    const stub = createStubNapi();

    // All async methods should resolve (not reject)
    const scanResult = await stub.driftScan('.');
    expect(scanResult).toBeDefined();
    expect(scanResult).toHaveProperty('filesTotal');

    const scanWithProgress = await stub.driftScanWithProgress('.', undefined, () => {});
    expect(scanWithProgress).toBeDefined();

    const analyzeResult = await stub.driftAnalyze();
    expect(Array.isArray(analyzeResult)).toBe(true);

    const callGraph = await stub.driftCallGraph();
    expect(callGraph).toHaveProperty('totalFunctions');

    const boundaries = await stub.driftBoundaries();
    expect(boundaries).toHaveProperty('models');

    const simulate = await stub.driftSimulate('refactor', 'test', '{}');
    expect(typeof simulate).toBe('string');
    expect(() => JSON.parse(simulate)).not.toThrow();

    const decisions = await stub.driftDecisions('.');
    expect(typeof decisions).toBe('string');
    expect(() => JSON.parse(decisions)).not.toThrow();

    const context = await stub.driftContext('fix_bug', 'standard', '{}');
    expect(typeof context).toBe('string');
    expect(() => JSON.parse(context)).not.toThrow();

    const spec = await stub.driftGenerateSpec('{}');
    expect(typeof spec).toBe('string');
    expect(() => JSON.parse(spec)).not.toThrow();
  });

  // TH-NAPI-09: driftIsInitialized() stub returns false
  it('TH-NAPI-09: driftIsInitialized() stub returns false', () => {
    const stub = createStubNapi();
    expect(stub.driftIsInitialized()).toBe(false);
  });

  // TH-NAPI-10: drift_violations() stub returns [], not null/undefined
  it('TH-NAPI-10: drift_violations() stub returns [], not null/undefined', () => {
    const stub = createStubNapi();
    const result = stub.driftViolations('.');
    expect(result).not.toBeNull();
    expect(result).not.toBeUndefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(0);
  });

  // TH-NAPI-11: drift_check() stub returns complete shape
  it('TH-NAPI-11: drift_check() stub returns { overallPassed: true, totalViolations: 0, gates: [], sarif: null }', () => {
    const stub = createStubNapi();
    const result = stub.driftCheck('.');
    expect(result.overallPassed).toBe(true);
    expect(result.totalViolations).toBe(0);
    expect(Array.isArray(result.gates)).toBe(true);
    expect(result.gates.length).toBe(0);
    expect(result.sarif).toBeNull();
  });
});
