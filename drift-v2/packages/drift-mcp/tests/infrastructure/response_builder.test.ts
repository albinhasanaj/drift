/**
 * Response Builder Tests — TH-RESP-01 through TH-RESP-05
 */

import { describe, it, expect } from 'vitest';
import { ResponseBuilder } from '../../src/infrastructure/response_builder.js';
import { TokenEstimator } from '../../src/infrastructure/token_estimator.js';

describe('Response Builder', () => {
  const estimator = new TokenEstimator();
  const builder = new ResponseBuilder(estimator);

  // TH-RESP-01: under-budget passthrough
  it('TH-RESP-01: under-budget response passes through unchanged', () => {
    const data = { violations: [], healthScore: 100 };
    const result = builder.build(data, 'No violations found', 10000);
    expect(result.violations).toEqual([]);
    expect(result.healthScore).toBe(100);
    expect(result._summary).toBe('No violations found');
    expect(result._tokenEstimate).toBeGreaterThan(0);
    expect(result._truncated).toBeUndefined();
  });

  // TH-RESP-02: truncation with _totalCount
  it('TH-RESP-02: over-budget response is truncated with _totalCount', () => {
    // Create a large array that exceeds a small budget
    const violations = Array.from({ length: 100 }, (_, i) => ({
      id: `v-${i}`,
      file: `/src/file-${i}.ts`,
      line: i,
      message: `Violation ${i}: ` + 'x'.repeat(50),
    }));
    const data = { violations, meta: 'kept' };

    // Very small budget to force truncation
    const result = builder.build(data, '100 violations found', 200);
    expect(result._truncated).toBe(true);
    expect(result._totalCount).toBeDefined();
    expect(result._totalCount).toBeGreaterThanOrEqual(100);
    expect((result.violations as unknown[]).length).toBeLessThan(100);
  });

  // TH-RESP-03: _summary present
  it('TH-RESP-03: _summary always present in response', () => {
    const data = { ok: true };
    const result = builder.build(data, 'All checks passed');
    expect(result._summary).toBe('All checks passed');
  });

  // TH-RESP-04: _tokenEstimate present
  it('TH-RESP-04: _tokenEstimate always present in response', () => {
    const data = { items: ['a', 'b', 'c'] };
    const result = builder.build(data, 'test');
    expect(result._tokenEstimate).toBeDefined();
    expect(typeof result._tokenEstimate).toBe('number');
    expect(result._tokenEstimate).toBeGreaterThan(0);
  });

  // TH-RESP-05: 0 items valid
  it('TH-RESP-05: empty data produces valid response', () => {
    const data = { items: [] as string[] };
    const result = builder.build(data, 'No items');
    expect(result.items).toEqual([]);
    expect(result._summary).toBe('No items');
    expect(result._tokenEstimate).toBeGreaterThan(0);
    expect(result._truncated).toBeUndefined();
  });
});
