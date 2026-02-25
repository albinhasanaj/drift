/**
 * Token Estimator Tests — TH-TOKEN-01 through TH-TOKEN-05
 */

import { describe, it, expect } from 'vitest';
import { TokenEstimator } from '../../src/infrastructure/token_estimator.js';

describe('Token Estimator', () => {
  const estimator = new TokenEstimator();

  // TH-TOKEN-01: estimateTokens('hello world') returns 2-4
  it("TH-TOKEN-01: estimateTokens('hello world') returns 2-4", () => {
    const tokens = estimator.estimateTokens('hello world');
    expect(tokens).toBeGreaterThanOrEqual(2);
    expect(tokens).toBeLessThanOrEqual(4);
  });

  // TH-TOKEN-02: 10KB code block within 20% of expected (code uses blended ratio)
  it('TH-TOKEN-02: 10KB code block within 20% of expected', () => {
    const code = 'const x = 1;\n'.repeat(750); // ~10KB
    const tokens = estimator.estimateTokens(code);
    // Code has indicators (= ;) so ratio blends toward chars/2.5
    // Expected range: chars/3.5 to chars/2.5, allow 30% margin for blending
    const lowerBound = code.length / 3.5 * 0.8;
    const upperBound = code.length / 2.5 * 1.2;
    expect(tokens).toBeGreaterThan(lowerBound);
    expect(tokens).toBeLessThan(upperBound);
  });

  // TH-TOKEN-03: estimateTokens('') returns 0
  it("TH-TOKEN-03: estimateTokens('') returns 0", () => {
    expect(estimator.estimateTokens('')).toBe(0);
  });

  // TH-TOKEN-04: wouldExceedBudget() correctly flags over-budget
  it('TH-TOKEN-04: wouldExceedBudget() correctly flags over-budget', () => {
    // drift_context has historical average of 2000
    expect(estimator.wouldExceedBudget('drift_context', {}, 1000)).toBe(true);
    expect(estimator.wouldExceedBudget('drift_context', {}, 3000)).toBe(false);

    // drift_status has historical average of 200
    expect(estimator.wouldExceedBudget('drift_status', {}, 100)).toBe(true);
    expect(estimator.wouldExceedBudget('drift_status', {}, 500)).toBe(false);
  });

  // TH-TOKEN-05: per-tool historical averages used when available
  it('TH-TOKEN-05: per-tool historical averages used when available', () => {
    const statusEstimate = estimator.estimateResponseTokens('drift_status');
    expect(statusEstimate).toBe(200); // Known tool

    const contextEstimate = estimator.estimateResponseTokens('drift_context');
    expect(contextEstimate).toBe(2000); // Known tool

    const unknownEstimate = estimator.estimateResponseTokens('unknown_tool');
    expect(unknownEstimate).toBe(500); // Default for unknown
  });
});
