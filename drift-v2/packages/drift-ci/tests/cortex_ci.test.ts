/**
 * Cortex CI Agent Tests — CH-T04 through CH-T09.
 *
 * Verifies cortex_health and cortex_validation passes integrate into
 * the CI agent, --no-cortex flag, cortexEnabled config, PR comment output,
 * and pass count updates.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../src/napi.js';
import { runAnalysis, type CiAgentConfig } from '../src/agent.js';
import { generatePrComment } from '../src/pr_comment.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '../src/napi.js';

function createMockNapi(overrides: Partial<DriftNapi> = {}): DriftNapi {
  return { ...createStubNapi(), ...overrides };
}

describe('Cortex CI Passes', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createMockNapi());
  });

  // CH-T04: cortex_health pass appears in results
  it('CH-T04: cortex_health pass is included in analysis results', async () => {
    const result = await runAnalysis({ path: '.' });
    const cortexHealthPass = result.passes.find(p => p.name === 'cortex_health');
    expect(cortexHealthPass).toBeDefined();
    expect(['passed', 'failed', 'error']).toContain(cortexHealthPass!.status);
    expect(cortexHealthPass!.durationMs).toBeGreaterThanOrEqual(0);
  });

  // CH-T05: cortex_validation pass appears in results
  it('CH-T05: cortex_validation pass is included in analysis results', async () => {
    const result = await runAnalysis({ path: '.' });
    const cortexValidationPass = result.passes.find(p => p.name === 'cortex_validation');
    expect(cortexValidationPass).toBeDefined();
    expect(['passed', 'failed', 'error']).toContain(cortexValidationPass!.status);
    expect(cortexValidationPass!.durationMs).toBeGreaterThanOrEqual(0);
  });

  // CH-T06: cortex passes skip gracefully when cortex not initialized
  it('CH-T06: cortex passes skip gracefully when not initialized', async () => {
    const result = await runAnalysis({ path: '.' });
    const cortexHealthPass = result.passes.find(p => p.name === 'cortex_health');
    // Without native binary, passes skip gracefully
    expect(cortexHealthPass!.status).toBe('passed');
    const data = cortexHealthPass!.data as Record<string, unknown>;
    expect(data.skipped).toBe(true);
  });

  // CH-T07: --no-cortex flag disables cortex passes
  it('CH-T07: cortexEnabled=false skips cortex passes', async () => {
    const result = await runAnalysis({ path: '.', cortexEnabled: false });
    const cortexHealthPass = result.passes.find(p => p.name === 'cortex_health');
    const cortexValidationPass = result.passes.find(p => p.name === 'cortex_validation');
    expect(cortexHealthPass).toBeUndefined();
    expect(cortexValidationPass).toBeUndefined();
    // Should have 11 passes (10 drift + 1 bridge)
    expect(result.passes).toHaveLength(11);
  });

  // CH-T08: cortexEnabled default is true
  it('CH-T08: cortexEnabled defaults to true', async () => {
    const result = await runAnalysis({ path: '.' });
    const cortexHealthPass = result.passes.find(p => p.name === 'cortex_health');
    expect(cortexHealthPass).toBeDefined();
    expect(result.passes).toHaveLength(13);
  });

  // CH-T09: cortex summary wired into PR comment
  it('CH-T09: PR comment includes cortex section when cortexSummary present', () => {
    const mockResult = {
      status: 'passed' as const,
      totalViolations: 0,
      score: 95,
      passes: [],
      durationMs: 100,
      summary: 'All clean',
      filesAnalyzed: 10,
      incremental: false,
      cortexSummary: {
        available: true,
        overallStatus: 'healthy',
        subsystemCount: 8,
        degradationCount: 0,
        validationCandidates: 3,
        badge: '✅' as const,
      },
    };

    const comment = generatePrComment(mockResult);
    expect(comment.markdown).toContain('Cortex Memory Health');
    expect(comment.markdown).toContain('healthy');
    expect(comment.markdown).toContain('8 subsystems');
    expect(comment.markdown).toContain('0 degradations');
    expect(comment.markdown).toContain('3 validation candidates');
  });

  // CH-T09b: PR comment omits cortex section when no cortexSummary
  it('CH-T09b: PR comment omits cortex section when cortexSummary absent', async () => {
    const result = await runAnalysis({ path: '.', cortexEnabled: false });
    const comment = generatePrComment(result);
    expect(comment.markdown).not.toContain('Cortex Memory Health');
  });

  // Both cortex and bridge can be disabled independently
  it('cortex and bridge flags are independent', async () => {
    const result = await runAnalysis({
      path: '.',
      cortexEnabled: false,
      bridgeEnabled: false,
    });
    expect(result.passes).toHaveLength(10);
    expect(result.passes.find(p => p.name === 'cortex_health')).toBeUndefined();
    expect(result.passes.find(p => p.name === 'bridge')).toBeUndefined();
  });

  // Pass order is deterministic
  it('pass order includes cortex after bridge', async () => {
    const result = await runAnalysis({ path: '.' });
    const names = result.passes.map(p => p.name);
    const bridgeIdx = names.indexOf('bridge');
    const cortexHealthIdx = names.indexOf('cortex_health');
    const cortexValidationIdx = names.indexOf('cortex_validation');
    expect(bridgeIdx).toBeLessThan(cortexHealthIdx);
    expect(cortexHealthIdx).toBeLessThan(cortexValidationIdx);
  });
});
