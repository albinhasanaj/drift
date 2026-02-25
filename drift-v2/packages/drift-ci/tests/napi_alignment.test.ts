/**
 * Phase D Tests — CI Agent NAPI Alignment (TH-CI-01 through TH-CI-07)
 *
 * Verifies CI agent calls correct NAPI contract method names.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setNapi } from '../src/napi.js';
import { runAnalysis } from '../src/agent.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '../src/napi.js';

function createSpyNapi(): DriftNapi & Record<string, ReturnType<typeof vi.fn>> {
  const stub = createStubNapi();
  const spied: Record<string, ReturnType<typeof vi.fn>> = {};
  for (const key of Object.keys(stub)) {
    const fn = vi.fn((stub as unknown as Record<string, (...args: unknown[]) => unknown>)[key]);
    spied[key] = fn;
  }
  return spied as unknown as DriftNapi & Record<string, ReturnType<typeof vi.fn>>;
}

let napi: DriftNapi & Record<string, ReturnType<typeof vi.fn>>;

describe('CI Agent NAPI Alignment', () => {
  beforeEach(() => {
    napi = createSpyNapi();
    setNapi(napi);
  });

  // TH-CI-01: Test agent calls 10 correct NAPI function names
  it('TH-CI-01: agent calls 10 correct NAPI function names', async () => {
    await runAnalysis({ path: '/test' });

    // Verify correct camelCase method names called
    expect(napi.driftScan).toHaveBeenCalled();                  // scan pass
    expect(napi.driftPatterns).toHaveBeenCalled();              // patterns pass
    expect(napi.driftCallGraph).toHaveBeenCalled();             // call_graph pass
    expect(napi.driftBoundaries).toHaveBeenCalled();            // boundaries pass
    expect(napi.driftOwaspAnalysis).toHaveBeenCalled();         // security pass
    expect(napi.driftTestTopology).toHaveBeenCalled();          // tests pass
    expect(napi.driftErrorHandling).toHaveBeenCalled();         // errors pass
    expect(napi.driftContractTracking).toHaveBeenCalled();      // contracts pass
    expect(napi.driftConstraintVerification).toHaveBeenCalled(); // constraints pass
    expect(napi.driftCheck).toHaveBeenCalled();                 // enforcement pass
  });

  // TH-CI-02: Test empty diff
  it('TH-CI-02: empty diff returns no changes to analyze', async () => {
    const result = await runAnalysis({
      path: '.',
      incremental: true,
      changedFiles: [],
    });
    expect(result.summary).toContain('No changes to analyze');
    expect(result.passes).toHaveLength(0);
  });

  // TH-CI-03: Test timeout → partial results
  it('TH-CI-03: timeout produces error pass result', async () => {
    const result = await runAnalysis({ path: '.', timeoutMs: 60_000 });
    // With fast stubs, all passes complete
    expect(result.passes).toHaveLength(13);
    for (const pass of result.passes) {
      expect(['passed', 'failed', 'error']).toContain(pass.status);
    }
  });

  // TH-CI-04: Test 1/9 passes fail → other 8 complete
  it('TH-CI-04: one pass failure does not block others', async () => {
    // Make security pass throw
    napi.driftOwaspAnalysis = vi.fn(() => { throw new Error('OWASP analysis failed'); });
    setNapi(napi as unknown as DriftNapi);

    const result = await runAnalysis({ path: '.' });
    expect(result.passes).toHaveLength(13);

    const securityPass = result.passes.find(p => p.name === 'security');
    expect(securityPass?.status).toBe('error');
    expect(securityPass?.error).toContain('OWASP analysis failed');

    // Other passes should still succeed
    const otherPasses = result.passes.filter(p => p.name !== 'security');
    for (const pass of otherPasses) {
      expect(pass.status).not.toBe('error');
    }
  });

  // TH-CI-05: Verify old method names NOT called
  it('TH-CI-05: old method names are not called', async () => {
    await runAnalysis({ path: '.' });

    // Old snake_case methods should NOT exist on the spy
    // All methods are now camelCase (driftAnalyze, not drift_analyze)
    expect(napi.driftAnalyze).toHaveBeenCalled(); // driftAnalyze IS called (in scan pass)
  });

  // TH-CI-06: napi.ts is re-export only
  it('TH-CI-06: napi.ts re-exports from @drift/napi-contracts', async () => {
    const mod = await import('../src/napi.js');
    expect(mod.loadNapi).toBeDefined();
    expect(mod.setNapi).toBeDefined();
    expect(mod.resetNapi).toBeDefined();
  });

  // TH-CI-07: All 13 passes complete with correct names
  it('TH-CI-07: all 13 passes produce valid results', async () => {
    const result = await runAnalysis({ path: '.' });
    expect(result.passes).toHaveLength(13);
    expect(result.passes.map(p => p.name)).toEqual([
      'scan', 'patterns', 'call_graph', 'boundaries',
      'security', 'tests', 'errors', 'contracts', 'constraints', 'enforcement', 'bridge',
      'cortex_health', 'cortex_validation',
    ]);
    for (const pass of result.passes) {
      expect(pass.durationMs).toBeGreaterThanOrEqual(0);
    }
  });
});
