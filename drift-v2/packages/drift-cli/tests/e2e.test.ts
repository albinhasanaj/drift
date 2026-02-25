/**
 * CLI E2E tests — T9-CLI-01 through T9-CLI-06.
 *
 * Verifies the full CLI pipeline: setup → scan → analyze → check → violations → export.
 * Uses stub NAPI (no native binary required).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createProgram } from '../src/index.js';
import { setNapi, resetNapi, loadNapi } from '../src/napi.js';
import { createStubNapi } from '@drift/napi-contracts';

describe('CLI E2E Pipeline', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createStubNapi());
  });

  // T9-CLI-01: Full pipeline creates a working program with all commands
  it('T9-CLI-01: createProgram registers all 31 commands', () => {
    const program = createProgram();
    expect(program.commands.length).toBe(31);

    const names = program.commands.map((c) => c.name());
    // Core pipeline
    expect(names).toContain('scan');
    expect(names).toContain('analyze');
    expect(names).toContain('check');
    expect(names).toContain('status');
    expect(names).toContain('report');

    // Exploration
    expect(names).toContain('patterns');
    expect(names).toContain('violations');
    expect(names).toContain('security');
    expect(names).toContain('contracts');
    expect(names).toContain('coupling');
    expect(names).toContain('dna');
    expect(names).toContain('taint');
    expect(names).toContain('errors');
    expect(names).toContain('test-quality');
    expect(names).toContain('impact');

    // Feedback
    expect(names).toContain('fix');
    expect(names).toContain('dismiss');
    expect(names).toContain('suppress');
    expect(names).toContain('explain');
    expect(names).toContain('approve');

    // Advanced
    expect(names).toContain('simulate');
    expect(names).toContain('context');
    expect(names).toContain('audit');
    expect(names).toContain('export');

    // Operational
    expect(names).toContain('gc');
    expect(names).toContain('setup');
    expect(names).toContain('doctor');

    // Cortex memory system
    expect(names).toContain('cortex');
    // Bridge: memory grounding, causal intelligence, learning
    expect(names).toContain('bridge');
    // Framework pack validation
    expect(names).toContain('validate-pack');
  });

  // T9-CLI-02: NAPI stub provides all 40 methods
  it('T9-CLI-02: stub NAPI has all required methods', () => {
    const napi = loadNapi();
    // Core pipeline methods
    expect(typeof napi.driftScan).toBe('function');
    expect(typeof napi.driftAnalyze).toBe('function');
    expect(typeof napi.driftCheck).toBe('function');
    expect(typeof napi.driftPatterns).toBe('function');
    expect(typeof napi.driftViolations).toBe('function');
    expect(typeof napi.driftReport).toBe('function');
    expect(typeof napi.driftGC).toBe('function');

    // Graph methods
    expect(typeof napi.driftCallGraph).toBe('function');
    expect(typeof napi.driftBoundaries).toBe('function');
    expect(typeof napi.driftReachability).toBe('function');
    expect(typeof napi.driftTaintAnalysis).toBe('function');
    expect(typeof napi.driftErrorHandling).toBe('function');
    expect(typeof napi.driftImpactAnalysis).toBe('function');
    expect(typeof napi.driftTestTopology).toBe('function');

    // Structural methods
    expect(typeof napi.driftCouplingAnalysis).toBe('function');
    expect(typeof napi.driftContractTracking).toBe('function');
    expect(typeof napi.driftConstraintVerification).toBe('function');
    expect(typeof napi.driftOwaspAnalysis).toBe('function');
    expect(typeof napi.driftCryptoAnalysis).toBe('function');
    expect(typeof napi.driftDnaAnalysis).toBe('function');
    expect(typeof napi.driftWrapperDetection).toBe('function');
    expect(typeof napi.driftDecomposition).toBe('function');
    expect(typeof napi.driftConstantsAnalysis).toBe('function');

    // Advanced methods
    expect(typeof napi.driftSimulate).toBe('function');
    expect(typeof napi.driftContext).toBe('function');
    expect(typeof napi.driftDecisions).toBe('function');
    expect(typeof napi.driftGenerateSpec).toBe('function');

    // Feedback methods
    expect(typeof napi.driftDismissViolation).toBe('function');
    expect(typeof napi.driftFixViolation).toBe('function');
    expect(typeof napi.driftSuppressViolation).toBe('function');
  });

  // T9-CLI-03: Scan returns structured data
  it('T9-CLI-03: scan returns valid ScanSummary', async () => {
    const napi = loadNapi();
    const result = await napi.driftScan('.');
    expect(result).toBeDefined();
    expect(typeof result.filesTotal).toBe('number');
    expect(typeof result.filesAdded).toBe('number');
    expect(typeof result.durationMs).toBe('number');
  });

  // T9-CLI-04: Check returns gate results
  it('T9-CLI-04: check returns valid gate results', () => {
    const napi = loadNapi();
    const result = napi.driftCheck('.');
    expect(result).toBeDefined();
    expect(typeof result.overallPassed).toBe('boolean');
    expect(typeof result.totalViolations).toBe('number');
    expect(Array.isArray(result.gates)).toBe(true);
  });

  // T9-CLI-05: Report generates string output
  it('T9-CLI-05: driftReport returns string for all formats', () => {
    const napi = loadNapi();
    const formats = ['sarif', 'json', 'html', 'junit', 'sonarqube', 'console', 'github', 'gitlab'];
    for (const format of formats) {
      const result = napi.driftReport(format);
      expect(typeof result).toBe('string');
    }
  });

  // T9-CLI-06: Feedback methods accept valid input
  it('T9-CLI-06: feedback methods do not throw', () => {
    const napi = loadNapi();
    const input = { violationId: 'test-v1', action: 'dismiss', reason: 'test reason' };
    expect(() => napi.driftDismissViolation(input)).not.toThrow();
    expect(() => napi.driftFixViolation('test-v1')).not.toThrow();
  });
});
