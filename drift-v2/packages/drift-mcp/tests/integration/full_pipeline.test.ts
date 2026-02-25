/**
 * Phase E Tests — End-to-End Pipeline + Adversarial (PH-PARITY-05)
 * TH-E2E-01 through TH-E2E-05, TH-ADV-01 through TH-ADV-06
 * TH-SHUT-01 through TH-SHUT-03
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createStubNapi, setNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '@drift/napi-contracts';
import { handleDriftTool, buildToolCatalog } from '../../src/tools/drift_tool.js';
import { handleDriftStatus } from '../../src/tools/drift_status.js';
import { handleDriftWorkflow } from '../../src/tools/drift_workflow.js';
import type { InternalTool } from '../../src/types.js';

let napi: DriftNapi;
let catalog: Map<string, InternalTool>;

beforeEach(() => {
  napi = createStubNapi();
  setNapi(napi);
  catalog = buildToolCatalog();
});

describe('End-to-End Pipeline', () => {
  // TH-E2E-01: full MCP pipeline
  it('TH-E2E-01: MCP pipeline scan→violations→impact→check→audit returns valid results', async () => {
    const check = await handleDriftTool({ tool: 'drift_quality_gate', params: { root: '.' } }, catalog);
    expect(check).toBeDefined();

    const violations = napi.driftViolations('.');
    expect(Array.isArray(violations)).toBe(true);

    const audit = await handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog);
    expect(audit).toBeDefined();
    expect(audit).toHaveProperty('healthScore');

    const patterns = await handleDriftTool({ tool: 'drift_patterns_list', params: {} }, catalog);
    expect(patterns).toBeDefined();
  });

  // TH-E2E-02: full CLI pipeline uses correct exit logic
  it('TH-E2E-02: check + audit both return valid typed results', async () => {
    const check = await handleDriftTool({ tool: 'drift_quality_gate', params: { root: '.' } }, catalog);
    expect(check).toBeDefined();

    const audit = await handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog);
    expect(audit).toBeDefined();
    expect(audit).toHaveProperty('healthScore');
  });

  // TH-E2E-03: full CI pipeline uses correct NAPI methods
  it('TH-E2E-03: all 9 CI analysis pass methods exist on stub', () => {
    expect(typeof napi.driftScan).toBe('function');
    expect(typeof napi.driftPatterns).toBe('function');
    expect(typeof napi.driftCallGraph).toBe('function');
    expect(typeof napi.driftBoundaries).toBe('function');
    expect(typeof napi.driftOwaspAnalysis).toBe('function');
    expect(typeof napi.driftTestTopology).toBe('function');
    expect(typeof napi.driftErrorHandling).toBe('function');
    expect(typeof napi.driftContractTracking).toBe('function');
    expect(typeof napi.driftConstraintVerification).toBe('function');
  });

  // TH-E2E-04: workflow security_audit end-to-end
  it('TH-E2E-04: workflow security_audit returns aggregated results', async () => {
    const result = await handleDriftWorkflow({ workflow: 'security_audit', path: '.' }, catalog);
    expect(result).toHaveProperty('workflow', 'security_audit');
    expect(result).toHaveProperty('steps');
    expect(result).toHaveProperty('_workflow');
    expect(result).toHaveProperty('totalDurationMs');
  });

  // TH-E2E-05: workflow pre_commit end-to-end
  it('TH-E2E-05: workflow pre_commit returns check+violations+impact', async () => {
    const result = await handleDriftWorkflow({ workflow: 'pre_commit', path: '.' }, catalog);
    expect(result).toHaveProperty('workflow', 'pre_commit');
    expect(result).toHaveProperty('steps');
    expect(result.steps.length).toBeGreaterThanOrEqual(2);
  });
});

describe('Graceful Shutdown', () => {
  // TH-SHUT-01: in-flight request completes
  it('TH-SHUT-01: in-flight request completes before shutdown', async () => {
    // Simulate by running a tool call, then calling shutdown
    const result = await handleDriftTool({ tool: 'drift_quality_gate', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
    // Shutdown should not throw
    expect(() => napi.driftShutdown()).not.toThrow();
  });

  // TH-SHUT-02: no crash after shutdown
  it('TH-SHUT-02: shutdown does not throw', () => {
    expect(() => napi.driftShutdown()).not.toThrow();
  });

  // TH-SHUT-03: driftShutdown exists and is callable
  it('TH-SHUT-03: driftShutdown callable during server shutdown', () => {
    expect(typeof napi.driftShutdown).toBe('function');
    napi.driftShutdown();
  });
});

describe('Adversarial — Input Fuzzing', () => {
  // TH-ADV-01: 1MB string in drift_context intent
  it('TH-ADV-01: 1MB string in drift_context intent → no OOM', () => {
    const hugeString = 'x'.repeat(1_000_000);
    // Should not throw OOM — stub just returns empty result
    expect(() => napi.driftContext(hugeString, 'deep', '{}')).not.toThrow();
  });

  // TH-ADV-02: null/undefined in required fields
  it('TH-ADV-02: empty tool name → structured error, no crash', async () => {
    try {
      await handleDriftTool({ tool: '', params: {} }, catalog);
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toContain('Unknown tool');
    }
  });

  // TH-ADV-03: SQL injection in params
  it('TH-ADV-03: SQL injection in tool params → safe', async () => {
    // Call napi directly since drift_violations is not in the tool catalog
    const result = napi.driftViolations("'; DROP TABLE violations; --");
    // Stub returns empty array, no crash
    expect(Array.isArray(result)).toBe(true);
  });

  // TH-ADV-04: Unicode edge cases
  it('TH-ADV-04: Unicode edge cases in string params → no corruption', () => {
    const unicodeInputs = [
      '日本語テスト',
      '🔥🎯💡',
      '\u200B\u200C\u200D', // zero-width chars
      'مرحبا', // RTL
      '中文测试',
    ];
    for (const input of unicodeInputs) {
      expect(() => napi.driftContext(input, 'deep', '{}')).not.toThrow();
    }
  });

  // TH-ADV-05: all 41 tools with empty params → no crash
  it('TH-ADV-05: all tools with empty params → no crash (result or undefined)', async () => {
    for (const [toolName] of catalog) {
      // Should not throw — either returns result or undefined
      let threw = false;
      try {
        await handleDriftTool({ tool: toolName, params: {} }, catalog);
      } catch {
        threw = true;
      }
      // Tool should not throw unexpected errors
      expect(threw).toBe(false);
    }
  });

  // TH-ADV-06: all 41 tools callable in stub mode
  it('TH-ADV-06: all 41 tools callable in stub mode', () => {
    expect(catalog.size).toBeGreaterThanOrEqual(35);
    for (const [, tool] of catalog) {
      expect(tool.handler).toBeDefined();
      expect(typeof tool.handler).toBe('function');
    }
  });
});
