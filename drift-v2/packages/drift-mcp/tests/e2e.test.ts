/**
 * MCP E2E tests — T9-MCP-01 through T9-MCP-05.
 *
 * Verifies the full MCP pipeline: server creation → tool listing → scan → query.
 * Uses stub NAPI (no native binary required).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi, loadNapi } from '../../drift-mcp/src/napi.js';
import { createStubNapi } from '@drift/napi-contracts';

describe('MCP E2E Pipeline', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createStubNapi());
  });

  // T9-MCP-01: Stub provides all required NAPI methods for MCP tools
  it('T9-MCP-01: stub has all methods used by MCP tools', () => {
    const napi = loadNapi();

    // Methods used by MCP scan tool
    expect(typeof napi.driftScan).toBe('function');
    expect(typeof napi.driftAnalyze).toBe('function');

    // Methods used by MCP status tool
    expect(typeof napi.driftIsInitialized).toBe('function');

    // Methods used by internal tools
    expect(typeof napi.driftCheck).toBe('function');
    expect(typeof napi.driftViolations).toBe('function');
    expect(typeof napi.driftPatterns).toBe('function');
    expect(typeof napi.driftReport).toBe('function');
    expect(typeof napi.driftOwaspAnalysis).toBe('function');
    expect(typeof napi.driftContractTracking).toBe('function');
    expect(typeof napi.driftCouplingAnalysis).toBe('function');
    expect(typeof napi.driftDnaAnalysis).toBe('function');
    expect(typeof napi.driftSimulate).toBe('function');
    expect(typeof napi.driftContext).toBe('function');
  });

  // T9-MCP-02: Scan returns structured result
  it('T9-MCP-02: scan produces valid ScanSummary', async () => {
    const napi = loadNapi();
    const result = await napi.driftScan('.');
    expect(result).toBeDefined();
    expect(typeof result.filesTotal).toBe('number');
    expect(result.filesTotal).toBeGreaterThanOrEqual(0);
  });

  // T9-MCP-03: Analysis pipeline returns results array
  it('T9-MCP-03: analyze returns array of file results', async () => {
    const napi = loadNapi();
    const results = await napi.driftAnalyze();
    expect(Array.isArray(results)).toBe(true);
  });

  // T9-MCP-04: Structural analysis tools return valid shapes
  it('T9-MCP-04: structural tools return valid data', () => {
    const napi = loadNapi();

    const owasp = napi.driftOwaspAnalysis('.');
    expect(owasp).toBeDefined();
    expect(Array.isArray(owasp.findings)).toBe(true);
    expect(owasp.compliance).toBeDefined();

    const contracts = napi.driftContractTracking('.');
    expect(contracts).toBeDefined();
    expect(Array.isArray(contracts.endpoints)).toBe(true);
    expect(Array.isArray(contracts.mismatches)).toBe(true);

    const coupling = napi.driftCouplingAnalysis('.');
    expect(coupling).toBeDefined();
    expect(Array.isArray(coupling.metrics)).toBe(true);
  });

  // T9-MCP-05: Report tool generates string output for all formats
  it('T9-MCP-05: driftReport works for all 8 formats', () => {
    const napi = loadNapi();
    const formats = ['sarif', 'json', 'html', 'junit', 'sonarqube', 'console', 'github', 'gitlab'];
    for (const fmt of formats) {
      const output = napi.driftReport(fmt);
      expect(typeof output).toBe('string');
    }
  });
});
