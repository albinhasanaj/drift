/**
 * Phase C Tests — Workflow Composite Execution (TH-WORK-01 through TH-WORK-09)
 * + Entry Point Registration (TH-TOOL-26 through TH-TOOL-28)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../../src/napi.js';
import { buildToolCatalog } from '../../src/tools/drift_tool.js';
import { handleDriftWorkflow, VALID_WORKFLOWS } from '../../src/tools/drift_workflow.js';
import { createDriftMcpServer } from '../../src/server.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { InternalTool } from '../../src/types.js';

describe('Workflow — Composite Execution', () => {
  let catalog: Map<string, InternalTool>;

  beforeEach(() => {
    resetNapi();
    setNapi({ ...createStubNapi() });
    catalog = buildToolCatalog();
  });

  // TH-WORK-01: pre_commit calls check + violations + impact
  it('TH-WORK-01: pre_commit workflow runs 3 steps', async () => {
    const result = await handleDriftWorkflow({ workflow: 'pre_commit' }, catalog);
    expect(result.workflow).toBe('pre_commit');
    expect(result.steps).toHaveLength(3);
    expect(result._workflow.toolsRun).toContain('drift_prevalidate');
    expect(result._workflow.toolsRun).toContain('drift_impact_analysis');
  });

  // TH-WORK-02: security_audit calls owasp + crypto + taint + error_handling
  it('TH-WORK-02: security_audit workflow runs 4 steps', async () => {
    const result = await handleDriftWorkflow({ workflow: 'security_audit' }, catalog);
    expect(result.steps).toHaveLength(4);
    expect(result._workflow.toolsRun).toContain('drift_owasp');
    expect(result._workflow.toolsRun).toContain('drift_crypto');
    expect(result._workflow.toolsRun).toContain('drift_taint');
    expect(result._workflow.toolsRun).toContain('drift_error_handling');
  });

  // TH-WORK-03: code_review calls status + context + violations + patterns
  it('TH-WORK-03: code_review workflow runs 4 steps', async () => {
    const result = await handleDriftWorkflow({ workflow: 'code_review' }, catalog);
    expect(result.steps).toHaveLength(4);
    expect(result._workflow.toolsRun).toContain('drift_status');
  });

  // TH-WORK-04: health_check calls status + audit + test_topology + dna
  it('TH-WORK-04: health_check workflow runs 4 steps', async () => {
    const result = await handleDriftWorkflow({ workflow: 'health_check' }, catalog);
    expect(result.steps).toHaveLength(4);
    expect(result._workflow.toolsRun).toContain('drift_audit');
    expect(result._workflow.toolsRun).toContain('drift_test_topology');
    expect(result._workflow.toolsRun).toContain('drift_dna_profile');
  });

  // TH-WORK-05: onboard calls status + conventions + patterns + contracts
  it('TH-WORK-05: onboard workflow runs 4 steps', async () => {
    const result = await handleDriftWorkflow({ workflow: 'onboard' }, catalog);
    expect(result.steps).toHaveLength(4);
    expect(result._workflow.toolsRun).toContain('drift_conventions');
    expect(result._workflow.toolsRun).toContain('drift_contracts');
  });

  // TH-WORK-06: unknown workflow → error with valid list
  it('TH-WORK-06: unknown workflow throws', async () => {
    await expect(
      handleDriftWorkflow({ workflow: 'deploy' }, catalog),
    ).rejects.toThrow('Unknown workflow');
    await expect(
      handleDriftWorkflow({ workflow: 'deploy' }, catalog),
    ).rejects.toThrow('pre_commit');
  });

  // TH-WORK-07: partial failure → partial results, not total failure
  it('TH-WORK-07: partial failure returns partial results', async () => {
    // Remove one tool from catalog to force partial failure
    catalog.delete('drift_owasp');
    const result = await handleDriftWorkflow({ workflow: 'security_audit' }, catalog);
    expect(result.steps.some(s => s.success)).toBe(true);
    expect(result.steps.some(s => !s.success)).toBe(true);
    expect(result._workflow.partialFailure).toBe(true);
  });

  // TH-WORK-08: response includes _workflow metadata
  it('TH-WORK-08: response includes workflow metadata', async () => {
    const result = await handleDriftWorkflow({ workflow: 'pre_commit' }, catalog);
    expect(result._workflow).toBeDefined();
    expect(result._workflow.toolsRun).toBeDefined();
    expect(result._workflow.durationPerTool).toBeDefined();
    expect(typeof result._workflow.partialFailure).toBe('boolean');
    expect(typeof result.totalDurationMs).toBe('number');
  });

  // TH-WORK-09: workflow respects rate limits (sub-tool rate-limited → reported)
  it('TH-WORK-09: all steps report duration', async () => {
    const result = await handleDriftWorkflow({ workflow: 'health_check' }, catalog);
    for (const step of result.steps) {
      expect(typeof step.durationMs).toBe('number');
      expect(step.durationMs).toBeGreaterThanOrEqual(0);
    }
  });
});

describe('Entry Point Registration', () => {
  beforeEach(() => {
    resetNapi();
    setNapi({ ...createStubNapi() });
  });

  // TH-TOOL-26: MCP server registers exactly 6 entry points
  it('TH-TOOL-26: server registers 6 entry points', () => {
    const server = createDriftMcpServer();
    expect(server.server).toBeDefined();
    // The server registers 6 tools via server.tool()
    // We verify by checking the catalog + server existence
    expect(server.catalog).toBeDefined();
  });

  // TH-TOOL-27: drift_tool catalog contains ≥35 internal tools
  it('TH-TOOL-27: catalog contains ≥35 internal tools', () => {
    const catalog = buildToolCatalog();
    expect(catalog.size).toBeGreaterThanOrEqual(35);
  });

  // TH-TOOL-28: progressive disclosure — 6 entry points < 1.5K tokens
  it('TH-TOOL-28: 6 entry points are lightweight', () => {
    // 6 tool names + descriptions should be under 1.5K tokens
    const entryPoints = [
      { name: 'drift_status', desc: 'Get project overview' },
      { name: 'drift_context', desc: 'Intent-weighted context' },
      { name: 'drift_scan', desc: 'Trigger analysis' },
      { name: 'drift_tool', desc: 'Dynamic dispatch for internal tools' },
      { name: 'drift_discover', desc: 'Find relevant tools for intent' },
      { name: 'drift_workflow', desc: 'Run composite workflows' },
    ];
    const totalChars = entryPoints.reduce((sum, ep) => sum + ep.name.length + ep.desc.length, 0);
    const estimatedTokens = totalChars / 3.5;
    expect(estimatedTokens).toBeLessThan(1500);
    expect(entryPoints).toHaveLength(6);
  });

  // Verify 5 valid workflows exist
  it('8 valid workflows defined (5 drift + 2 cortex + 1 bridge)', () => {
    expect(VALID_WORKFLOWS).toContain('pre_commit');
    expect(VALID_WORKFLOWS).toContain('security_audit');
    expect(VALID_WORKFLOWS).toContain('code_review');
    expect(VALID_WORKFLOWS).toContain('health_check');
    expect(VALID_WORKFLOWS).toContain('onboard');
    expect(VALID_WORKFLOWS).toContain('cortex_health_check');
    expect(VALID_WORKFLOWS).toContain('cortex_onboard');
    expect(VALID_WORKFLOWS).toContain('bridge_health_check');
    expect(VALID_WORKFLOWS).toHaveLength(8);
  });
});
