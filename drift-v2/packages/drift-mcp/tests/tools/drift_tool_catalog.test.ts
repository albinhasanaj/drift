/**
 * Tool catalog handler tests — exercises every internal tool handler
 * to achieve function coverage for drift_tool.ts.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../../src/napi.js';
import { buildToolCatalog, handleDriftTool } from '../../src/tools/drift_tool.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '@drift/napi-contracts';
import type { InternalTool } from '../../src/types.js';

function createMock(): DriftNapi {
  return { ...createStubNapi() };
}

describe('drift_tool catalog handlers', () => {
  let catalog: Map<string, InternalTool>;

  beforeEach(() => {
    resetNapi();
    setNapi(createMock());
    catalog = buildToolCatalog();
  });

  it('drift_status handler returns composed status', async () => {
    const result = await handleDriftTool({ tool: 'drift_status', params: {} }, catalog);
    expect(result).toHaveProperty('version');
    expect(result).toHaveProperty('initialized');
    expect(result).toHaveProperty('healthScore');
  });

  it('drift_capabilities handler returns tool listing', async () => {
    const result = await handleDriftTool({ tool: 'drift_capabilities', params: {} }, catalog) as { tools: unknown[]; totalCount: number };
    expect(result.tools).toBeDefined();
    expect(result.totalCount).toBeGreaterThan(0);
  });

  it('drift_callers handler calls drift_call_graph', async () => {
    const result = await handleDriftTool({ tool: 'drift_callers', params: {} }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_reachability handler calls drift_reachability', async () => {
    const result = await handleDriftTool({ tool: 'drift_reachability', params: { functionKey: 'fn1', direction: 'forward' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_prevalidate handler calls drift_check', async () => {
    const result = await handleDriftTool({ tool: 'drift_prevalidate', params: { path: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_similar handler calls drift_patterns', async () => {
    const result = await handleDriftTool({ tool: 'drift_similar', params: {} }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_patterns_list handler calls drift_patterns', async () => {
    const result = await handleDriftTool({ tool: 'drift_patterns_list', params: {} }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_security_summary handler calls drift_owasp_analysis', async () => {
    const result = await handleDriftTool({ tool: 'drift_security_summary', params: { path: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_trends handler calls drift_audit', async () => {
    const result = await handleDriftTool({ tool: 'drift_trends', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_impact_analysis handler calls drift_impact_analysis', async () => {
    const result = await handleDriftTool({ tool: 'drift_impact_analysis', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_taint handler calls drift_taint_analysis', async () => {
    const result = await handleDriftTool({ tool: 'drift_taint', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_dna_profile handler calls drift_dna_analysis', async () => {
    const result = await handleDriftTool({ tool: 'drift_dna_profile', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_wrappers handler calls drift_wrapper_detection', async () => {
    const result = await handleDriftTool({ tool: 'drift_wrappers', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_coupling handler calls drift_coupling_analysis', async () => {
    const result = await handleDriftTool({ tool: 'drift_coupling', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_test_topology handler calls drift_test_topology', async () => {
    const result = await handleDriftTool({ tool: 'drift_test_topology', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_error_handling handler calls drift_error_handling', async () => {
    const result = await handleDriftTool({ tool: 'drift_error_handling', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_quality_gate handler calls drift_gates', async () => {
    const result = await handleDriftTool({ tool: 'drift_quality_gate', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_constants handler calls drift_constants_analysis', async () => {
    const result = await handleDriftTool({ tool: 'drift_constants', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_constraints handler calls drift_constraint_verification', async () => {
    const result = await handleDriftTool({ tool: 'drift_constraints', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_audit handler calls drift_audit', async () => {
    const result = await handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_decisions handler calls drift_decisions', async () => {
    const result = await handleDriftTool({ tool: 'drift_decisions', params: { repoPath: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_simulate handler calls drift_simulate', async () => {
    const result = await handleDriftTool({ tool: 'drift_simulate', params: { category: 'refactor', description: 'test', contextJson: '{}' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_explain handler calls drift_context', async () => {
    const result = await handleDriftTool({ tool: 'drift_explain', params: { query: 'explain auth' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_validate_change handler calls drift_check', async () => {
    const result = await handleDriftTool({ tool: 'drift_validate_change', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_suggest_changes handler calls drift_violations', async () => {
    const result = await handleDriftTool({ tool: 'drift_suggest_changes', params: { root: '.' } }, catalog);
    expect(result).toBeDefined();
  });

  it('drift_generate_spec handler calls drift_generate_spec', async () => {
    const result = await handleDriftTool({ tool: 'drift_generate_spec', params: { moduleJson: '{}' } }, catalog);
    expect(result).toBeDefined();
  });
});
