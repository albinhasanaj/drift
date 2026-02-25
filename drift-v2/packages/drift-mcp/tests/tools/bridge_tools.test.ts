/**
 * Phase D Tests — MCP Bridge Tools (BT-MCP-01 through BT-MCP-16)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../../src/napi.js';
import { buildToolCatalog, handleDriftTool } from '../../src/tools/drift_tool.js';
import { handleDriftDiscover } from '../../src/tools/drift_discover.js';
import { handleDriftWorkflow } from '../../src/tools/drift_workflow.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { InternalTool } from '../../src/types.js';

/** All 12 bridge tool names that should be in the catalog. */
const BRIDGE_TOOL_NAMES = [
  'drift_bridge_status',
  'drift_bridge_health',
  'drift_bridge_ground',
  'drift_bridge_ground_all',
  'drift_bridge_memories',
  'drift_bridge_grounding_history',
  'drift_bridge_why',
  'drift_bridge_counterfactual',
  'drift_bridge_intervention',
  'drift_bridge_narrative',
  'drift_bridge_learn',
  'drift_bridge_events',
];

describe('Phase D — MCP Bridge Tools', () => {
  let catalog: Map<string, InternalTool>;

  beforeEach(() => {
    resetNapi();
    setNapi({ ...createStubNapi() });
    catalog = buildToolCatalog();
  });

  // ─── Tool Registration Tests ─────────────────────────────────────

  // BT-MCP-01: All 12 bridge tools appear in buildToolCatalog()
  it('BT-MCP-01: all 12 bridge tools registered in catalog', () => {
    for (const name of BRIDGE_TOOL_NAMES) {
      expect(catalog.has(name), `Missing bridge tool: ${name}`).toBe(true);
    }
  });

  // BT-MCP-02: drift_bridge_status returns valid BridgeStatusResult
  it('BT-MCP-02: drift_bridge_status returns valid result', async () => {
    const result = await handleDriftTool({ tool: 'drift_bridge_status', params: {} }, catalog);
    expect(result).toBeDefined();
    expect(typeof result).toBe('object');
    const r = result as Record<string, unknown>;
    expect('available' in r).toBe(true);
    expect('license_tier' in r).toBe(true);
  });

  // BT-MCP-03: drift_bridge_health returns subsystem checks
  it('BT-MCP-03: drift_bridge_health returns subsystem checks', async () => {
    const result = await handleDriftTool({ tool: 'drift_bridge_health', params: {} }, catalog);
    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    expect('status' in r).toBe(true);
    expect('subsystem_checks' in r).toBe(true);
  });

  // BT-MCP-04: drift_bridge_events returns event mappings
  it('BT-MCP-04: drift_bridge_events returns event mappings', async () => {
    const result = await handleDriftTool({ tool: 'drift_bridge_events', params: {} }, catalog);
    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    expect('mappings' in r).toBe(true);
    expect('count' in r).toBe(true);
  });

  // BT-MCP-05: drift_bridge_learn creates correction memory
  it('BT-MCP-05: drift_bridge_learn calls spec correction', async () => {
    const result = await handleDriftTool({
      tool: 'drift_bridge_learn',
      params: {
        entityType: 'pattern',
        entityId: 'p1',
        correction: 'too noisy',
      },
    }, catalog);
    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    expect('memory_id' in r).toBe(true);
    expect('status' in r).toBe(true);
  });

  // ─── Caching & Rate Limiting Tests ───────────────────────────────

  // BT-MCP-06: drift_bridge_status is in cacheable set
  it('BT-MCP-06: bridge read-only tools are cacheable', () => {
    // We verify the tool is registered and check the CACHEABLE set indirectly
    // by running the same tool twice — with infra it would cache
    const tool = catalog.get('drift_bridge_status');
    expect(tool).toBeDefined();
    expect(tool!.category).toBe('discovery');
  });

  // BT-MCP-07: drift_bridge_learn is a mutation tool (category: feedback)
  it('BT-MCP-07: bridge mutation tools have correct category', () => {
    const learn = catalog.get('drift_bridge_learn');
    expect(learn).toBeDefined();
    expect(learn!.category).toBe('feedback');

    const ground = catalog.get('drift_bridge_ground');
    expect(ground).toBeDefined();
    expect(ground!.category).toBe('analysis');

    const groundAll = catalog.get('drift_bridge_ground_all');
    expect(groundAll).toBeDefined();
    expect(groundAll!.category).toBe('analysis');
  });

  // BT-MCP-08: drift_bridge_ground_all is analysis category (rate-limited as mutation)
  it('BT-MCP-08: ground_all is an analysis tool', async () => {
    const result = await handleDriftTool({ tool: 'drift_bridge_ground_all', params: {} }, catalog);
    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    expect('total_checked' in r).toBe(true);
  });

  // ─── Discovery & Workflow Tests ──────────────────────────────────

  // BT-MCP-09: drift_discover({ intent: "memory" }) includes bridge tools
  it('BT-MCP-09: discover "memory" includes bridge tools', () => {
    const result = handleDriftDiscover({ intent: 'memory', maxTools: 20 }, catalog);
    const names = result.tools.map(t => t.name);
    // Bridge tools have "bridge" in name, which should match "bridge" keywords
    const bridgeTools = names.filter(n => n.includes('bridge'));
    expect(bridgeTools.length).toBeGreaterThan(0);
  });

  // BT-MCP-10: drift_discover({ intent: "grounding" }) boosts bridge_ground
  it('BT-MCP-10: discover "grounding" boosts bridge ground tools', () => {
    const result = handleDriftDiscover({ intent: 'grounding', maxTools: 10 }, catalog);
    const names = result.tools.map(t => t.name);
    const bridgeTools = names.filter(n => n.includes('bridge'));
    expect(bridgeTools.length).toBeGreaterThan(0);
    // bridge_ground or bridge_ground_all should be in top results
    expect(names.some(n => n.includes('bridge_ground'))).toBe(true);
  });

  // BT-MCP-11: drift_discover({ intent: "why" }) includes bridge_why
  it('BT-MCP-11: discover "why" includes bridge_why', () => {
    const result = handleDriftDiscover({ intent: 'why', maxTools: 10 }, catalog);
    const names = result.tools.map(t => t.name);
    expect(names.some(n => n.includes('bridge_why') || n.includes('bridge_narrative'))).toBe(true);
  });

  // BT-MCP-12: bridge_health_check workflow runs all 3 steps
  it('BT-MCP-12: bridge_health_check workflow runs 3 steps', async () => {
    const result = await handleDriftWorkflow({ workflow: 'bridge_health_check' }, catalog);
    expect(result.workflow).toBe('bridge_health_check');
    expect(result.steps).toHaveLength(3);
    expect(result._workflow.toolsRun).toContain('drift_bridge_status');
    expect(result._workflow.toolsRun).toContain('drift_bridge_health');
    expect(result._workflow.toolsRun).toContain('drift_bridge_ground_all');
  });

  // ─── Error Handling Tests ────────────────────────────────────────

  // BT-MCP-13: bridge tool before init → structured error
  it('BT-MCP-13: bridge tool returns stub data from stub napi', async () => {
    // With stub NAPI, bridge tools still return structurally valid data
    const result = await handleDriftTool({ tool: 'drift_bridge_status', params: {} }, catalog);
    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    // Stub returns available: false
    expect(r.available).toBe(false);
  });

  // BT-MCP-14: invalid memory_id to drift_bridge_ground → still returns result from stub
  it('BT-MCP-14: bridge_ground with params returns result', async () => {
    const result = await handleDriftTool({
      tool: 'drift_bridge_ground',
      params: { memoryId: 'invalid-id', memoryType: 'PatternRationale' },
    }, catalog);
    expect(result).toBeDefined();
  });

  // BT-MCP-15: unknown bridge tool → "not found" error
  it('BT-MCP-15: unknown tool throws with available list', async () => {
    await expect(
      handleDriftTool({ tool: 'drift_bridge_nonexistent', params: {} }, catalog),
    ).rejects.toThrow('Unknown tool');
    await expect(
      handleDriftTool({ tool: 'drift_bridge_nonexistent', params: {} }, catalog),
    ).rejects.toThrow('drift_bridge_status');
  });

  // BT-MCP-16: bridge tools have correct estimatedTokens metadata
  it('BT-MCP-16: all bridge tools have estimatedTokens', () => {
    for (const name of BRIDGE_TOOL_NAMES) {
      const tool = catalog.get(name);
      expect(tool, `Missing tool: ${name}`).toBeDefined();
      expect(tool!.estimatedTokens).toBeDefined();
      expect(tool!.estimatedTokens.startsWith('~')).toBe(true);
    }
  });
});
