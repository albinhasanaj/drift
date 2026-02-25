/**
 * Cortex tool integration tests — verifies cortex tools are registered
 * in the drift_tool catalog and dispatch correctly via stub fallback.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../../src/napi.js';
import { buildToolCatalog, handleDriftTool } from '../../src/tools/drift_tool.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '@drift/napi-contracts';
import type { InternalTool } from '../../src/types.js';
import { CORTEX_CACHEABLE_TOOLS, CORTEX_MUTATION_TOOLS } from '../../src/tools/cortex_tools.js';

function createMock(): DriftNapi {
  return { ...createStubNapi() };
}

describe('cortex tools in drift_tool catalog', () => {
  let catalog: Map<string, InternalTool>;

  beforeEach(() => {
    resetNapi();
    setNapi(createMock());
    catalog = buildToolCatalog();
  });

  // ─── CT-E2E-04: Tool registry has 61+ tools with unique names ───
  it('catalog contains cortex tools', () => {
    const cortexTools = Array.from(catalog.keys()).filter(k => k.startsWith('cortex_'));
    expect(cortexTools.length).toBeGreaterThanOrEqual(61);
  });

  it('total catalog has at least 60 tools', () => {
    expect(catalog.size).toBeGreaterThanOrEqual(60);
  });

  it('no duplicate tool names', () => {
    const names = Array.from(catalog.keys());
    const unique = new Set(names);
    expect(unique.size).toBe(names.length);
  });

  // ─── CT-FIX-05: All tools have description and handler ──────────
  it('every tool has non-empty description and handler', () => {
    for (const [name, tool] of catalog) {
      expect(tool.description, `${name} missing description`).toBeTruthy();
      expect(typeof tool.handler, `${name} missing handler`).toBe('function');
      expect(tool.category, `${name} missing category`).toBeTruthy();
    }
  });

  // ─── Cortex cache/mutation sets are disjoint ────────────────────
  it('CORTEX_CACHEABLE_TOOLS and CORTEX_MUTATION_TOOLS are disjoint', () => {
    for (const tool of CORTEX_CACHEABLE_TOOLS) {
      expect(CORTEX_MUTATION_TOOLS.has(tool), `${tool} in both sets`).toBe(false);
    }
  });

  // ─── CT-FIX-09: Cortex MCP config defaults ─────────────────────
  it('DEFAULT_MCP_CONFIG has cortex defaults', async () => {
    const { DEFAULT_MCP_CONFIG } = await import('../../src/types.js');
    expect(DEFAULT_MCP_CONFIG.cortexEnabled).toBe(true);
    expect(DEFAULT_MCP_CONFIG.cortexDbPath).toBe('.cortex/cortex.db');
  });

  // ─── CT-E2E-10: calling cortex tool before init → structured error ─
  it('cortex tool returns structured error when cortex not initialized', async () => {
    const result = await handleDriftTool({ tool: 'cortex_status', params: {} }, catalog) as Record<string, unknown>;
    // ErrorHandler.wrap() converts thrown errors into structured error objects
    expect(result).toHaveProperty('code');
    expect(result).toHaveProperty('message');
    expect(String(result.message)).toMatch(/not initialized|Cortex/i);
  });

  // ─── CT-E2E-19: drift_discover with "cortex" returns cortex tools
  it('drift_discover for "cortex" returns cortex tools', async () => {
    const { handleDriftDiscover } = await import('../../src/tools/drift_discover.js');
    const result = handleDriftDiscover({ intent: 'cortex memory' }, catalog);
    expect(result.tools.length).toBeGreaterThan(0);
    const cortexResults = result.tools.filter(t => t.name.startsWith('cortex_'));
    expect(cortexResults.length).toBeGreaterThan(0);
  });

  // ─── Workflow registration ──────────────────────────────────────
  it('cortex workflows are registered', async () => {
    const { VALID_WORKFLOWS } = await import('../../src/tools/drift_workflow.js');
    expect(VALID_WORKFLOWS).toContain('cortex_health_check');
    expect(VALID_WORKFLOWS).toContain('cortex_onboard');
  });

  // ─── Unknown tool error ─────────────────────────────────────────
  it('unknown cortex tool throws helpful error', async () => {
    await expect(
      handleDriftTool({ tool: 'cortex_nonexistent', params: {} }, catalog),
    ).rejects.toThrow(/Unknown tool.*cortex_nonexistent/);
  });

  // ─── Category check ─────────────────────────────────────────────
  it('all cortex tools have category "cortex"', () => {
    for (const [name, tool] of catalog) {
      if (name.startsWith('cortex_')) {
        expect(tool.category, `${name} wrong category`).toBe('cortex');
      }
    }
  });

  // ─── Estimated tokens ───────────────────────────────────────────
  it('all cortex tools have estimatedTokens', () => {
    for (const [name, tool] of catalog) {
      if (name.startsWith('cortex_')) {
        expect(tool.estimatedTokens, `${name} missing estimatedTokens`).toBeTruthy();
      }
    }
  });
});
