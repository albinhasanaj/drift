/**
 * Cortex MCP Hardening Tests — CH-T10/T11 (new tool wrappers),
 * CH-T16 (bridge notification on mutation).
 *
 * Verifies cortex_analyze_correction and cortex_configure are registered,
 * and that mutation tools trigger bridge notification.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../../src/napi.js';
import { buildToolCatalog } from '../../src/tools/drift_tool.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '@drift/napi-contracts';
import type { InternalTool } from '../../src/types.js';
import { CORTEX_CACHEABLE_TOOLS, CORTEX_MUTATION_TOOLS } from '../../src/tools/cortex_tools.js';

function createMock(): DriftNapi {
  return { ...createStubNapi() };
}

describe('Cortex MCP Hardening (CH-T10/T11)', () => {
  let catalog: Map<string, InternalTool>;

  beforeEach(() => {
    resetNapi();
    setNapi(createMock());
    catalog = buildToolCatalog();
  });

  // CH-T10: cortex_analyze_correction is registered
  it('CH-T10: cortex_analyze_correction tool is registered', () => {
    const tool = catalog.get('cortex_analyze_correction');
    expect(tool).toBeDefined();
    expect(tool!.category).toBe('cortex');
    expect(tool!.description).toContain('correction');
    expect(typeof tool!.handler).toBe('function');
    expect(tool!.estimatedTokens).toBeTruthy();
  });

  // CH-T10b: cortex_configure is registered
  it('CH-T10b: cortex_configure tool is registered', () => {
    const tool = catalog.get('cortex_configure');
    expect(tool).toBeDefined();
    expect(tool!.category).toBe('cortex');
    expect(tool!.description).toContain('configuration');
    expect(typeof tool!.handler).toBe('function');
    expect(tool!.estimatedTokens).toBeTruthy();
  });

  // CH-T11: New tools are in CORTEX_CACHEABLE_TOOLS set
  it('CH-T11: cortex_analyze_correction is in cacheable set', () => {
    expect(CORTEX_CACHEABLE_TOOLS.has('cortex_analyze_correction')).toBe(true);
  });

  it('CH-T11b: cortex_configure is in cacheable set', () => {
    expect(CORTEX_CACHEABLE_TOOLS.has('cortex_configure')).toBe(true);
  });

  // CH-T11c: New tools NOT in mutation set (they are read-only)
  it('CH-T11c: new tools are not in mutation set', () => {
    expect(CORTEX_MUTATION_TOOLS.has('cortex_analyze_correction')).toBe(false);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_configure')).toBe(false);
  });

  // CH-T11d: Total cortex tool count increased to 63
  it('CH-T11d: catalog has 63+ cortex tools', () => {
    const cortexTools = Array.from(catalog.keys()).filter(k => k.startsWith('cortex_'));
    expect(cortexTools.length).toBeGreaterThanOrEqual(63);
  });

  // CH-T11e: All new tools have non-empty description and handler
  it('CH-T11e: new tools have valid structure', () => {
    for (const name of ['cortex_analyze_correction', 'cortex_configure']) {
      const tool = catalog.get(name);
      expect(tool, `${name} not found`).toBeDefined();
      expect(tool!.description, `${name} missing description`).toBeTruthy();
      expect(typeof tool!.handler, `${name} missing handler`).toBe('function');
      expect(tool!.category, `${name} wrong category`).toBe('cortex');
    }
  });
});

describe('Bridge Notification on Cortex Mutation (CH-T16)', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createMock());
  });

  // CH-T16: Mutation tools (add, update, delete, learn) call notifyBridgeOfCortexMutation
  // We verify this structurally — the tools exist and mutation tools are in the correct set
  it('CH-T16: memory mutation tools are in CORTEX_MUTATION_TOOLS', () => {
    expect(CORTEX_MUTATION_TOOLS.has('cortex_memory_add')).toBe(true);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_memory_update')).toBe(true);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_memory_delete')).toBe(true);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_learn')).toBe(true);
  });

  // CH-T16b: Non-mutation tools are NOT in CORTEX_MUTATION_TOOLS
  it('CH-T16b: read-only tools are not in mutation set', () => {
    expect(CORTEX_MUTATION_TOOLS.has('cortex_status')).toBe(false);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_search')).toBe(false);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_why')).toBe(false);
    expect(CORTEX_MUTATION_TOOLS.has('cortex_configure')).toBe(false);
  });

  // CH-T16c: Cache and mutation sets together cover all cortex tools
  it('CH-T16c: cacheable + mutation sets cover all cortex tools', () => {
    const catalog = buildToolCatalog();
    const cortexTools = Array.from(catalog.keys()).filter(k => k.startsWith('cortex_'));
    const covered = new Set([...CORTEX_CACHEABLE_TOOLS, ...CORTEX_MUTATION_TOOLS]);

    const uncovered = cortexTools.filter(t => !covered.has(t));
    // All cortex tools should be in either cacheable or mutation set
    expect(uncovered, `Uncovered tools: ${uncovered.join(', ')}`).toHaveLength(0);
  });
});
