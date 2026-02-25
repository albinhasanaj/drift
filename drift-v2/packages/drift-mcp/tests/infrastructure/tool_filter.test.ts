/**
 * Tool Filter Tests — TH-FILTER-01 through TH-FILTER-04
 */

import { describe, it, expect } from 'vitest';
import { ToolFilter } from '../../src/infrastructure/tool_filter.js';
import type { InternalToolEntry } from '../../src/infrastructure/tool_filter.js';

function buildCatalog(): Map<string, InternalToolEntry> {
  const catalog = new Map<string, InternalToolEntry>();
  // Core tools (should never be filtered)
  catalog.set('drift_status', { name: 'drift_status', description: 'Project status', category: 'operational', estimatedTokens: '200' });
  catalog.set('drift_context', { name: 'drift_context', description: 'Intent context', category: 'operational', estimatedTokens: '2000' });
  catalog.set('drift_scan', { name: 'drift_scan', description: 'Scan project', category: 'operational', estimatedTokens: '300' });
  catalog.set('drift_check', { name: 'drift_check', description: 'Run checks', category: 'enforcement', estimatedTokens: '400' });
  catalog.set('drift_violations', { name: 'drift_violations', description: 'List violations', category: 'enforcement', estimatedTokens: '800' });
  // Analysis tools (language-agnostic)
  catalog.set('drift_coupling_analysis', { name: 'drift_coupling_analysis', description: 'Module coupling', category: 'structural', estimatedTokens: '700' });
  catalog.set('drift_taint_analysis', { name: 'drift_taint_analysis', description: 'Taint flow analysis', category: 'graph', estimatedTokens: '600' });
  // Language-specific tool (for test)
  catalog.set('drift_ts_lint', { name: 'drift_ts_lint', description: 'TypeScript-specific linting with ts rules', category: 'language', estimatedTokens: '300' });
  catalog.set('drift_py_lint', { name: 'drift_py_lint', description: 'Python-specific linting with python rules', category: 'language', estimatedTokens: '300' });
  return catalog;
}

describe('Tool Filter', () => {
  const filter = new ToolFilter();

  // TH-FILTER-01: Python filters TS tools
  it('TH-FILTER-01: Python project filters TypeScript-specific tools', () => {
    const catalog = buildCatalog();
    const filtered = filter.filter(catalog, { Python: 100 });

    // Python tool should be present (description matches 'python' keyword)
    expect(filtered.has('drift_py_lint')).toBe(true);
    // TS tool should be filtered out (no python keyword match)
    expect(filtered.has('drift_ts_lint')).toBe(false);
    // Core tools always present
    expect(filtered.has('drift_status')).toBe(true);
    expect(filtered.has('drift_check')).toBe(true);
  });

  // TH-FILTER-02: core tools never filtered
  it('TH-FILTER-02: core tools never filtered regardless of language', () => {
    const catalog = buildCatalog();
    const filtered = filter.filter(catalog, { Rust: 50 });

    expect(filtered.has('drift_status')).toBe(true);
    expect(filtered.has('drift_context')).toBe(true);
    expect(filtered.has('drift_scan')).toBe(true);
    expect(filtered.has('drift_check')).toBe(true);
    expect(filtered.has('drift_violations')).toBe(true);
  });

  // TH-FILTER-03: empty languages → full catalog
  it('TH-FILTER-03: empty languages returns full catalog', () => {
    const catalog = buildCatalog();

    // null languages
    const filtered1 = filter.filter(catalog, null);
    expect(filtered1.size).toBe(catalog.size);

    // empty object
    const filtered2 = filter.filter(catalog, {});
    expect(filtered2.size).toBe(catalog.size);
  });

  // TH-FILTER-04: multi-language union
  it('TH-FILTER-04: multi-language union includes tools for all languages', () => {
    const catalog = buildCatalog();
    const filtered = filter.filter(catalog, { TypeScript: 80, Python: 20 });

    // Both language-specific tools should be present
    expect(filtered.has('drift_ts_lint')).toBe(true);
    expect(filtered.has('drift_py_lint')).toBe(true);
    // Analysis tools always present (agnostic category)
    expect(filtered.has('drift_coupling_analysis')).toBe(true);
    expect(filtered.has('drift_taint_analysis')).toBe(true);
  });
});
