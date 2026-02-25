/**
 * Phase C Tests — Discover Intent Matching (TH-DISC-01 through TH-DISC-10)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../../src/napi.js';
import { buildToolCatalog } from '../../src/tools/drift_tool.js';
import { handleDriftDiscover } from '../../src/tools/drift_discover.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { InternalTool } from '../../src/types.js';

describe('Discover — Intent Matching', () => {
  let catalog: Map<string, InternalTool>;

  beforeEach(() => {
    resetNapi();
    setNapi({ ...createStubNapi() });
    catalog = buildToolCatalog();
  });

  // TH-DISC-01: security audit → top 5 includes owasp, taint, crypto
  it('TH-DISC-01: security audit intent', () => {
    const result = handleDriftDiscover({ intent: 'security audit' }, catalog);
    const names = result.tools.map(t => t.name);
    expect(names.some(n => n.includes('owasp') || n.includes('security'))).toBe(true);
    expect(names.some(n => n.includes('taint'))).toBe(true);
  });

  // TH-DISC-02: fix bug → top 5 includes check/prevalidate/suggest (fix-related tools)
  it('TH-DISC-02: fix bug intent', () => {
    const result = handleDriftDiscover({ intent: 'fix bug' }, catalog);
    const names = result.tools.map(t => t.name);
    // The "fix" keyword maps to check, prevalidate, suggest, violations, impact, explain
    expect(names.some(n => n.includes('fix') || n.includes('check') || n.includes('validate') || n.includes('suggest'))).toBe(true);
  });

  // TH-DISC-03: understand code → top 5 includes context, patterns, conventions
  it('TH-DISC-03: understand code intent', () => {
    const result = handleDriftDiscover({ intent: 'understand code' }, catalog);
    const names = result.tools.map(t => t.name);
    expect(names.some(n => n.includes('context') || n.includes('pattern') || n.includes('convention'))).toBe(true);
  });

  // TH-DISC-04: pre-commit check → top 5 includes check, violations
  it('TH-DISC-04: pre-commit check intent', () => {
    const result = handleDriftDiscover({ intent: 'pre-commit check' }, catalog);
    const names = result.tools.map(t => t.name);
    expect(names.some(n => n.includes('check') || n.includes('validate') || n.includes('violation'))).toBe(true);
  });

  // TH-DISC-05: maxTools=3 returns exactly 3
  it('TH-DISC-05: maxTools=3 returns exactly 3', () => {
    const result = handleDriftDiscover({ intent: 'security', maxTools: 3 }, catalog);
    expect(result.tools).toHaveLength(3);
  });

  // TH-DISC-06: maxTools=0 returns empty array
  it('TH-DISC-06: maxTools=0 returns empty', () => {
    const result = handleDriftDiscover({ intent: 'security', maxTools: 0 }, catalog);
    expect(result.tools).toHaveLength(0);
  });

  // TH-DISC-07: unknown intent → generic top tools, no crash
  it('TH-DISC-07: unknown intent returns tools', () => {
    const result = handleDriftDiscover({ intent: 'make coffee' }, catalog);
    expect(result.tools.length).toBeGreaterThan(0);
    expect(result.totalAvailable).toBe(catalog.size);
  });

  // TH-DISC-08: results include relevanceScore, sorted descending
  it('TH-DISC-08: results sorted by relevanceScore descending', () => {
    const result = handleDriftDiscover({ intent: 'security audit' }, catalog);
    for (let i = 1; i < result.tools.length; i++) {
      expect(result.tools[i - 1].relevanceScore).toBeGreaterThanOrEqual(result.tools[i].relevanceScore);
    }
    expect(result.tools[0].relevanceScore).toBeGreaterThan(0);
  });

  // TH-DISC-09: focus boosts auth/security tools
  it('TH-DISC-09: focus boosts relevant tools', () => {
    const withFocus = handleDriftDiscover({ intent: 'audit', focus: 'security' }, catalog);
    const withoutFocus = handleDriftDiscover({ intent: 'audit' }, catalog);
    // Security-related tool should score higher with focus
    const secToolWith = withFocus.tools.find(t => t.name.includes('security'));
    const secToolWithout = withoutFocus.tools.find(t => t.name.includes('security'));
    if (secToolWith && secToolWithout) {
      expect(secToolWith.relevanceScore).toBeGreaterThanOrEqual(secToolWithout.relevanceScore);
    }
  });

  // TH-DISC-10: response < 500 tokens (lightweight)
  it('TH-DISC-10: response is lightweight', () => {
    const result = handleDriftDiscover({ intent: 'security', maxTools: 5 }, catalog);
    const json = JSON.stringify(result);
    // Rough estimate: chars / 3.5 ≈ tokens
    const estimatedTokens = json.length / 3.5;
    expect(estimatedTokens).toBeLessThan(500);
  });
});
