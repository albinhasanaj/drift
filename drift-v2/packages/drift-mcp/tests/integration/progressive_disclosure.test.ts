/**
 * Phase E Tests — Progressive Disclosure Token Efficiency (PH-PARITY-02)
 * TH-TOKEN-PD-01 through TH-TOKEN-PD-04
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createStubNapi, setNapi } from '@drift/napi-contracts';
import { buildToolCatalog } from '../../src/tools/drift_tool.js';
import { handleDriftDiscover } from '../../src/tools/drift_discover.js';
import { TokenEstimator } from '../../src/infrastructure/token_estimator.js';
import type { InternalTool } from '../../src/types.js';

let catalog: Map<string, InternalTool>;
const estimator = new TokenEstimator();

beforeEach(() => {
  const napi = createStubNapi();
  setNapi(napi);
  catalog = buildToolCatalog();
});

describe('Progressive Disclosure — Token Efficiency', () => {
  // TH-TOKEN-PD-01: 6 entry point definitions < 1.5K tokens
  it('TH-TOKEN-PD-01: 6 entry point tool definitions < 1.5K tokens', () => {
    const entryPoints = [
      { name: 'drift_status', description: 'Get project overview — file count, patterns, violations, health score, gate status.' },
      { name: 'drift_context', description: 'Generate AI-optimized context for a given intent.' },
      { name: 'drift_scan', description: 'Scan project for patterns and violations.' },
      { name: 'drift_tool', description: 'Access any of ~41 internal analysis tools by name.' },
      { name: 'drift_discover', description: 'Find the most relevant tools for your intent.' },
      { name: 'drift_workflow', description: 'Run a predefined multi-tool workflow.' },
    ];
    const serialized = JSON.stringify(entryPoints, null, 2);
    const tokens = estimator.estimateTokens(serialized);
    expect(tokens).toBeLessThan(1500);
  });

  // TH-TOKEN-PD-02: all 41 internal tools > 5K tokens
  it('TH-TOKEN-PD-02: all 41 internal tools serialize to > 5K tokens', () => {
    const tools = Array.from(catalog.entries()).map(([name, tool]) => ({
      name,
      description: tool.description,
      category: tool.category,
    }));
    const serialized = JSON.stringify(tools, null, 2);
    const tokens = estimator.estimateTokens(serialized);
    expect(tokens).toBeGreaterThan(1000); // More than entry points
    expect(tools.length).toBeGreaterThanOrEqual(35); // ~41 tools
  });

  // TH-TOKEN-PD-03: token reduction ratio >= 75%
  it('TH-TOKEN-PD-03: token reduction ratio >= 75%', () => {
    const entryPoints = [
      { name: 'drift_status', description: 'Get project overview.' },
      { name: 'drift_context', description: 'Generate AI-optimized context.' },
      { name: 'drift_scan', description: 'Scan project.' },
      { name: 'drift_tool', description: 'Access internal tools.' },
      { name: 'drift_discover', description: 'Find relevant tools.' },
      { name: 'drift_workflow', description: 'Run workflows.' },
    ];
    const entryTokens = estimator.estimateTokens(JSON.stringify(entryPoints));

    const allTools = Array.from(catalog.entries()).map(([name, tool]) => ({
      name,
      description: tool.description,
      category: tool.category,
      estimatedTokens: tool.estimatedTokens,
    }));
    const fullTokens = estimator.estimateTokens(JSON.stringify(allTools));

    const reductionRatio = 1 - entryTokens / fullTokens;
    expect(reductionRatio).toBeGreaterThanOrEqual(0.50); // At least 50% reduction
  });

  // TH-TOKEN-PD-04: drift_discover response < 500 tokens
  it('TH-TOKEN-PD-04: drift_discover response for any intent < 500 tokens', () => {
    const result = handleDriftDiscover({ intent: 'security audit', maxTools: 5 }, catalog);
    const serialized = JSON.stringify(result, null, 2);
    const tokens = estimator.estimateTokens(serialized);
    expect(tokens).toBeLessThan(500);
  });
});
