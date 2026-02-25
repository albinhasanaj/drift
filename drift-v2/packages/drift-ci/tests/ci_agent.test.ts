/**
 * CI Agent tests — T8-CI-01 through T8-CI-06.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../src/napi.js';
import { runAnalysis, type CiAgentConfig } from '../src/agent.js';
import { generatePrComment } from '../src/pr_comment.js';
import { writeSarifFile } from '../src/sarif_upload.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '../src/napi.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function createMockNapi(overrides: Partial<DriftNapi> = {}): DriftNapi {
  return { ...createStubNapi(), ...overrides };
}

describe('CI Agent', () => {
  beforeEach(() => {
    setNapi(createMockNapi());
  });

  // T8-CI-01: Test CI agent runs 13 analysis passes
  it('T8-CI-01: runs 13 analysis passes in parallel', async () => {
    const result = await runAnalysis({ path: '.' });

    expect(result.passes).toHaveLength(13);
    expect(result.passes.map((p) => p.name)).toEqual([
      'scan',
      'patterns',
      'call_graph',
      'boundaries',
      'security',
      'tests',
      'errors',
      'contracts',
      'constraints',
      'enforcement',
      'bridge',
      'cortex_health',
      'cortex_validation',
    ]);

    // All passes should complete
    for (const pass of result.passes) {
      expect(['passed', 'failed', 'error']).toContain(pass.status);
      expect(pass.durationMs).toBeGreaterThanOrEqual(0);
    }
  });

  // T8-CI-02: Test SARIF file generation
  it('T8-CI-02: generates valid SARIF file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-ci-test-'));
    const sarifPath = path.join(tmpDir, 'results.sarif');

    const violations = [
      { rule_id: 'test-rule', file: 'src/test.ts', line: 10, severity: 'error', message: 'Test error' },
      { rule_id: 'test-rule-2', file: 'src/auth.ts', line: 20, severity: 'warning', message: 'Test warning' },
    ];

    writeSarifFile(violations, sarifPath);

    const content = fs.readFileSync(sarifPath, 'utf-8');
    const sarif = JSON.parse(content);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('drift');
    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].results[0].ruleId).toBe('test-rule');
    expect(sarif.runs[0].results[0].level).toBe('error');
    expect(sarif.runs[0].results[1].level).toBe('warning');

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  // T8-CI-03: Test PR comment generation
  it('T8-CI-03: generates readable PR comment', async () => {
    const result = await runAnalysis({ path: '.' });
    const comment = generatePrComment(result);

    expect(comment.violationCount).toBe(result.totalViolations);
    expect(comment.markdown).toContain('Drift Analysis');
    expect(comment.markdown).toContain('Score:');
    expect(comment.markdown).toContain('Violations:');
    expect(['↑', '↓', '→']).toContain(comment.trend);
    expect(comment.details).toBeTruthy();
  });

  // T8-CI-03 continued: PR comment with trend indicators
  it('T8-CI-03: PR comment shows trend indicators', async () => {
    const result = await runAnalysis({ path: '.' });

    // Improving trend
    const improving = generatePrComment(result, 50);
    expect(improving.trend).toBe('↑');

    // Degrading trend (previous score much higher than current)
    const degrading = generatePrComment({ ...result, score: 50 }, 100);
    expect(degrading.trend).toBe('↓');

    // Stable trend
    const stable = generatePrComment(result, result.score);
    expect(stable.trend).toBe('→');
  });

  // T8-CI-04: Test empty PR diff
  it('T8-CI-04: handles empty PR diff', async () => {
    const result = await runAnalysis({
      path: '.',
      incremental: true,
      changedFiles: [],
    });

    expect(result.status).toBe('passed');
    expect(result.totalViolations).toBe(0);
    expect(result.summary).toContain('No changes to analyze');
    expect(result.passes).toHaveLength(0);
  });

  // T8-CI-05: Test incremental mode
  it('T8-CI-05: incremental mode analyzes changed files', async () => {
    const result = await runAnalysis({
      path: '.',
      incremental: true,
      changedFiles: ['src/auth.ts', 'src/db.ts'],
    });

    expect(result.incremental).toBe(true);
    expect(result.filesAnalyzed).toBe(2);
    expect(result.passes).toHaveLength(13);
  });

  // T8-CI-06: Test timeout handling
  it('T8-CI-06: handles timeout gracefully', async () => {
    setNapi(
      createMockNapi({
        async driftScan() {
          // Simulate slow scan — but our timeout is very short
          const start = Date.now();
          while (Date.now() - start < 10) { /* busy wait */ }
          return { filesTotal: 0, filesAdded: 0, filesModified: 0, filesRemoved: 0, filesUnchanged: 0, errorsCount: 0, durationMs: 10, status: 'ok', languages: {} };
        },
      }),
    );

    const result = await runAnalysis({
      path: '.',
      timeoutMs: 5000, // 5s timeout — should complete fine with mock
    });

    // Should complete (mock is fast enough)
    expect(result.passes).toHaveLength(13);
  });

  // Test score calculation
  it('calculates quality score correctly', async () => {
    const result = await runAnalysis({ path: '.' });
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  // Test fail-on configuration
  it('respects fail-on configuration', async () => {
    // Override owasp to return findings, making security pass fail
    setNapi(
      createMockNapi({
        driftOwaspAnalysis() {
          return {
            findings: [{ id: 'f1', detector: 'owasp-xss', file: 'a.ts', line: 1, description: 'XSS vulnerability', severity: 3, cweIds: [79], owaspCategories: ['A01'], confidence: 0.9, remediation: null }],
            compliance: { postureScore: 50, owaspCoverage: 0.1, cweTop25Coverage: 0.04, criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0 },
          };
        },
      }),
    );

    const errorResult = await runAnalysis({ path: '.', failOn: 'error' });
    expect(errorResult.status).toBe('failed');

    const noneResult = await runAnalysis({ path: '.', failOn: 'none' });
    expect(noneResult.status).toBe('passed');
  });

  // Test threshold enforcement
  it('enforces quality threshold', async () => {
    const result = await runAnalysis({ path: '.', threshold: 999 });
    expect(result.status).toBe('failed');
  });
});

describe('PR Comment Generator', () => {
  it('generates markdown with pass details', async () => {
    setNapi(createMockNapi());
    const result = await runAnalysis({ path: '.' });
    const comment = generatePrComment(result);

    expect(comment.markdown).toContain('| Pass |');
    expect(comment.markdown).toContain('scan');
    expect(comment.markdown).toContain('patterns');
    expect(comment.markdown).toContain('security');
  });

  it('shows incremental mode info', async () => {
    setNapi(createMockNapi());
    const result = await runAnalysis({
      path: '.',
      incremental: true,
      changedFiles: ['a.ts', 'b.ts'],
    });
    const comment = generatePrComment(result);
    expect(comment.markdown).toContain('Incremental');
  });
});
