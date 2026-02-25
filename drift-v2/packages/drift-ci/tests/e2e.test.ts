/**
 * CI E2E tests — T9-CI-01 through T9-CI-04.
 *
 * Verifies the full CI pipeline: scan → analyze → 10 passes → SARIF → PR comment.
 * Uses stub NAPI (no native binary required).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../src/napi.js';
import { runAnalysis } from '../src/agent.js';
import { generatePrComment } from '../src/pr_comment.js';
import { writeSarifFile } from '../src/sarif_upload.js';
import { createStubNapi } from '@drift/napi-contracts';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('CI E2E Pipeline', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createStubNapi());
  });

  // T9-CI-01: Full pipeline runs 13 passes and produces valid result
  it('T9-CI-01: full analysis produces 13 passes with valid structure', async () => {
    const result = await runAnalysis({ path: '.' });

    expect(result.passes).toHaveLength(13);
    expect(result.status).toBe('passed');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.totalViolations).toBeGreaterThanOrEqual(0);
    expect(typeof result.summary).toBe('string');
    expect(typeof result.durationMs).toBe('number');

    // All passes have valid structure
    for (const pass of result.passes) {
      expect(typeof pass.name).toBe('string');
      expect(['passed', 'failed', 'error']).toContain(pass.status);
      expect(typeof pass.violations).toBe('number');
      expect(typeof pass.durationMs).toBe('number');
    }

    // Expected pass names
    const names = result.passes.map((p) => p.name);
    expect(names).toContain('scan');
    expect(names).toContain('patterns');
    expect(names).toContain('security');
    expect(names).toContain('enforcement');
  });

  // T9-CI-02: PR comment generation from analysis result
  it('T9-CI-02: PR comment has all required sections', async () => {
    const result = await runAnalysis({ path: '.' });
    const comment = generatePrComment(result);

    expect(comment.markdown).toContain('Drift Analysis');
    expect(comment.markdown).toContain('Score:');
    expect(comment.markdown).toContain('Violations:');
    expect(comment.markdown).toContain('| Pass |');
    expect(['↑', '↓', '→']).toContain(comment.trend);
    expect(typeof comment.violationCount).toBe('number');
  });

  // T9-CI-03: SARIF output is valid JSON
  it('T9-CI-03: SARIF file has valid structure', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-ci-e2e-'));
    const sarifPath = path.join(tmpDir, 'e2e.sarif');

    const violations = [
      { rule_id: 'e2e-rule', file: 'src/test.ts', line: 1, severity: 'warning', message: 'E2E test violation' },
    ];

    writeSarifFile(violations, sarifPath);

    const content = JSON.parse(fs.readFileSync(sarifPath, 'utf-8'));
    expect(content.version).toBe('2.1.0');
    expect(content.runs).toHaveLength(1);
    expect(content.runs[0].tool.driver.name).toBe('drift');
    expect(content.runs[0].results).toHaveLength(1);
    expect(content.runs[0].results[0].ruleId).toBe('e2e-rule');

    fs.rmSync(tmpDir, { recursive: true });
  });

  // T9-CI-04: Incremental mode with empty changeset
  it('T9-CI-04: incremental with no changes produces clean result', async () => {
    const result = await runAnalysis({
      path: '.',
      incremental: true,
      changedFiles: [],
    });

    expect(result.status).toBe('passed');
    expect(result.totalViolations).toBe(0);
    expect(result.passes).toHaveLength(0);
    expect(result.summary).toContain('No changes');
  });
});
