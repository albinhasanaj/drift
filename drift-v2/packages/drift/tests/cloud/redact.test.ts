import { describe, it, expect } from 'vitest';
import {
  redactPath,
  redactRootPath,
  redactRow,
  redactBatch,
  tableNeedsRedaction,
  getRedactedTables,
} from '../../src/cloud/redact.js';
import { REDACTION_CONFIGS } from '../../src/cloud/redact-config.js';

const PROJECT_ROOT = '/Users/geoff/myapp';

// ── redactPath ──

describe('redactPath', () => {
  it('strips absolute path to project-relative', () => {
    expect(redactPath('/Users/geoff/myapp/src/index.ts', PROJECT_ROOT))
      .toBe('src/index.ts');
  });

  it('handles nested paths', () => {
    expect(redactPath('/Users/geoff/myapp/src/deep/nested/file.rs', PROJECT_ROOT))
      .toBe('src/deep/nested/file.rs');
  });

  it('returns path unchanged if different root', () => {
    expect(redactPath('/other/project/file.ts', PROJECT_ROOT))
      .toBe('/other/project/file.ts');
  });

  it('returns empty string unchanged', () => {
    expect(redactPath('', PROJECT_ROOT)).toBe('');
  });

  it('handles root with trailing slash', () => {
    expect(redactPath('/Users/geoff/myapp/src/a.ts', '/Users/geoff/myapp/'))
      .toBe('src/a.ts');
  });

  it('handles already-relative path', () => {
    expect(redactPath('src/index.ts', PROJECT_ROOT))
      .toBe('src/index.ts');
  });
});

// ── redactRootPath ──

describe('redactRootPath', () => {
  it('strips exact root path to empty string', () => {
    expect(redactRootPath('/Users/geoff/myapp', PROJECT_ROOT)).toBe('');
  });

  it('strips root with trailing slash', () => {
    expect(redactRootPath('/Users/geoff/myapp/', PROJECT_ROOT)).toBe('');
  });

  it('relativizes subpath', () => {
    expect(redactRootPath('/Users/geoff/myapp/src', PROJECT_ROOT)).toBe('src');
  });
});

// ── redactRow ──

describe('redactRow', () => {
  it('redacts file path in violations', () => {
    const row = {
      id: 'v-1',
      file: '/Users/geoff/myapp/src/auth.ts',
      line: 42,
      severity: 'error',
      message: 'Unsafe cast',
    };
    const result = redactRow('violations', row, PROJECT_ROOT);
    expect(result.file).toBe('src/auth.ts');
    expect(result.id).toBe('v-1');
    expect(result.line).toBe(42);
    expect(result.severity).toBe('error');
    expect(result.message).toBe('Unsafe cast');
  });

  it('redacts matched_text to null in detections', () => {
    const row = {
      id: 1,
      file: '/Users/geoff/myapp/src/db.ts',
      matched_text: 'const password = "hunter2"',
      pattern_id: 'sec-001',
      confidence: 0.95,
    };
    const result = redactRow('detections', row, PROJECT_ROOT);
    expect(result.file).toBe('src/db.ts');
    expect(result.matched_text).toBeNull();
    expect(result.confidence).toBe(0.95);
  });

  it('redacts secret values in secrets table', () => {
    const row = {
      id: 1,
      pattern_name: 'aws_access_key',
      redacted_value: 'AKIAIOSFODNN7EXAMPLE',
      file: '/Users/geoff/myapp/.env',
      severity: 'critical',
    };
    const result = redactRow('secrets', row, PROJECT_ROOT);
    expect(result.redacted_value).toBe('[REDACTED]');
    expect(result.file).toBe('.env');
  });

  it('redacts code in dna_mutations', () => {
    const row = {
      id: 'mut-1',
      file: '/Users/geoff/myapp/src/utils.ts',
      code: 'function doStuff() { return 42; }',
      gene_id: 'gene-1',
    };
    const result = redactRow('dna_mutations', row, PROJECT_ROOT);
    expect(result.file).toBe('src/utils.ts');
    expect(result.code).toBeNull();
  });

  it('redacts code in crypto_findings', () => {
    const row = {
      id: 1,
      file: '/Users/geoff/myapp/src/crypto.ts',
      code: 'crypto.createHash("md5")',
      category: 'weak_hash',
    };
    const result = redactRow('crypto_findings', row, PROJECT_ROOT);
    expect(result.file).toBe('src/crypto.ts');
    expect(result.code).toBeNull();
  });

  it('redacts root_path in scan_history', () => {
    const row = {
      id: 1,
      root_path: '/Users/geoff/myapp',
      total_files: 100,
      status: 'completed',
    };
    const result = redactRow('scan_history', row, PROJECT_ROOT);
    expect(result.root_path).toBe('');
    expect(result.total_files).toBe(100);
  });

  it('passes through fields not in redaction config', () => {
    const row = {
      id: 'v-1',
      file: '/Users/geoff/myapp/src/a.ts',
      severity: 'warning',
      pattern_id: 'pat-001',
      rule_id: 'rule-001',
      cwe_id: 79,
    };
    const result = redactRow('violations', row, PROJECT_ROOT);
    expect(result.severity).toBe('warning');
    expect(result.pattern_id).toBe('pat-001');
    expect(result.rule_id).toBe('rule-001');
    expect(result.cwe_id).toBe(79);
  });

  it('passes through entire row for non-redacted table', () => {
    const row = {
      id: 1,
      gate_id: 'complexity',
      passed: true,
      score: 0.85,
    };
    const result = redactRow('gate_results', row, PROJECT_ROOT);
    expect(result).toEqual(row);
  });

  it('handles null field values gracefully', () => {
    const row = {
      id: 1,
      file: null,
      matched_text: null,
      pattern_id: 'pat-1',
    };
    const result = redactRow('detections', row, PROJECT_ROOT);
    expect(result.file).toBeNull();
    expect(result.matched_text).toBeNull();
  });

  it('redacts multiple path fields in taint_flows', () => {
    const row = {
      id: 1,
      source_file: '/Users/geoff/myapp/src/input.ts',
      sink_file: '/Users/geoff/myapp/src/db.ts',
      source_line: 10,
      sink_line: 20,
    };
    const result = redactRow('taint_flows', row, PROJECT_ROOT);
    expect(result.source_file).toBe('src/input.ts');
    expect(result.sink_file).toBe('src/db.ts');
  });

  it('redacts file_path in cortex memory_files', () => {
    const row = {
      memory_id: 'mem-1',
      file_path: '/Users/geoff/myapp/src/service.ts',
      line_start: 1,
      line_end: 50,
    };
    const result = redactRow('memory_files', row, PROJECT_ROOT);
    expect(result.file_path).toBe('src/service.ts');
  });

  it('redacts file_path in cortex memory_functions', () => {
    const row = {
      memory_id: 'mem-1',
      function_name: 'handleAuth',
      file_path: '/Users/geoff/myapp/src/auth.ts',
    };
    const result = redactRow('memory_functions', row, PROJECT_ROOT);
    expect(result.file_path).toBe('src/auth.ts');
  });

  it('converts blob to hex for file_metadata content_hash', () => {
    const row = {
      path: '/Users/geoff/myapp/src/a.ts',
      content_hash: new Uint8Array([0xab, 0xcd, 0xef, 0x01]),
      file_size: 1024,
    };
    const result = redactRow('file_metadata', row, PROJECT_ROOT);
    expect(result.path).toBe('src/a.ts');
    expect(result.content_hash).toBe('abcdef01');
  });
});

// ── redactBatch ──

describe('redactBatch', () => {
  it('redacts all rows in batch', () => {
    const rows = [
      { id: 'v-1', file: '/Users/geoff/myapp/src/a.ts', severity: 'error' },
      { id: 'v-2', file: '/Users/geoff/myapp/src/b.ts', severity: 'warning' },
    ];
    const results = redactBatch('violations', rows, PROJECT_ROOT);
    expect(results).toHaveLength(2);
    expect(results[0].file).toBe('src/a.ts');
    expect(results[1].file).toBe('src/b.ts');
  });

  it('handles empty batch', () => {
    expect(redactBatch('violations', [], PROJECT_ROOT)).toEqual([]);
  });
});

// ── tableNeedsRedaction ──

describe('tableNeedsRedaction', () => {
  it('returns true for REDACT tables', () => {
    expect(tableNeedsRedaction('violations')).toBe(true);
    expect(tableNeedsRedaction('detections')).toBe(true);
    expect(tableNeedsRedaction('secrets')).toBe(true);
    expect(tableNeedsRedaction('taint_flows')).toBe(true);
    expect(tableNeedsRedaction('memory_files')).toBe(true);
  });

  it('returns false for non-REDACT tables', () => {
    expect(tableNeedsRedaction('gate_results')).toBe(false);
    expect(tableNeedsRedaction('conventions')).toBe(false);
    expect(tableNeedsRedaction('pattern_confidence')).toBe(false);
    expect(tableNeedsRedaction('bridge_memories')).toBe(false);
  });
});

// ── getRedactedTables ──

describe('getRedactedTables', () => {
  it('returns all 19 redacted tables', () => {
    const tables = getRedactedTables();
    expect(tables).toHaveLength(19);
  });

  it('includes drift.db and cortex.db tables', () => {
    const tables = getRedactedTables();
    expect(tables).toContain('violations');
    expect(tables).toContain('detections');
    expect(tables).toContain('secrets');
    expect(tables).toContain('memory_files');
    expect(tables).toContain('memory_functions');
  });
});

// ── REDACTION_CONFIGS completeness ──

describe('REDACTION_CONFIGS', () => {
  it('has exactly 19 entries matching the plan', () => {
    expect(Object.keys(REDACTION_CONFIGS)).toHaveLength(19);
  });

  it('all entries have at least one field', () => {
    for (const [table, config] of Object.entries(REDACTION_CONFIGS)) {
      expect(Object.keys(config.fields).length).toBeGreaterThan(0);
    }
  });

  it('all field redaction types are valid', () => {
    const validTypes = new Set(['path', 'root_path', 'secret', 'code', 'blob_hex']);
    for (const [_table, config] of Object.entries(REDACTION_CONFIGS)) {
      for (const [_field, type] of Object.entries(config.fields)) {
        expect(validTypes.has(type)).toBe(true);
      }
    }
  });
});
