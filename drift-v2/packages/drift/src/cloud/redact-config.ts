/**
 * Table-specific redaction configurations.
 *
 * Each entry maps a local SQLite table name to its redaction rules.
 * Fields not listed pass through unchanged.
 */

/**
 * How to redact a field:
 * - 'path': absolute file path → project-relative
 * - 'root_path': project root path → empty string
 * - 'secret': any value → '[REDACTED]'
 * - 'code': source code snippet → null
 * - 'blob_hex': binary BLOB → hex string
 */
export type FieldRedaction = 'path' | 'root_path' | 'secret' | 'code' | 'blob_hex';

export interface RedactionConfig {
  /** Map of field name → redaction type */
  fields: Record<string, FieldRedaction>;
}

/**
 * All tables that require redaction before cloud sync.
 * Tables not listed here sync as-is (no redaction needed).
 *
 * 19 REDACT tables: 17 from drift.db + 2 from cortex.db
 */
export const REDACTION_CONFIGS: Record<string, RedactionConfig> = {
  // ── drift.db v001 ──

  file_metadata: {
    fields: {
      path: 'path',
      content_hash: 'blob_hex',
    },
  },

  functions: {
    fields: {
      file: 'path',
      body_hash: 'blob_hex',
      signature_hash: 'blob_hex',
    },
  },

  scan_history: {
    fields: {
      root_path: 'root_path',
    },
  },

  // ── drift.db v002 ──

  detections: {
    fields: {
      file: 'path',
      matched_text: 'code',
    },
  },

  boundaries: {
    fields: {
      file: 'path',
    },
  },

  // ── drift.db v003 ──

  outliers: {
    fields: {
      file: 'path',
    },
  },

  // ── drift.db v004 ──

  taint_flows: {
    fields: {
      source_file: 'path',
      sink_file: 'path',
    },
  },

  error_gaps: {
    fields: {
      file: 'path',
    },
  },

  // ── drift.db v005 ──

  contracts: {
    fields: {
      source_file: 'path',
    },
  },

  constants: {
    fields: {
      file: 'path',
    },
  },

  secrets: {
    fields: {
      file: 'path',
      redacted_value: 'secret',
    },
  },

  env_variables: {
    fields: {
      file: 'path',
    },
  },

  wrappers: {
    fields: {
      file: 'path',
    },
  },

  dna_mutations: {
    fields: {
      file: 'path',
      code: 'code',
    },
  },

  crypto_findings: {
    fields: {
      file: 'path',
      code: 'code',
    },
  },

  owasp_findings: {
    fields: {
      file: 'path',
    },
  },

  // ── drift.db v006 ──

  violations: {
    fields: {
      file: 'path',
    },
  },

  // ── cortex.db v001 ──

  memory_files: {
    fields: {
      file_path: 'path',
    },
  },

  memory_functions: {
    fields: {
      file_path: 'path',
    },
  },
};
