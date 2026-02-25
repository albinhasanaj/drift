/**
 * Cloud redaction layer — transforms local rows into cloud-safe rows.
 *
 * Rules:
 * - File paths: strip to project-relative
 * - Root paths: strip entirely
 * - Secret values: replace with [REDACTED]
 * - Source code snippets: strip to null
 * - Environment variable values: strip (keep name only)
 */

import { REDACTION_CONFIGS, type RedactionConfig, type FieldRedaction } from './redact-config.js';

// ── Path redaction ──

/**
 * Convert an absolute file path to project-relative.
 * Returns the path unchanged if it doesn't start with projectRoot.
 */
export function redactPath(absolutePath: string, projectRoot: string): string {
  if (!absolutePath || !projectRoot) return absolutePath;

  // Normalize: ensure no trailing slash on root
  const root = projectRoot.endsWith('/') ? projectRoot.slice(0, -1) : projectRoot;

  if (absolutePath.startsWith(root + '/')) {
    return absolutePath.slice(root.length + 1);
  }
  if (absolutePath.startsWith(root + '\\')) {
    return absolutePath.slice(root.length + 1);
  }
  // Already relative or different root — return as-is
  return absolutePath;
}

/**
 * Strip a root path entirely (returns empty string).
 */
export function redactRootPath(rootPath: string, projectRoot: string): string {
  if (!rootPath || !projectRoot) return rootPath;
  const root = projectRoot.endsWith('/') ? projectRoot.slice(0, -1) : projectRoot;
  if (rootPath === root || rootPath === root + '/' || rootPath === root + '\\') {
    return '';
  }
  // Relativize if it's a subpath
  return redactPath(rootPath, projectRoot);
}

// ── Field-level redaction ──

function applyFieldRedaction(
  value: unknown,
  redaction: FieldRedaction,
  projectRoot: string,
): unknown {
  if (value === null || value === undefined) return value;

  switch (redaction) {
    case 'path':
      return typeof value === 'string' ? redactPath(value, projectRoot) : value;
    case 'root_path':
      return typeof value === 'string' ? redactRootPath(value, projectRoot) : value;
    case 'secret':
      return '[REDACTED]';
    case 'code':
      return null;
    case 'blob_hex':
      // Convert binary to hex string representation (for content_hash etc.)
      if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
        const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      return typeof value === 'string' ? value : null;
    default:
      return value;
  }
}

// ── Row-level redaction ──

/**
 * Redact a single row from a local table, making it safe for cloud sync.
 *
 * @param tableName - The local SQLite table name (e.g. 'violations', 'detections')
 * @param row - The raw row object from the local DB
 * @param projectRoot - Absolute path to the project root
 * @returns A new object with redacted fields, or the original if no config exists
 */
export function redactRow(
  tableName: string,
  row: Record<string, unknown>,
  projectRoot: string,
): Record<string, unknown> {
  const config = REDACTION_CONFIGS[tableName];
  if (!config) {
    // No redaction needed — pass through
    return { ...row };
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) {
    const redaction = config.fields[key];
    if (redaction) {
      result[key] = applyFieldRedaction(value, redaction, projectRoot);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Redact a batch of rows from the same table.
 */
export function redactBatch(
  tableName: string,
  rows: Record<string, unknown>[],
  projectRoot: string,
): Record<string, unknown>[] {
  return rows.map(row => redactRow(tableName, row, projectRoot));
}

/**
 * Check if a table requires redaction before cloud sync.
 */
export function tableNeedsRedaction(tableName: string): boolean {
  return tableName in REDACTION_CONFIGS;
}

/**
 * Get the list of all tables that require redaction.
 */
export function getRedactedTables(): string[] {
  return Object.keys(REDACTION_CONFIGS);
}

export type { RedactionConfig, FieldRedaction };
