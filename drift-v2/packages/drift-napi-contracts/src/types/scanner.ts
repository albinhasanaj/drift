/**
 * Scanner types — aligned to crates/drift/drift-napi/src/conversions/types.rs
 */

/**
 * Options for driftScan() and driftScanWithProgress().
 * Aligned to Rust ScanOptions (#[napi(object)]).
 */
export interface ScanOptions {
  /** Force full rescan, ignoring mtime optimization. */
  forceFull?: boolean;
  /** Maximum file size in bytes. */
  maxFileSize?: number;
  /** Include glob patterns — only matching paths are scanned (e.g., ["src/**", "lib/**"]). */
  include?: string[];
  /** Additional ignore/exclude patterns (e.g., ["**\/*.test.ts", "vendor/**"]). */
  extraIgnore?: string[];
  /** Follow symbolic links. */
  followSymlinks?: boolean;
  /** Restrict scan to these files only (for incremental CI analysis). */
  changedFiles?: string[];
}

/**
 * Lightweight scan summary returned from driftScan().
 * Aligned to Rust ScanSummary (#[napi(object)]).
 * Full results are persisted to drift.db — query on demand.
 */
export interface ScanSummary {
  filesTotal: number;
  filesAdded: number;
  filesModified: number;
  filesRemoved: number;
  filesUnchanged: number;
  errorsCount: number;
  durationMs: number;
  status: string;
  languages: Record<string, number>;
}

/**
 * Detailed scan statistics.
 * Aligned to Rust ScanStatsJs (#[napi(object)]).
 */
export interface ScanStatsJs {
  totalFiles: number;
  totalSizeBytes: number;
  discoveryMs: number;
  hashingMs: number;
  diffMs: number;
  cacheHitRate: number;
  filesSkippedLarge: number;
  filesSkippedIgnored: number;
  filesSkippedBinary: number;
}
