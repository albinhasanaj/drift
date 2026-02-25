/**
 * Cloud configuration types for Drift Cloud sync.
 */

export interface CloudConfig {
  /** Supabase project URL, e.g. https://abc123.supabase.co */
  supabaseUrl: string;
  /** Supabase anon key (public, safe to embed) */
  supabaseAnonKey: string;
  /** Project ID in the cloud (UUID) */
  projectId: string;
  /** Tenant ID in the cloud (UUID) */
  tenantId: string;
}

export interface CloudCredentials {
  /** JWT access token */
  accessToken: string;
  /** Refresh token for obtaining new access tokens */
  refreshToken: string;
  /** When the access token expires (ISO-8601) */
  expiresAt: string;
}

export interface SyncState {
  /** Last synced scan_history.id for drift.db delta tracking */
  driftCursor: number;
  /** Last synced bridge_event_log.id for bridge.db delta tracking */
  bridgeCursor: number;
  /** Last synced memory_events.event_id for cortex.db delta tracking */
  cortexCursor: number;
  /** ISO-8601 timestamp of last successful sync */
  lastSyncAt: string | null;
  /** Number of rows synced in last push */
  lastSyncRowCount: number;
}

export interface SyncResult {
  /** Whether the sync completed successfully */
  success: boolean;
  /** Total rows pushed across all tables */
  totalRows: number;
  /** Per-table row counts */
  tableCounts: Record<string, number>;
  /** Duration in milliseconds */
  durationMs: number;
  /** Errors encountered (non-fatal, per-table) */
  errors: SyncError[];
  /** Updated sync state */
  syncState: SyncState;
}

export interface SyncError {
  table: string;
  message: string;
  statusCode?: number;
  retryable: boolean;
}

export interface SyncProgress {
  /** Current table being synced */
  table: string;
  /** Total tables to sync */
  totalTables: number;
  /** Index of current table (0-based) */
  currentTableIndex: number;
  /** Rows uploaded for current table */
  rowsUploaded: number;
  /** Total rows for current table */
  totalRows: number;
}

export type SyncProgressCallback = (progress: SyncProgress) => void;

/** Default credentials file location */
export const CREDENTIALS_PATH = '.drift/cloud-credentials.json';

/** Default cloud config file location */
export const CLOUD_CONFIG_PATH = '.drift/cloud-config.json';

/** Maximum rows per PostgREST upsert batch */
export const BATCH_SIZE = 1000;

/** Maximum retry attempts for 5xx errors */
export const MAX_RETRIES = 3;

/** Base delay for exponential backoff (ms) */
export const RETRY_BASE_DELAY_MS = 1000;
