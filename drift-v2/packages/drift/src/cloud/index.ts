/**
 * @drift/core/cloud — Cloud sync utilities.
 *
 * Redaction, authentication, configuration, and sync client for Drift Cloud.
 */

// Redaction
export {
  redactPath,
  redactRootPath,
  redactRow,
  redactBatch,
  tableNeedsRedaction,
  getRedactedTables,
} from './redact.js';

export { REDACTION_CONFIGS } from './redact-config.js';

export type { RedactionConfig, FieldRedaction } from './redact-config.js';

// Config
export type {
  CloudConfig,
  CloudCredentials,
  SyncState,
  SyncResult,
  SyncError,
  SyncProgress,
  SyncProgressCallback,
} from './config.js';

export {
  CREDENTIALS_PATH,
  CLOUD_CONFIG_PATH,
  BATCH_SIZE,
  MAX_RETRIES,
  RETRY_BASE_DELAY_MS,
} from './config.js';

// Auth
export {
  saveCredentials,
  loadCredentials,
  getToken,
  refreshToken,
  logout,
  isLoggedIn,
} from './auth.js';

// Sync Client
export {
  SyncClient,
  TIER1_TABLES,
  defaultSyncState,
} from './sync-client.js';

export type { LocalRowReader, TableSyncDef } from './sync-client.js';
