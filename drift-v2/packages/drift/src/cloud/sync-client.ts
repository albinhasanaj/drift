/**
 * Cloud Sync Client — reads from local DBs, applies redaction, POSTs to Supabase PostgREST.
 *
 * Protocol:
 * 1. Read sync_state (last cursor per DB)
 * 2. For each syncable table, query rows WHERE rowid > cursor (delta)
 * 3. Apply redaction
 * 4. Batch into JSON payload (max 1000 rows per request)
 * 5. POST to PostgREST with upsert header
 * 6. Update sync_state cursor
 */

import { redactBatch, tableNeedsRedaction } from './redact.js';
import type {
  CloudConfig,
  SyncState,
  SyncResult,
  SyncError,
  SyncProgressCallback,
} from './config.js';
import { BATCH_SIZE, MAX_RETRIES, RETRY_BASE_DELAY_MS } from './config.js';
import { getToken } from './auth.js';

// ── Table sync definitions ──

/** Maps local table name → cloud table name + which DB it comes from + PK type */
interface TableSyncDef {
  localTable: string;
  cloudTable: string;
  db: 'drift' | 'bridge' | 'cortex';
  /** Column(s) used for the UNIQUE constraint in cloud (for upsert conflict resolution) */
  conflictColumns: string;
}

/**
 * Tier 1 — Dashboard Essentials (42 tables).
 * All drift.db analysis (37) + bridge.db (5).
 */
const TIER1_TABLES: TableSyncDef[] = [
  // Scan & Files
  { localTable: 'scan_history', cloudTable: 'cloud_scan_history', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'file_metadata', cloudTable: 'cloud_file_stats', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'functions', cloudTable: 'cloud_functions', db: 'drift', conflictColumns: 'project_id,local_id' },
  // Analysis & Patterns
  { localTable: 'call_edges', cloudTable: 'cloud_call_edges', db: 'drift', conflictColumns: 'project_id,caller_id,callee_id,call_site_line' },
  { localTable: 'data_access', cloudTable: 'cloud_data_access', db: 'drift', conflictColumns: 'project_id,function_id,table_name,operation,line' },
  { localTable: 'detections', cloudTable: 'cloud_detections', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'boundaries', cloudTable: 'cloud_boundaries', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'pattern_confidence', cloudTable: 'cloud_pattern_confidence', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'outliers', cloudTable: 'cloud_outliers', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'conventions', cloudTable: 'cloud_conventions', db: 'drift', conflictColumns: 'project_id,local_id' },
  // Graph Intelligence
  { localTable: 'taint_flows', cloudTable: 'cloud_taint_flows', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'error_gaps', cloudTable: 'cloud_error_gaps', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'impact_scores', cloudTable: 'cloud_impact_scores', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'test_coverage', cloudTable: 'cloud_test_coverage', db: 'drift', conflictColumns: 'project_id,test_function_id,source_function_id' },
  { localTable: 'test_quality', cloudTable: 'cloud_test_quality', db: 'drift', conflictColumns: 'project_id,local_id' },
  // Structural Intelligence
  { localTable: 'coupling_metrics', cloudTable: 'cloud_coupling_metrics', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'coupling_cycles', cloudTable: 'cloud_coupling_cycles', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'constraints', cloudTable: 'cloud_constraints', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'constraint_verifications', cloudTable: 'cloud_constraint_results', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'contracts', cloudTable: 'cloud_contracts', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'contract_mismatches', cloudTable: 'cloud_contract_mismatches', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'constants', cloudTable: 'cloud_constants', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'secrets', cloudTable: 'cloud_secrets', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'env_variables', cloudTable: 'cloud_env_variables', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'wrappers', cloudTable: 'cloud_wrappers', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'dna_genes', cloudTable: 'cloud_dna_genes', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'dna_mutations', cloudTable: 'cloud_dna_mutations', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'crypto_findings', cloudTable: 'cloud_crypto_findings', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'owasp_findings', cloudTable: 'cloud_owasp_findings', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'decomposition_decisions', cloudTable: 'cloud_decomposition_decisions', db: 'drift', conflictColumns: 'project_id,local_id' },
  // Enforcement
  { localTable: 'violations', cloudTable: 'cloud_violations', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'gate_results', cloudTable: 'cloud_gate_results', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'audit_snapshots', cloudTable: 'cloud_audit_snapshots', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'health_trends', cloudTable: 'cloud_health_trends', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'feedback', cloudTable: 'cloud_feedback', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'policy_results', cloudTable: 'cloud_policy_results', db: 'drift', conflictColumns: 'project_id,local_id' },
  { localTable: 'degradation_alerts', cloudTable: 'cloud_degradation_alerts', db: 'drift', conflictColumns: 'project_id,local_id' },
  // Bridge
  { localTable: 'bridge_memories', cloudTable: 'cloud_bridge_memories', db: 'bridge', conflictColumns: 'project_id,local_id' },
  { localTable: 'bridge_grounding_results', cloudTable: 'cloud_grounding_results', db: 'bridge', conflictColumns: 'project_id,local_id' },
  { localTable: 'bridge_grounding_snapshots', cloudTable: 'cloud_grounding_snapshots', db: 'bridge', conflictColumns: 'project_id,local_id' },
  { localTable: 'bridge_event_log', cloudTable: 'cloud_bridge_events', db: 'bridge', conflictColumns: 'project_id,local_id' },
  { localTable: 'bridge_metrics', cloudTable: 'cloud_bridge_metrics', db: 'bridge', conflictColumns: 'project_id,local_id' },
];

// ── Row reader interface ──

/**
 * Interface for reading rows from local databases.
 * Implemented by callers (CLI, CI agent) using NAPI bindings.
 */
export interface LocalRowReader {
  /**
   * Read rows from a local table, optionally after a cursor.
   * @returns Array of raw row objects
   */
  readRows(table: string, db: 'drift' | 'bridge' | 'cortex', afterCursor?: number): Promise<Record<string, unknown>[]>;

  /**
   * Get the current max rowid/id for a given DB (for cursor tracking).
   */
  getMaxCursor(db: 'drift' | 'bridge' | 'cortex'): Promise<number>;
}

// ── Sync Client ──

export class SyncClient {
  private config: CloudConfig;
  private projectRoot: string;

  constructor(config: CloudConfig, projectRoot: string) {
    this.config = config;
    this.projectRoot = projectRoot;
  }

  /**
   * Push local data to cloud.
   *
   * @param reader - Implementation that reads from local SQLite DBs
   * @param syncState - Current sync cursors (null = full sync)
   * @param onProgress - Optional progress callback
   * @param fullSync - If true, ignore cursors and re-upload everything
   * @returns Sync result with updated cursors
   */
  async push(
    reader: LocalRowReader,
    syncState: SyncState | null,
    onProgress?: SyncProgressCallback,
    fullSync = false,
  ): Promise<SyncResult> {
    const startTime = Date.now();
    const token = await getToken(this.config.supabaseUrl, this.config.supabaseAnonKey);
    if (!token) {
      return {
        success: false,
        totalRows: 0,
        tableCounts: {},
        durationMs: Date.now() - startTime,
        errors: [{ table: '*', message: 'Not authenticated. Run `drift cloud login` first.', retryable: false }],
        syncState: syncState ?? defaultSyncState(),
      };
    }

    const tables = TIER1_TABLES;
    const tableCounts: Record<string, number> = {};
    const errors: SyncError[] = [];
    let totalRows = 0;

    const cursors = {
      drift: fullSync ? 0 : (syncState?.driftCursor ?? 0),
      bridge: fullSync ? 0 : (syncState?.bridgeCursor ?? 0),
      cortex: fullSync ? 0 : (syncState?.cortexCursor ?? 0),
    };

    for (let i = 0; i < tables.length; i++) {
      const def = tables[i];

      onProgress?.({
        table: def.localTable,
        totalTables: tables.length,
        currentTableIndex: i,
        rowsUploaded: 0,
        totalRows: 0,
      });

      try {
        const rows = await reader.readRows(def.localTable, def.db, cursors[def.db]);
        if (rows.length === 0) {
          tableCounts[def.localTable] = 0;
          continue;
        }

        // Apply redaction
        const redacted = tableNeedsRedaction(def.localTable)
          ? redactBatch(def.localTable, rows, this.projectRoot)
          : rows;

        // Add tenant_id and project_id to each row
        const enriched = redacted.map(row => ({
          ...row,
          tenant_id: this.config.tenantId,
          project_id: this.config.projectId,
        }));

        // Upload in batches
        let uploaded = 0;
        for (let batchStart = 0; batchStart < enriched.length; batchStart += BATCH_SIZE) {
          const batch = enriched.slice(batchStart, batchStart + BATCH_SIZE);
          await this.uploadBatch(token, def.cloudTable, batch, def.conflictColumns);
          uploaded += batch.length;

          onProgress?.({
            table: def.localTable,
            totalTables: tables.length,
            currentTableIndex: i,
            rowsUploaded: uploaded,
            totalRows: enriched.length,
          });
        }

        tableCounts[def.localTable] = enriched.length;
        totalRows += enriched.length;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const statusCode = (err as { statusCode?: number }).statusCode;
        errors.push({
          table: def.localTable,
          message,
          statusCode,
          retryable: statusCode !== undefined && statusCode >= 500,
        });
      }
    }

    // Update cursors to current max
    const newState: SyncState = {
      driftCursor: await reader.getMaxCursor('drift').catch(() => cursors.drift),
      bridgeCursor: await reader.getMaxCursor('bridge').catch(() => cursors.bridge),
      cortexCursor: await reader.getMaxCursor('cortex').catch(() => cursors.cortex),
      lastSyncAt: new Date().toISOString(),
      lastSyncRowCount: totalRows,
    };

    return {
      success: errors.length === 0,
      totalRows,
      tableCounts,
      durationMs: Date.now() - startTime,
      errors,
      syncState: newState,
    };
  }

  /**
   * Upload a batch of rows to a cloud table via PostgREST upsert.
   */
  private async uploadBatch(
    token: string,
    cloudTable: string,
    rows: Record<string, unknown>[],
    conflictColumns: string,
  ): Promise<void> {
    const url = `${this.config.supabaseUrl}/rest/v1/${cloudTable}`;

    let lastError: Error | null = null;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            'apikey': this.config.supabaseAnonKey,
            'Prefer': `resolution=merge-duplicates,return=minimal`,
            'on_conflict': conflictColumns,
          },
          body: JSON.stringify(rows),
        });

        if (response.ok) return;

        const status = response.status;
        if (status >= 400 && status < 500) {
          // Client error — don't retry
          const body = await response.text().catch(() => '');
          throw Object.assign(
            new Error(`PostgREST ${status} for ${cloudTable}: ${body}`),
            { statusCode: status },
          );
        }

        // 5xx — retry
        lastError = Object.assign(
          new Error(`PostgREST ${status} for ${cloudTable}`),
          { statusCode: status },
        );
      } catch (err) {
        if ((err as { statusCode?: number }).statusCode !== undefined &&
            (err as { statusCode?: number }).statusCode! < 500) {
          throw err; // Don't retry client errors
        }
        lastError = err instanceof Error ? err : new Error(String(err));
      }

      // Exponential backoff
      if (attempt < MAX_RETRIES - 1) {
        await sleep(RETRY_BASE_DELAY_MS * Math.pow(2, attempt));
      }
    }

    throw lastError ?? new Error(`Failed to upload to ${cloudTable} after ${MAX_RETRIES} retries`);
  }
}

// ── Helpers ──

function defaultSyncState(): SyncState {
  return {
    driftCursor: 0,
    bridgeCursor: 0,
    cortexCursor: 0,
    lastSyncAt: null,
    lastSyncRowCount: 0,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export { TIER1_TABLES, defaultSyncState };
export type { TableSyncDef };
