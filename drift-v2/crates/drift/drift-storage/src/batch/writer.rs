//! Dedicated writer thread with crossbeam-channel bounded(1024).
//! Batches writes into single transactions for throughput.

use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender};
use drift_core::errors::StorageError;
use rusqlite::Connection;

use super::commands::{
    BatchCommand, CallEdgeRow, BoundaryRow, ConventionInsertRow, DataAccessInsertRow,
    DetectionRow, FileMetadataRow, FunctionRow, OutlierDetectionRow, ParseCacheRow,
    PatternConfidenceRow, ScanHistoryInsertRow,
    ReachabilityCacheRow, TaintFlowInsertRow, ErrorGapInsertRow, ImpactScoreInsertRow,
    TestQualityInsertRow, CouplingMetricInsertRow, CouplingCycleInsertRow,
    ViolationInsertRow, GateResultInsertRow, DegradationAlertInsertRow,
    WrapperInsertRow, CryptoFindingInsertRow, DnaGeneInsertRow, DnaMutationInsertRow,
    SecretInsertRow, ConstantInsertRow,
    EnvVariableInsertRow, OwaspFindingInsertRow, DecompositionDecisionInsertRow,
    ContractInsertRow, ContractMismatchInsertRow,
};

const CHANNEL_BOUND: usize = 1024;
const BATCH_SIZE: usize = 500;
const FLUSH_TIMEOUT: Duration = Duration::from_millis(100);

/// Statistics from the batch writer.
#[derive(Debug, Default, Clone)]
pub struct WriteStats {
    pub file_metadata_rows: usize,
    pub parse_cache_rows: usize,
    pub function_rows: usize,
    pub deleted_files: usize,
    pub call_edge_rows: usize,
    pub detection_rows: usize,
    pub boundary_rows: usize,
    pub pattern_confidence_rows: usize,
    pub outlier_rows: usize,
    pub convention_rows: usize,
    pub scan_history_rows: usize,
    pub data_access_rows: usize,
    pub reachability_cache_rows: usize,
    pub taint_flow_rows: usize,
    pub error_gap_rows: usize,
    pub impact_score_rows: usize,
    pub test_quality_rows: usize,
    pub coupling_metric_rows: usize,
    pub coupling_cycle_rows: usize,
    pub violation_rows: usize,
    pub gate_result_rows: usize,
    pub degradation_alert_rows: usize,
    pub wrapper_rows: usize,
    pub crypto_finding_rows: usize,
    pub dna_gene_rows: usize,
    pub dna_mutation_rows: usize,
    pub secret_rows: usize,
    pub constant_rows: usize,
    pub env_variable_rows: usize,
    pub owasp_finding_rows: usize,
    pub decomposition_decision_rows: usize,
    pub contract_rows: usize,
    pub contract_mismatch_rows: usize,
    pub flushes: usize,
}

/// A batch writer that accepts commands via a channel and writes them
/// in batched transactions on a dedicated thread.
pub struct BatchWriter {
    tx: Sender<BatchCommand>,
    handle: Option<JoinHandle<Result<WriteStats, StorageError>>>,
}

impl BatchWriter {
    /// Create a new batch writer with a dedicated writer thread.
    /// The `conn` is moved to the writer thread.
    pub fn new(conn: Connection) -> Self {
        let (tx, rx) = bounded(CHANNEL_BOUND);

        let handle = thread::Builder::new()
            .name("drift-batch-writer".to_string())
            .spawn(move || writer_loop(conn, rx))
            .expect("failed to spawn batch writer thread");

        Self {
            tx,
            handle: Some(handle),
        }
    }

    /// Send a command to the batch writer.
    pub fn send(&self, cmd: BatchCommand) -> Result<(), StorageError> {
        self.tx.send(cmd).map_err(|_| StorageError::SqliteError {
            message: "batch writer channel disconnected".to_string(),
        })
    }

    /// Flush pending writes (fire-and-forget, does NOT wait for completion).
    pub fn flush(&self) -> Result<(), StorageError> {
        self.send(BatchCommand::Flush)
    }

    /// Flush pending writes and **block** until the batch writer thread confirms
    /// all buffered commands have been committed to SQLite.
    ///
    /// Use this when downstream code needs to read data that was just written
    /// (e.g., `drift_analyze` reading `file_metadata` after `drift_scan`).
    pub fn flush_sync(&self) -> Result<(), StorageError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        self.send(BatchCommand::FlushSync(tx))?;
        rx.recv().map_err(|_| StorageError::SqliteError {
            message: "batch writer thread did not respond to flush_sync".to_string(),
        })
    }

    /// Shut down the writer thread and wait for completion.
    pub fn shutdown(mut self) -> Result<WriteStats, StorageError> {
        let _ = self.tx.send(BatchCommand::Shutdown);
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| StorageError::SqliteError {
                message: "batch writer thread panicked".to_string(),
            })?
        } else {
            Ok(WriteStats::default())
        }
    }
}

impl Drop for BatchWriter {
    fn drop(&mut self) {
        // Signal shutdown if not already done
        let _ = self.tx.send(BatchCommand::Shutdown);
    }
}

fn writer_loop(
    conn: Connection,
    rx: Receiver<BatchCommand>,
) -> Result<WriteStats, StorageError> {
    let mut buffer: Vec<BatchCommand> = Vec::with_capacity(BATCH_SIZE);
    let mut stats = WriteStats::default();

    loop {
        match rx.recv_timeout(FLUSH_TIMEOUT) {
            Ok(BatchCommand::Shutdown) => {
                flush_buffer(&conn, &mut buffer, &mut stats)?;
                break;
            }
            Ok(BatchCommand::Flush) => {
                flush_buffer(&conn, &mut buffer, &mut stats)?;
            }
            Ok(BatchCommand::FlushSync(done_tx)) => {
                flush_buffer(&conn, &mut buffer, &mut stats)?;
                let _ = done_tx.send(());
            }
            Ok(cmd) => {
                buffer.push(cmd);
                if buffer.len() >= BATCH_SIZE {
                    flush_buffer(&conn, &mut buffer, &mut stats)?;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !buffer.is_empty() {
                    flush_buffer(&conn, &mut buffer, &mut stats)?;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                flush_buffer(&conn, &mut buffer, &mut stats)?;
                break;
            }
        }
    }

    Ok(stats)
}

fn flush_buffer(
    conn: &Connection,
    buffer: &mut Vec<BatchCommand>,
    stats: &mut WriteStats,
) -> Result<(), StorageError> {
    if buffer.is_empty() {
        return Ok(());
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::SqliteError {
            message: format!("begin transaction: {e}"),
        })?;

    // Track stats for this batch separately — only apply to `stats` after commit.
    let mut batch_stats = WriteStats::default();

    // Iterate by reference so buffer is NOT consumed until commit succeeds.
    // If any insert fails, tx drops (auto-rollback) and buffer retains commands.
    for cmd in buffer.iter() {
        match cmd {
            BatchCommand::UpsertFileMetadata(rows) => {
                upsert_file_metadata(&tx, rows)?;
                batch_stats.file_metadata_rows += rows.len();
            }
            BatchCommand::InsertParseCache(rows) => {
                insert_parse_cache(&tx, rows)?;
                batch_stats.parse_cache_rows += rows.len();
            }
            BatchCommand::InsertFunctions(rows) => {
                insert_functions(&tx, rows)?;
                batch_stats.function_rows += rows.len();
            }
            BatchCommand::DeleteFileMetadata(paths) => {
                delete_file_metadata(&tx, paths)?;
                batch_stats.deleted_files += paths.len();
            }
            BatchCommand::InsertCallEdges(rows) => {
                insert_call_edges(&tx, rows)?;
                batch_stats.call_edge_rows += rows.len();
            }
            BatchCommand::InsertDetections(rows) => {
                insert_detections(&tx, rows)?;
                batch_stats.detection_rows += rows.len();
            }
            BatchCommand::InsertBoundaries(rows) => {
                insert_boundaries(&tx, rows)?;
                batch_stats.boundary_rows += rows.len();
            }
            BatchCommand::InsertPatternConfidence(rows) => {
                insert_pattern_confidence(&tx, rows)?;
                batch_stats.pattern_confidence_rows += rows.len();
            }
            BatchCommand::InsertOutliers(rows) => {
                insert_outlier_rows(&tx, rows)?;
                batch_stats.outlier_rows += rows.len();
            }
            BatchCommand::InsertConventions(rows) => {
                insert_convention_rows(&tx, rows)?;
                batch_stats.convention_rows += rows.len();
            }
            BatchCommand::InsertScanHistory(rows) => {
                insert_scan_history_rows(&tx, rows)?;
                batch_stats.scan_history_rows += rows.len();
            }
            BatchCommand::InsertDataAccess(rows) => {
                insert_data_access_rows(&tx, rows)?;
                batch_stats.data_access_rows += rows.len();
            }
            BatchCommand::InsertReachabilityCache(rows) => {
                insert_reachability_cache(&tx, rows)?;
                batch_stats.reachability_cache_rows += rows.len();
            }
            BatchCommand::InsertTaintFlows(rows) => {
                insert_taint_flows(&tx, rows)?;
                batch_stats.taint_flow_rows += rows.len();
            }
            BatchCommand::InsertErrorGaps(rows) => {
                insert_error_gaps(&tx, rows)?;
                batch_stats.error_gap_rows += rows.len();
            }
            BatchCommand::InsertImpactScores(rows) => {
                insert_impact_scores(&tx, rows)?;
                batch_stats.impact_score_rows += rows.len();
            }
            BatchCommand::InsertTestQuality(rows) => {
                insert_test_quality(&tx, rows)?;
                batch_stats.test_quality_rows += rows.len();
            }
            BatchCommand::InsertCouplingMetrics(rows) => {
                insert_coupling_metrics(&tx, rows)?;
                batch_stats.coupling_metric_rows += rows.len();
            }
            BatchCommand::InsertCouplingCycles(rows) => {
                insert_coupling_cycles(&tx, rows)?;
                batch_stats.coupling_cycle_rows += rows.len();
            }
            BatchCommand::InsertViolations(rows) => {
                insert_violations(&tx, rows)?;
                batch_stats.violation_rows += rows.len();
            }
            BatchCommand::InsertGateResults(rows) => {
                insert_gate_results(&tx, rows)?;
                batch_stats.gate_result_rows += rows.len();
            }
            BatchCommand::InsertDegradationAlerts(rows) => {
                insert_degradation_alerts(&tx, rows)?;
                batch_stats.degradation_alert_rows += rows.len();
            }
            BatchCommand::InsertWrappers(rows) => {
                insert_wrappers(&tx, rows)?;
                batch_stats.wrapper_rows += rows.len();
            }
            BatchCommand::InsertCryptoFindings(rows) => {
                insert_crypto_findings(&tx, rows)?;
                batch_stats.crypto_finding_rows += rows.len();
            }
            BatchCommand::InsertDnaGenes(rows) => {
                insert_dna_genes(&tx, rows)?;
                batch_stats.dna_gene_rows += rows.len();
            }
            BatchCommand::InsertDnaMutations(rows) => {
                insert_dna_mutations(&tx, rows)?;
                batch_stats.dna_mutation_rows += rows.len();
            }
            BatchCommand::InsertSecrets(rows) => {
                insert_secrets(&tx, rows)?;
                batch_stats.secret_rows += rows.len();
            }
            BatchCommand::InsertConstants(rows) => {
                insert_constants(&tx, rows)?;
                batch_stats.constant_rows += rows.len();
            }
            BatchCommand::InsertEnvVariables(rows) => {
                insert_env_variables(&tx, rows)?;
                batch_stats.env_variable_rows += rows.len();
            }
            BatchCommand::InsertOwaspFindings(rows) => {
                insert_owasp_findings(&tx, rows)?;
                batch_stats.owasp_finding_rows += rows.len();
            }
            BatchCommand::InsertDecompositionDecisions(rows) => {
                insert_decomposition_decisions(&tx, rows)?;
                batch_stats.decomposition_decision_rows += rows.len();
            }
            BatchCommand::InsertContracts(rows) => {
                insert_contracts(&tx, rows)?;
                batch_stats.contract_rows += rows.len();
            }
            BatchCommand::InsertContractMismatches(rows) => {
                insert_contract_mismatches(&tx, rows)?;
                batch_stats.contract_mismatch_rows += rows.len();
            }
            BatchCommand::Flush | BatchCommand::FlushSync(_) | BatchCommand::Shutdown => {}
        }
    }

    tx.commit().map_err(|e| StorageError::SqliteError {
        message: format!("commit: {e}"),
    })?;

    // Commit succeeded — clear buffer and merge stats.
    buffer.clear();
    stats.file_metadata_rows += batch_stats.file_metadata_rows;
    stats.parse_cache_rows += batch_stats.parse_cache_rows;
    stats.function_rows += batch_stats.function_rows;
    stats.deleted_files += batch_stats.deleted_files;
    stats.call_edge_rows += batch_stats.call_edge_rows;
    stats.detection_rows += batch_stats.detection_rows;
    stats.boundary_rows += batch_stats.boundary_rows;
    stats.pattern_confidence_rows += batch_stats.pattern_confidence_rows;
    stats.outlier_rows += batch_stats.outlier_rows;
    stats.convention_rows += batch_stats.convention_rows;
    stats.scan_history_rows += batch_stats.scan_history_rows;
    stats.data_access_rows += batch_stats.data_access_rows;
    stats.reachability_cache_rows += batch_stats.reachability_cache_rows;
    stats.taint_flow_rows += batch_stats.taint_flow_rows;
    stats.error_gap_rows += batch_stats.error_gap_rows;
    stats.impact_score_rows += batch_stats.impact_score_rows;
    stats.test_quality_rows += batch_stats.test_quality_rows;
    stats.coupling_metric_rows += batch_stats.coupling_metric_rows;
    stats.coupling_cycle_rows += batch_stats.coupling_cycle_rows;
    stats.violation_rows += batch_stats.violation_rows;
    stats.gate_result_rows += batch_stats.gate_result_rows;
    stats.degradation_alert_rows += batch_stats.degradation_alert_rows;
    stats.wrapper_rows += batch_stats.wrapper_rows;
    stats.crypto_finding_rows += batch_stats.crypto_finding_rows;
    stats.dna_gene_rows += batch_stats.dna_gene_rows;
    stats.dna_mutation_rows += batch_stats.dna_mutation_rows;
    stats.secret_rows += batch_stats.secret_rows;
    stats.constant_rows += batch_stats.constant_rows;
    stats.env_variable_rows += batch_stats.env_variable_rows;
    stats.owasp_finding_rows += batch_stats.owasp_finding_rows;
    stats.decomposition_decision_rows += batch_stats.decomposition_decision_rows;
    stats.contract_rows += batch_stats.contract_rows;
    stats.contract_mismatch_rows += batch_stats.contract_mismatch_rows;
    stats.flushes += 1;

    Ok(())
}

fn upsert_file_metadata(
    conn: &Connection,
    rows: &[FileMetadataRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO file_metadata
             (path, language, file_size, content_hash, mtime_secs, mtime_nanos,
              last_scanned_at, scan_duration_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.path,
            row.language,
            row.file_size,
            row.content_hash,
            row.mtime_secs,
            row.mtime_nanos,
            row.last_scanned_at,
            row.scan_duration_us,
        ])
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;
    }
    Ok(())
}

fn insert_parse_cache(
    conn: &Connection,
    rows: &[ParseCacheRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO parse_cache
             (content_hash, language, parse_result_json, created_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.content_hash,
            row.language,
            row.parse_result_json,
            row.created_at,
        ])
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;
    }
    Ok(())
}

fn insert_functions(
    conn: &Connection,
    rows: &[FunctionRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO functions
             (file, name, qualified_name, language, line, end_line,
              parameter_count, return_type, is_exported, is_async,
              body_hash, signature_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.file,
            row.name,
            row.qualified_name,
            row.language,
            row.line,
            row.end_line,
            row.parameter_count,
            row.return_type,
            row.is_exported,
            row.is_async,
            row.body_hash,
            row.signature_hash,
        ])
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;
    }
    Ok(())
}

fn delete_file_metadata(
    conn: &Connection,
    paths: &[String],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached("DELETE FROM file_metadata WHERE path = ?1")
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    for path in paths {
        stmt.execute(rusqlite::params![path])
            .map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })?;
    }
    Ok(())
}

fn insert_call_edges(
    conn: &Connection,
    rows: &[CallEdgeRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO call_edges
             (caller_id, callee_id, resolution, confidence, call_site_line)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.caller_id, row.callee_id, row.resolution,
            row.confidence, row.call_site_line,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_detections(
    conn: &Connection,
    rows: &[DetectionRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO detections
             (file, line, column_num, pattern_id, category, confidence,
              detection_method, cwe_ids, owasp, matched_text)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.file, row.line, row.column_num, row.pattern_id,
            row.category, row.confidence, row.detection_method,
            row.cwe_ids, row.owasp, row.matched_text,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_boundaries(
    conn: &Connection,
    rows: &[BoundaryRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO boundaries
             (file, framework, model_name, table_name, field_name, sensitivity, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.file, row.framework, row.model_name, row.table_name,
            row.field_name, row.sensitivity, row.confidence,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_pattern_confidence(
    conn: &Connection,
    rows: &[PatternConfidenceRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO pattern_confidence
             (pattern_id, alpha, beta, posterior_mean, credible_interval_low,
              credible_interval_high, tier, momentum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.pattern_id, row.alpha, row.beta, row.posterior_mean,
            row.credible_interval_low, row.credible_interval_high,
            row.tier, row.momentum,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_outlier_rows(
    conn: &Connection,
    rows: &[OutlierDetectionRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO outliers
             (pattern_id, file, line, deviation_score, significance, method)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.pattern_id, row.file, row.line,
            row.deviation_score, row.significance, row.method,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_convention_rows(
    conn: &Connection,
    rows: &[ConventionInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO conventions
             (pattern_id, category, scope, dominance_ratio, promotion_status,
              discovered_at, last_seen, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.pattern_id, row.category, row.scope, row.dominance_ratio,
            row.promotion_status, row.discovered_at, row.last_seen, row.expires_at,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_scan_history_rows(
    conn: &Connection,
    rows: &[ScanHistoryInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO scan_history (started_at, root_path, status)
             VALUES (?1, ?2, 'running')",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![row.started_at, row.root_path])
            .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_data_access_rows(
    conn: &Connection,
    rows: &[DataAccessInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO data_access
             (function_id, table_name, operation, framework, line, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.function_id, row.table_name, row.operation,
            row.framework, row.line, row.confidence,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

// ─── v004: Graph Intelligence handlers ──────────────────────────────

fn insert_reachability_cache(
    conn: &Connection,
    rows: &[ReachabilityCacheRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO reachability_cache
             (source_node, direction, reachable_set, sensitivity)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.source_node, row.direction, row.reachable_set, row.sensitivity,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_taint_flows(
    conn: &Connection,
    rows: &[TaintFlowInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO taint_flows
             (source_file, source_line, source_type, sink_file, sink_line, sink_type,
              cwe_id, is_sanitized, path, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.source_file, row.source_line, row.source_type,
            row.sink_file, row.sink_line, row.sink_type,
            row.cwe_id, row.is_sanitized as i32, row.path, row.confidence,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_error_gaps(
    conn: &Connection,
    rows: &[ErrorGapInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO error_gaps
             (file, function_id, gap_type, error_type, propagation_chain,
              framework, cwe_id, severity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.file, row.function_id, row.gap_type, row.error_type,
            row.propagation_chain, row.framework, row.cwe_id, row.severity,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_impact_scores(
    conn: &Connection,
    rows: &[ImpactScoreInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO impact_scores
             (function_id, blast_radius, risk_score, is_dead_code,
              dead_code_reason, exclusion_category)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.function_id, row.blast_radius, row.risk_score,
            row.is_dead_code as i32, row.dead_code_reason, row.exclusion_category,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_test_quality(
    conn: &Connection,
    rows: &[TestQualityInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO test_quality
             (function_id, coverage_breadth, coverage_depth, assertion_density,
              mock_ratio, isolation, freshness, stability, overall_score, smells)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.function_id, row.coverage_breadth, row.coverage_depth,
            row.assertion_density, row.mock_ratio, row.isolation,
            row.freshness, row.stability, row.overall_score, row.smells,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

// ─── v005: Structural Intelligence handlers ─────────────────────────

fn insert_coupling_metrics(
    conn: &Connection,
    rows: &[CouplingMetricInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO coupling_metrics
             (module, ce, ca, instability, abstractness, distance, zone)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.module, row.ce, row.ca, row.instability,
            row.abstractness, row.distance, row.zone,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_coupling_cycles(
    conn: &Connection,
    rows: &[CouplingCycleInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO coupling_cycles (members, break_suggestions) VALUES (?1, ?2)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![row.members, row.break_suggestions])
            .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

// ─── v006: Enforcement handlers ─────────────────────────────────────

fn insert_violations(
    conn: &Connection,
    rows: &[ViolationInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO violations
             (id, file, line, column_num, end_line, end_column, severity,
              pattern_id, rule_id, message, quick_fix_strategy, quick_fix_description,
              cwe_id, owasp_category, suppressed, is_new)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.id, row.file, row.line, row.column_num,
            row.end_line, row.end_column, row.severity,
            row.pattern_id, row.rule_id, row.message,
            row.quick_fix_strategy, row.quick_fix_description,
            row.cwe_id, row.owasp_category, row.suppressed as i32, row.is_new as i32,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_gate_results(
    conn: &Connection,
    rows: &[GateResultInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO gate_results
             (gate_id, status, passed, score, summary, violation_count,
              warning_count, execution_time_ms, details, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.gate_id, row.status, row.passed as i32, row.score,
            row.summary, row.violation_count, row.warning_count,
            row.execution_time_ms, row.details, row.error,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_degradation_alerts(
    conn: &Connection,
    rows: &[DegradationAlertInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO degradation_alerts
             (alert_type, severity, message, current_value, previous_value, delta)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.alert_type, row.severity, row.message,
            row.current_value, row.previous_value, row.delta,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

// ─── v007: Remaining Structural Entity handlers ──────────────────────

fn insert_wrappers(
    conn: &Connection,
    rows: &[WrapperInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO wrappers
             (name, file, line, category, wrapped_primitives, framework,
              confidence, is_multi_primitive, is_exported, usage_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.name, row.file, row.line, row.category, row.wrapped_primitives,
            row.framework, row.confidence, row.is_multi_primitive as i32,
            row.is_exported as i32, row.usage_count,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_crypto_findings(
    conn: &Connection,
    rows: &[CryptoFindingInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO crypto_findings
             (file, line, category, description, code, confidence,
              cwe_id, owasp, remediation, language)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.file, row.line, row.category, row.description, row.code,
            row.confidence, row.cwe_id, row.owasp, row.remediation, row.language,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_dna_genes(
    conn: &Connection,
    rows: &[DnaGeneInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO dna_genes
             (gene_id, name, description, dominant_allele, alleles,
              confidence, consistency, exemplars)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.gene_id, row.name, row.description, row.dominant_allele,
            row.alleles, row.confidence, row.consistency, row.exemplars,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_dna_mutations(
    conn: &Connection,
    rows: &[DnaMutationInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO dna_mutations
             (id, file, line, gene_id, expected, actual, impact,
              code, suggestion, detected_at, resolved, resolved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, NULL)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.id, row.file, row.line, row.gene_id, row.expected,
            row.actual, row.impact, row.code, row.suggestion, row.detected_at,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_secrets(
    conn: &Connection,
    rows: &[SecretInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO secrets
             (pattern_name, redacted_value, file, line, severity,
              entropy, confidence, cwe_ids)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.pattern_name, row.redacted_value, row.file, row.line,
            row.severity, row.entropy, row.confidence, row.cwe_ids,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_constants(
    conn: &Connection,
    rows: &[ConstantInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO constants
             (name, value, file, line, is_used, language, is_named)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.name, row.value, row.file, row.line,
            row.is_used as i32, row.language, row.is_named as i32,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

// ─── v008: Remaining Unwired Table handlers ──────────────────────────

fn insert_env_variables(
    conn: &Connection,
    rows: &[EnvVariableInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO env_variables
             (name, file, line, access_method, has_default, defined_in_env, framework_prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.name, row.file, row.line, row.access_method,
            row.has_default as i32, row.defined_in_env as i32, row.framework_prefix,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_owasp_findings(
    conn: &Connection,
    rows: &[OwaspFindingInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO owasp_findings
             (id, detector, file, line, description, severity,
              cwes, owasp_categories, confidence, remediation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.id, row.detector, row.file, row.line, row.description,
            row.severity, row.cwes, row.owasp_categories, row.confidence,
            row.remediation,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_decomposition_decisions(
    conn: &Connection,
    rows: &[DecompositionDecisionInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO decomposition_decisions
             (dna_profile_hash, adjustment, confidence, dna_similarity,
              narrative, source_dna_hash, applied_weight)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.dna_profile_hash, row.adjustment, row.confidence,
            row.dna_similarity, row.narrative, row.source_dna_hash,
            row.applied_weight,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_contracts(
    conn: &Connection,
    rows: &[ContractInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO contracts
             (id, paradigm, source_file, framework, confidence, endpoints)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.id, row.paradigm, row.source_file, row.framework,
            row.confidence, row.endpoints,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

fn insert_contract_mismatches(
    conn: &Connection,
    rows: &[ContractMismatchInsertRow],
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO contract_mismatches
             (backend_endpoint, frontend_call, mismatch_type, severity, message)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(rusqlite::params![
            row.backend_endpoint, row.frontend_call, row.mismatch_type,
            row.severity, row.message,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}
