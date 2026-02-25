//! `DriftStorageEngine` — unified storage engine implementing all 7 drift storage traits.
//!
//! Wraps `DatabaseManager` (read/write routing) + `BatchWriter` (async batch writes).
//! All reads go through `with_reader()`, all writes through `with_writer()`.
//! This is the single owner of both — no code outside this module should touch
//! a raw `&Connection` for drift.db operations.
//!
//! Pattern reference: `cortex-storage/src/engine.rs`

use std::path::Path;
use std::sync::Arc;

use drift_core::errors::StorageError;
use drift_core::traits::storage::drift_files::{
    FileMetadataRow, IDriftFiles, ParseCacheRow,
};
use drift_core::traits::storage::drift_analysis::{
    BoundaryRow, CallEdgeRow, ConventionRow, DetectionRow, DetectionSummaryRow,
    FunctionRow, IDriftAnalysis, OutlierRow, PatternConfidenceRow, ScanHistoryRow,
};
use drift_core::traits::storage::drift_structural::{
    ConstantRow, ContractMismatchRow, ContractRow, CouplingCycleRow,
    CouplingMetricsRow, CryptoFindingRow, DataAccessRow, DecompositionDecisionRow, DnaGeneRow,
    DnaMutationRow, EnvVariableRow, ErrorGapRow, IDriftStructural, ImpactScoreRow,
    OwaspFindingRow, ReachabilityCacheRow, SecretRow, TaintFlowRow, TestCoverageRow,
    TestQualityRow, WrapperRow, ConstraintRow, ConstraintVerificationRow,
};
use drift_core::traits::storage::drift_enforcement::{
    AuditSnapshotRow, DegradationAlertRow, FeedbackRow, FeedbackStats, GateResultRow,
    HealthTrendRow, IDriftEnforcement, PolicyResultRow, ViolationRow,
};
use drift_core::traits::storage::drift_advanced::{
    CorrectionRow, IDriftAdvanced, SimulationRow,
};
use drift_core::traits::storage::drift_batch::{IDriftBatchWriter, WriteStats};
use drift_core::traits::storage::drift_reader::IDriftReader;

use crate::batch::commands::BatchCommand;
use crate::batch::BatchWriter;
use crate::connection::DatabaseManager;
use crate::queries;

/// The unified Drift storage engine.
///
/// Owns `DatabaseManager` (single write connection + read pool) and
/// `BatchWriter` (async batch writes via crossbeam channel).
/// Implements all 7 drift storage traits from `drift-core`.
pub struct DriftStorageEngine {
    db: DatabaseManager,
    batch: BatchWriter,
}

impl DriftStorageEngine {
    /// Open a file-backed storage engine at the given path.
    /// Runs migrations and applies pragmas.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let db = DatabaseManager::open(path)?;
        let batch_conn = db.open_batch_connection()?;
        let batch = BatchWriter::new(batch_conn);
        Ok(Self { db, batch })
    }

    /// Open an in-memory storage engine (for testing).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let db = DatabaseManager::open_in_memory()?;
        let batch_conn = db.open_batch_connection()?;
        let batch = BatchWriter::new(batch_conn);
        Ok(Self { db, batch })
    }

    /// Send a typed `BatchCommand` to the batch writer.
    /// This is the concrete method for NAPI bindings — NOT on the trait.
    pub fn send_batch(&self, command: BatchCommand) -> Result<(), StorageError> {
        self.batch.send(command)
    }

    /// WAL checkpoint delegation.
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        self.db.checkpoint()
    }

    /// Database file path (None for in-memory).
    pub fn path(&self) -> Option<&Path> {
        self.db.path()
    }

    /// Expose as `Arc<dyn IDriftReader>` for bridge consumption.
    pub fn as_drift_reader(self: &Arc<Self>) -> Arc<dyn IDriftReader> {
        Arc::clone(self) as Arc<dyn IDriftReader>
    }

    /// Flush pending batch writes (fire-and-forget).
    pub fn flush_batch(&self) -> Result<(), StorageError> {
        self.batch.flush()
    }

    /// Flush pending batch writes and block until complete.
    pub fn flush_batch_sync(&self) -> Result<(), StorageError> {
        self.batch.flush_sync()
    }

    /// Raw read access — for operations not yet covered by a trait method.
    /// Prefer trait methods where possible.
    pub fn with_reader<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, StorageError>,
    {
        self.db.with_reader(f)
    }

    /// Raw write access — for operations not yet covered by a trait method.
    /// Prefer trait methods where possible.
    pub fn with_writer<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, StorageError>,
    {
        self.db.with_writer(f)
    }

    /// Open a batch connection from the underlying DatabaseManager.
    /// Used during runtime construction for bridge event handlers that need
    /// their own connection.
    pub fn open_batch_connection(&self) -> Result<rusqlite::Connection, StorageError> {
        self.db.open_batch_connection()
    }
}

// ─── Helper: StorageError from rusqlite ─────────────────────────────────────

fn sqe(e: impl std::fmt::Display) -> StorageError {
    StorageError::SqliteError {
        message: e.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// From impls: drift-storage record types → drift-core trait row types
// ═══════════════════════════════════════════════════════════════════════════════

impl From<queries::files::FileMetadataRecord> for FileMetadataRow {
    fn from(r: queries::files::FileMetadataRecord) -> Self {
        Self {
            path: r.path,
            language: r.language,
            file_size: r.file_size,
            content_hash: r.content_hash,
            mtime_secs: r.mtime_secs,
            mtime_nanos: r.mtime_nanos,
            last_scanned_at: r.last_scanned_at,
            scan_duration_us: r.scan_duration_us,
            pattern_count: r.pattern_count,
            function_count: r.function_count,
            error_count: r.error_count,
            error: r.error,
        }
    }
}

impl From<queries::parse_cache::ParseCacheRecord> for ParseCacheRow {
    fn from(r: queries::parse_cache::ParseCacheRecord) -> Self {
        Self {
            content_hash: r.content_hash,
            language: r.language,
            parse_result_json: r.parse_result_json,
            created_at: r.created_at,
        }
    }
}

impl From<queries::functions::FunctionRecord> for FunctionRow {
    fn from(r: queries::functions::FunctionRecord) -> Self {
        Self {
            id: r.id,
            file: r.file,
            name: r.name,
            qualified_name: r.qualified_name,
            language: r.language,
            line: r.line,
            end_line: r.end_line,
            parameter_count: r.parameter_count,
            return_type: r.return_type,
            is_exported: r.is_exported,
            is_async: r.is_async,
            body_hash: r.body_hash,
            signature_hash: r.signature_hash,
        }
    }
}

impl From<queries::detections::DetectionRecord> for DetectionRow {
    fn from(r: queries::detections::DetectionRecord) -> Self {
        Self {
            id: r.id,
            file: r.file,
            line: r.line,
            column_num: r.column_num,
            pattern_id: r.pattern_id,
            category: r.category,
            confidence: r.confidence,
            detection_method: r.detection_method,
            cwe_ids: r.cwe_ids,
            owasp: r.owasp,
            matched_text: r.matched_text,
            created_at: r.created_at,
        }
    }
}

impl From<queries::detections::DetectionSummaryRow> for DetectionSummaryRow {
    fn from(r: queries::detections::DetectionSummaryRow) -> Self {
        Self {
            detection_method: r.detection_method,
            count: r.count,
            avg_confidence: r.avg_confidence,
        }
    }
}

impl From<queries::patterns::PatternConfidenceRow> for PatternConfidenceRow {
    fn from(r: queries::patterns::PatternConfidenceRow) -> Self {
        Self {
            pattern_id: r.pattern_id,
            alpha: r.alpha,
            beta: r.beta,
            posterior_mean: r.posterior_mean,
            credible_interval_low: r.credible_interval_low,
            credible_interval_high: r.credible_interval_high,
            tier: r.tier,
            momentum: r.momentum,
            last_updated: r.last_updated,
        }
    }
}

impl From<&PatternConfidenceRow> for queries::patterns::PatternConfidenceRow {
    fn from(r: &PatternConfidenceRow) -> Self {
        Self {
            pattern_id: r.pattern_id.clone(),
            alpha: r.alpha,
            beta: r.beta,
            posterior_mean: r.posterior_mean,
            credible_interval_low: r.credible_interval_low,
            credible_interval_high: r.credible_interval_high,
            tier: r.tier.clone(),
            momentum: r.momentum.clone(),
            last_updated: r.last_updated,
        }
    }
}

impl From<queries::patterns::OutlierRow> for OutlierRow {
    fn from(r: queries::patterns::OutlierRow) -> Self {
        Self {
            id: r.id,
            pattern_id: r.pattern_id,
            file: r.file,
            line: r.line,
            deviation_score: r.deviation_score,
            significance: r.significance,
            method: r.method,
            created_at: r.created_at,
        }
    }
}

impl From<&OutlierRow> for queries::patterns::OutlierRow {
    fn from(r: &OutlierRow) -> Self {
        Self {
            id: r.id,
            pattern_id: r.pattern_id.clone(),
            file: r.file.clone(),
            line: r.line,
            deviation_score: r.deviation_score,
            significance: r.significance.clone(),
            method: r.method.clone(),
            created_at: r.created_at,
        }
    }
}

impl From<queries::patterns::ConventionRow> for ConventionRow {
    fn from(r: queries::patterns::ConventionRow) -> Self {
        Self {
            id: r.id,
            pattern_id: r.pattern_id,
            category: r.category,
            scope: r.scope,
            dominance_ratio: r.dominance_ratio,
            promotion_status: r.promotion_status,
            discovered_at: r.discovered_at,
            last_seen: r.last_seen,
            expires_at: r.expires_at,
        }
    }
}

impl From<&ConventionRow> for queries::patterns::ConventionRow {
    fn from(r: &ConventionRow) -> Self {
        Self {
            id: r.id,
            pattern_id: r.pattern_id.clone(),
            category: r.category.clone(),
            scope: r.scope.clone(),
            dominance_ratio: r.dominance_ratio,
            promotion_status: r.promotion_status.clone(),
            discovered_at: r.discovered_at,
            last_seen: r.last_seen,
            expires_at: r.expires_at,
        }
    }
}

impl From<queries::boundaries::BoundaryRecord> for BoundaryRow {
    fn from(r: queries::boundaries::BoundaryRecord) -> Self {
        Self {
            id: r.id,
            file: r.file,
            framework: r.framework,
            model_name: r.model_name,
            table_name: r.table_name,
            field_name: r.field_name,
            sensitivity: r.sensitivity,
            confidence: r.confidence,
            created_at: r.created_at,
        }
    }
}

impl From<queries::call_edges::CallEdgeRecord> for CallEdgeRow {
    fn from(r: queries::call_edges::CallEdgeRecord) -> Self {
        Self {
            caller_id: r.caller_id,
            callee_id: r.callee_id,
            resolution: r.resolution,
            confidence: r.confidence,
            call_site_line: r.call_site_line,
        }
    }
}

impl From<queries::scan_history::ScanHistoryRow> for ScanHistoryRow {
    fn from(r: queries::scan_history::ScanHistoryRow) -> Self {
        Self {
            id: r.id,
            started_at: r.started_at,
            completed_at: r.completed_at,
            root_path: r.root_path,
            total_files: r.total_files,
            added_files: r.added_files,
            modified_files: r.modified_files,
            removed_files: r.removed_files,
            unchanged_files: r.unchanged_files,
            duration_ms: r.duration_ms,
            status: r.status,
            error: r.error,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftFiles implementation
// ═══════════════════════════════════════════════════════════════════════════════

impl IDriftFiles for DriftStorageEngine {
    fn load_all_file_metadata(&self) -> Result<Vec<FileMetadataRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::files::load_all_file_metadata(conn)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_file_metadata(&self, path: &str) -> Result<Option<FileMetadataRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::files::get_file_metadata(conn, path)?;
            Ok(row.map(Into::into))
        })
    }

    fn update_function_count(&self, path: &str, count: i64) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            queries::files::update_function_count(conn, path, count)
        })
    }

    fn update_file_error(
        &self,
        path: &str,
        error_count: i64,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            queries::files::update_file_error(conn, path, error_count, error_msg)
        })
    }

    fn count_files(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::files::count_files)
    }

    fn get_parse_cache_by_hash(
        &self,
        content_hash: &[u8],
    ) -> Result<Option<ParseCacheRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::parse_cache::get_by_hash(conn, content_hash)?;
            Ok(row.map(Into::into))
        })
    }

    fn insert_parse_cache(
        &self,
        content_hash: &[u8],
        language: &str,
        parse_result_json: &str,
        created_at: i64,
    ) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            queries::parse_cache::insert(conn, content_hash, language, parse_result_json, created_at)
        })
    }

    fn invalidate_parse_cache(&self, content_hash: &[u8]) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            queries::parse_cache::invalidate(conn, content_hash)
        })
    }

    fn count_parse_cache(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::parse_cache::count)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftAnalysis implementation
// ═══════════════════════════════════════════════════════════════════════════════

impl IDriftAnalysis for DriftStorageEngine {
    // ── functions ──

    fn get_functions_by_file(&self, file: &str) -> Result<Vec<FunctionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::functions::get_functions_by_file(conn, file)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_function_by_qualified_name(
        &self,
        qualified_name: &str,
    ) -> Result<Option<FunctionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::functions::get_function_by_qualified_name(conn, qualified_name)?;
            Ok(row.map(Into::into))
        })
    }

    fn delete_functions_by_file(&self, file: &str) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| {
            queries::functions::delete_functions_by_file(conn, file)
        })
    }

    fn count_functions(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::functions::count_functions)
    }

    fn count_entry_points(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::functions::count_entry_points)
    }

    // ── detections ──

    fn insert_detections(&self, detections: &[DetectionRow]) -> Result<usize, StorageError> {
        let records: Vec<queries::detections::DetectionRecord> = detections
            .iter()
            .map(|d| queries::detections::DetectionRecord {
                id: d.id,
                file: d.file.clone(),
                line: d.line,
                column_num: d.column_num,
                pattern_id: d.pattern_id.clone(),
                category: d.category.clone(),
                confidence: d.confidence,
                detection_method: d.detection_method.clone(),
                cwe_ids: d.cwe_ids.clone(),
                owasp: d.owasp.clone(),
                matched_text: d.matched_text.clone(),
                created_at: d.created_at,
            })
            .collect();
        self.db.with_writer(|conn| {
            queries::detections::insert_detections(conn, &records)
        })
    }

    fn get_detections_by_file(&self, file: &str) -> Result<Vec<DetectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::get_detections_by_file(conn, file)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_detections_by_category(&self, category: &str) -> Result<Vec<DetectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::get_detections_by_category(conn, category)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn query_all_detections(&self, limit: usize) -> Result<Vec<DetectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::query_all_detections(conn, limit)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn delete_detections_by_file(&self, file: &str) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| {
            queries::detections::delete_detections_by_file(conn, file)
        })
    }

    fn count_detections(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::detections::count_detections)
    }

    fn get_detections_by_method(&self, method: &str) -> Result<Vec<DetectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::get_detections_by_method(conn, method)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_detections_by_pattern_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<DetectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::get_detections_by_pattern_prefix(conn, prefix)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_detections_by_cwe(&self, cwe_id: u32) -> Result<Vec<DetectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::get_detections_by_cwe(conn, cwe_id)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_framework_detection_summary(&self) -> Result<Vec<DetectionSummaryRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::detections::get_framework_detection_summary(conn)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    // ── patterns ──

    fn upsert_confidence(&self, row: &PatternConfidenceRow) -> Result<(), StorageError> {
        let storage_row: queries::patterns::PatternConfidenceRow = row.into();
        self.db.with_writer(|conn| {
            queries::patterns::upsert_confidence(conn, &storage_row)
        })
    }

    fn query_confidence_by_tier(
        &self,
        tier: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PatternConfidenceRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::patterns::query_confidence_by_tier(conn, tier, after_id, limit)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn query_all_confidence(&self) -> Result<Vec<PatternConfidenceRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::patterns::query_all_confidence(conn)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn insert_outlier(&self, row: &OutlierRow) -> Result<(), StorageError> {
        let storage_row: queries::patterns::OutlierRow = row.into();
        self.db.with_writer(|conn| {
            queries::patterns::insert_outlier(conn, &storage_row)
        })
    }

    fn query_outliers_by_pattern(
        &self,
        pattern_id: &str,
    ) -> Result<Vec<OutlierRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::patterns::query_outliers_by_pattern(conn, pattern_id)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn insert_convention(&self, row: &ConventionRow) -> Result<(), StorageError> {
        let storage_row: queries::patterns::ConventionRow = row.into();
        self.db.with_writer(|conn| {
            queries::patterns::insert_convention(conn, &storage_row)
        })
    }

    fn query_conventions_by_category(
        &self,
        category: &str,
    ) -> Result<Vec<ConventionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::patterns::query_conventions_by_category(conn, category)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn query_all_conventions(&self) -> Result<Vec<ConventionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::patterns::query_all_conventions(conn)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    // ── boundaries ──

    fn insert_boundaries(&self, boundaries: &[BoundaryRow]) -> Result<usize, StorageError> {
        let records: Vec<queries::boundaries::BoundaryRecord> = boundaries
            .iter()
            .map(|b| queries::boundaries::BoundaryRecord {
                id: b.id,
                file: b.file.clone(),
                framework: b.framework.clone(),
                model_name: b.model_name.clone(),
                table_name: b.table_name.clone(),
                field_name: b.field_name.clone(),
                sensitivity: b.sensitivity.clone(),
                confidence: b.confidence,
                created_at: b.created_at,
            })
            .collect();
        self.db.with_writer(|conn| {
            queries::boundaries::insert_boundaries(conn, &records)
        })
    }

    fn get_boundaries_by_file(&self, file: &str) -> Result<Vec<BoundaryRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::boundaries::get_boundaries_by_file(conn, file)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_boundaries_by_framework(
        &self,
        framework: &str,
    ) -> Result<Vec<BoundaryRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::boundaries::get_boundaries_by_framework(conn, framework)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_sensitive_boundaries(&self) -> Result<Vec<BoundaryRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::boundaries::get_sensitive_boundaries(conn)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn delete_boundaries_by_file(&self, file: &str) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| {
            queries::boundaries::delete_boundaries_by_file(conn, file)
        })
    }

    fn count_boundaries(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::boundaries::count_boundaries)
    }

    // ── call_edges ──

    fn insert_call_edges(&self, edges: &[CallEdgeRow]) -> Result<usize, StorageError> {
        let records: Vec<queries::call_edges::CallEdgeRecord> = edges
            .iter()
            .map(|e| queries::call_edges::CallEdgeRecord {
                caller_id: e.caller_id,
                callee_id: e.callee_id,
                resolution: e.resolution.clone(),
                confidence: e.confidence,
                call_site_line: e.call_site_line,
            })
            .collect();
        self.db.with_writer(|conn| {
            queries::call_edges::insert_call_edges(conn, &records)
        })
    }

    fn get_edges_by_caller(&self, caller_id: i64) -> Result<Vec<CallEdgeRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::call_edges::get_edges_by_caller(conn, caller_id)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn get_edges_by_callee(&self, callee_id: i64) -> Result<Vec<CallEdgeRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::call_edges::get_edges_by_callee(conn, callee_id)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn delete_edges_by_file(&self, file: &str) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| {
            queries::call_edges::delete_edges_by_file(conn, file)
        })
    }

    fn count_call_edges(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::call_edges::count_call_edges)
    }

    fn count_resolved_edges(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::call_edges::count_resolved_edges)
    }

    // ── scan_history ──

    fn insert_scan_start(&self, started_at: i64, root_path: &str) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::scan_history::insert_scan_start(conn, started_at, root_path)
        })
    }

    fn update_scan_complete(
        &self,
        id: i64,
        completed_at: i64,
        total_files: i64,
        added_files: i64,
        modified_files: i64,
        removed_files: i64,
        unchanged_files: i64,
        duration_ms: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            queries::scan_history::update_scan_complete(
                conn, id, completed_at, total_files, added_files, modified_files,
                removed_files, unchanged_files, duration_ms, status, error,
            )
        })
    }

    fn query_recent_scans(&self, limit: usize) -> Result<Vec<ScanHistoryRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::scan_history::query_recent(conn, limit)?;
            Ok(rows.into_iter().map(Into::into).collect())
        })
    }

    fn count_scans(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::scan_history::count)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftStructural implementation
// ═══════════════════════════════════════════════════════════════════════════════

impl IDriftStructural for DriftStorageEngine {
    // ── coupling_metrics ──

    fn upsert_coupling_metrics(&self, row: &CouplingMetricsRow) -> Result<(), StorageError> {
        let sr = queries::structural::CouplingMetricsRow {
            module: row.module.clone(), ce: row.ce, ca: row.ca,
            instability: row.instability, abstractness: row.abstractness,
            distance: row.distance, zone: row.zone.clone(),
        };
        self.db.with_writer(|conn| queries::structural::upsert_coupling_metrics(conn, &sr))
    }

    fn get_coupling_metrics(&self, module: &str) -> Result<Option<CouplingMetricsRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::structural::get_coupling_metrics(conn, module)?;
            Ok(row.map(|r| CouplingMetricsRow {
                module: r.module, ce: r.ce, ca: r.ca,
                instability: r.instability, abstractness: r.abstractness,
                distance: r.distance, zone: r.zone,
            }))
        })
    }

    fn get_all_coupling_metrics(&self) -> Result<Vec<CouplingMetricsRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_all_coupling_metrics(conn)?;
            Ok(rows.into_iter().map(|r| CouplingMetricsRow {
                module: r.module, ce: r.ce, ca: r.ca,
                instability: r.instability, abstractness: r.abstractness,
                distance: r.distance, zone: r.zone,
            }).collect())
        })
    }

    fn get_coupling_metrics_by_zone(&self, zone: &str) -> Result<Vec<CouplingMetricsRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_coupling_metrics_by_zone(conn, zone)?;
            Ok(rows.into_iter().map(|r| CouplingMetricsRow {
                module: r.module, ce: r.ce, ca: r.ca,
                instability: r.instability, abstractness: r.abstractness,
                distance: r.distance, zone: r.zone,
            }).collect())
        })
    }

    // ── coupling_cycles ──

    fn insert_coupling_cycle(&self, members: &str, break_suggestions: &str) -> Result<(), StorageError> {
        self.db.with_writer(|conn| queries::structural::insert_coupling_cycle(conn, members, break_suggestions))
    }

    fn query_coupling_cycles(&self) -> Result<Vec<CouplingCycleRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::query_coupling_cycles(conn)?;
            Ok(rows.into_iter().map(|r| CouplingCycleRow {
                id: r.id, members: r.members, break_suggestions: r.break_suggestions, created_at: r.created_at,
            }).collect())
        })
    }

    // ── constraints ──

    fn upsert_constraint(&self, row: &ConstraintRow) -> Result<(), StorageError> {
        let sr = queries::structural::ConstraintRow {
            id: row.id.clone(), description: row.description.clone(),
            invariant_type: row.invariant_type.clone(), target: row.target.clone(),
            scope: row.scope.clone(), source: row.source.clone(), enabled: row.enabled,
        };
        self.db.with_writer(|conn| queries::structural::upsert_constraint(conn, &sr))
    }

    fn get_constraint(&self, id: &str) -> Result<Option<ConstraintRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::structural::get_constraint(conn, id)?;
            Ok(row.map(|r| ConstraintRow {
                id: r.id, description: r.description, invariant_type: r.invariant_type,
                target: r.target, scope: r.scope, source: r.source, enabled: r.enabled,
            }))
        })
    }

    fn get_enabled_constraints(&self) -> Result<Vec<ConstraintRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_enabled_constraints(conn)?;
            Ok(rows.into_iter().map(|r| ConstraintRow {
                id: r.id, description: r.description, invariant_type: r.invariant_type,
                target: r.target, scope: r.scope, source: r.source, enabled: r.enabled,
            }).collect())
        })
    }

    // ── constraint_verifications ──

    fn insert_constraint_verification(&self, constraint_id: &str, passed: bool, violations: &str) -> Result<(), StorageError> {
        self.db.with_writer(|conn| queries::structural::insert_constraint_verification(conn, constraint_id, passed, violations))
    }

    fn query_constraint_verifications(&self, constraint_id: &str) -> Result<Vec<ConstraintVerificationRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::query_constraint_verifications(conn, constraint_id)?;
            Ok(rows.into_iter().map(|r| ConstraintVerificationRow {
                id: r.id, constraint_id: r.constraint_id, passed: r.passed,
                violations: r.violations, verified_at: r.verified_at,
            }).collect())
        })
    }

    // ── contracts ──

    fn upsert_contract(&self, row: &ContractRow) -> Result<(), StorageError> {
        let sr = queries::structural::ContractRow {
            id: row.id.clone(), paradigm: row.paradigm.clone(),
            source_file: row.source_file.clone(), framework: row.framework.clone(),
            confidence: row.confidence, endpoints: row.endpoints.clone(),
        };
        self.db.with_writer(|conn| queries::structural::upsert_contract(conn, &sr))
    }

    fn get_contract(&self, id: &str) -> Result<Option<ContractRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::structural::get_contract(conn, id)?;
            Ok(row.map(|r| ContractRow {
                id: r.id, paradigm: r.paradigm, source_file: r.source_file,
                framework: r.framework, confidence: r.confidence, endpoints: r.endpoints,
            }))
        })
    }

    fn get_contracts_by_paradigm(&self, paradigm: &str) -> Result<Vec<ContractRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_contracts_by_paradigm(conn, paradigm)?;
            Ok(rows.into_iter().map(|r| ContractRow {
                id: r.id, paradigm: r.paradigm, source_file: r.source_file,
                framework: r.framework, confidence: r.confidence, endpoints: r.endpoints,
            }).collect())
        })
    }

    // ── contract_mismatches ──

    fn insert_contract_mismatch(&self, row: &ContractMismatchRow) -> Result<(), StorageError> {
        let sr = queries::structural::ContractMismatchRow {
            id: row.id, backend_endpoint: row.backend_endpoint.clone(),
            frontend_call: row.frontend_call.clone(), mismatch_type: row.mismatch_type.clone(),
            severity: row.severity.clone(), message: row.message.clone(), created_at: row.created_at,
        };
        self.db.with_writer(|conn| queries::structural::insert_contract_mismatch(conn, &sr))
    }

    fn query_contract_mismatches(&self) -> Result<Vec<ContractMismatchRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::query_contract_mismatches(conn)?;
            Ok(rows.into_iter().map(|r| ContractMismatchRow {
                id: r.id, backend_endpoint: r.backend_endpoint, frontend_call: r.frontend_call,
                mismatch_type: r.mismatch_type, severity: r.severity, message: r.message, created_at: r.created_at,
            }).collect())
        })
    }

    fn query_contract_mismatches_by_type(&self, mismatch_type: &str) -> Result<Vec<ContractMismatchRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::query_contract_mismatches_by_type(conn, mismatch_type)?;
            Ok(rows.into_iter().map(|r| ContractMismatchRow {
                id: r.id, backend_endpoint: r.backend_endpoint, frontend_call: r.frontend_call,
                mismatch_type: r.mismatch_type, severity: r.severity, message: r.message, created_at: r.created_at,
            }).collect())
        })
    }

    // ── secrets ──

    fn insert_secret(&self, row: &SecretRow) -> Result<i64, StorageError> {
        let sr = queries::structural::SecretRow {
            id: row.id, pattern_name: row.pattern_name.clone(),
            redacted_value: row.redacted_value.clone(), file: row.file.clone(),
            line: row.line, severity: row.severity.clone(), entropy: row.entropy,
            confidence: row.confidence, cwe_ids: row.cwe_ids.clone(),
        };
        self.db.with_writer(|conn| queries::structural::insert_secret(conn, &sr))
    }

    fn get_secrets_by_file(&self, file: &str) -> Result<Vec<SecretRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_secrets_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| SecretRow {
                id: r.id, pattern_name: r.pattern_name, redacted_value: r.redacted_value,
                file: r.file, line: r.line, severity: r.severity, entropy: r.entropy,
                confidence: r.confidence, cwe_ids: r.cwe_ids,
            }).collect())
        })
    }

    fn get_secrets_by_severity(&self, severity: &str) -> Result<Vec<SecretRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_secrets_by_severity(conn, severity)?;
            Ok(rows.into_iter().map(|r| SecretRow {
                id: r.id, pattern_name: r.pattern_name, redacted_value: r.redacted_value,
                file: r.file, line: r.line, severity: r.severity, entropy: r.entropy,
                confidence: r.confidence, cwe_ids: r.cwe_ids,
            }).collect())
        })
    }

    // ── wrappers ──

    fn insert_wrapper(&self, row: &WrapperRow) -> Result<i64, StorageError> {
        let sr = queries::structural::WrapperRow {
            id: row.id, name: row.name.clone(), file: row.file.clone(),
            line: row.line, category: row.category.clone(),
            wrapped_primitives: row.wrapped_primitives.clone(), framework: row.framework.clone(),
            confidence: row.confidence, is_multi_primitive: row.is_multi_primitive,
            is_exported: row.is_exported, usage_count: row.usage_count,
        };
        self.db.with_writer(|conn| queries::structural::insert_wrapper(conn, &sr))
    }

    fn get_wrappers_by_file(&self, file: &str) -> Result<Vec<WrapperRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_wrappers_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| WrapperRow {
                id: r.id, name: r.name, file: r.file, line: r.line, category: r.category,
                wrapped_primitives: r.wrapped_primitives, framework: r.framework,
                confidence: r.confidence, is_multi_primitive: r.is_multi_primitive,
                is_exported: r.is_exported, usage_count: r.usage_count,
            }).collect())
        })
    }

    fn get_wrappers_by_category(&self, category: &str) -> Result<Vec<WrapperRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_wrappers_by_category(conn, category)?;
            Ok(rows.into_iter().map(|r| WrapperRow {
                id: r.id, name: r.name, file: r.file, line: r.line, category: r.category,
                wrapped_primitives: r.wrapped_primitives, framework: r.framework,
                confidence: r.confidence, is_multi_primitive: r.is_multi_primitive,
                is_exported: r.is_exported, usage_count: r.usage_count,
            }).collect())
        })
    }

    // ── dna_genes ──

    fn upsert_dna_gene(&self, row: &DnaGeneRow) -> Result<(), StorageError> {
        let sr = queries::structural::DnaGeneRow {
            gene_id: row.gene_id.clone(), name: row.name.clone(),
            description: row.description.clone(), dominant_allele: row.dominant_allele.clone(),
            alleles: row.alleles.clone(), confidence: row.confidence,
            consistency: row.consistency, exemplars: row.exemplars.clone(),
        };
        self.db.with_writer(|conn| queries::structural::upsert_dna_gene(conn, &sr))
    }

    fn get_dna_gene(&self, gene_id: &str) -> Result<Option<DnaGeneRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::structural::get_dna_gene(conn, gene_id)?;
            Ok(row.map(|r| DnaGeneRow {
                gene_id: r.gene_id, name: r.name, description: r.description,
                dominant_allele: r.dominant_allele, alleles: r.alleles,
                confidence: r.confidence, consistency: r.consistency, exemplars: r.exemplars,
            }))
        })
    }

    fn get_all_dna_genes(&self) -> Result<Vec<DnaGeneRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_all_dna_genes(conn)?;
            Ok(rows.into_iter().map(|r| DnaGeneRow {
                gene_id: r.gene_id, name: r.name, description: r.description,
                dominant_allele: r.dominant_allele, alleles: r.alleles,
                confidence: r.confidence, consistency: r.consistency, exemplars: r.exemplars,
            }).collect())
        })
    }

    // ── dna_mutations ──

    fn upsert_dna_mutation(&self, row: &DnaMutationRow) -> Result<(), StorageError> {
        let sr = queries::structural::DnaMutationRow {
            id: row.id.clone(), file: row.file.clone(), line: row.line,
            gene_id: row.gene_id.clone(), expected: row.expected.clone(),
            actual: row.actual.clone(), impact: row.impact.clone(),
            code: row.code.clone(), suggestion: row.suggestion.clone(),
            detected_at: row.detected_at, resolved: row.resolved,
            resolved_at: row.resolved_at,
        };
        self.db.with_writer(|conn| queries::structural::upsert_dna_mutation(conn, &sr))
    }

    fn get_dna_mutations_by_gene(&self, gene_id: &str) -> Result<Vec<DnaMutationRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_dna_mutations_by_gene(conn, gene_id)?;
            Ok(rows.into_iter().map(|r| DnaMutationRow {
                id: r.id, file: r.file, line: r.line, gene_id: r.gene_id,
                expected: r.expected, actual: r.actual, impact: r.impact,
                code: r.code, suggestion: r.suggestion, detected_at: r.detected_at,
                resolved: r.resolved, resolved_at: r.resolved_at,
            }).collect())
        })
    }

    fn get_unresolved_mutations(&self) -> Result<Vec<DnaMutationRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_unresolved_mutations(conn)?;
            Ok(rows.into_iter().map(|r| DnaMutationRow {
                id: r.id, file: r.file, line: r.line, gene_id: r.gene_id,
                expected: r.expected, actual: r.actual, impact: r.impact,
                code: r.code, suggestion: r.suggestion, detected_at: r.detected_at,
                resolved: r.resolved, resolved_at: r.resolved_at,
            }).collect())
        })
    }

    // ── crypto_findings ──

    fn insert_crypto_finding(&self, row: &CryptoFindingRow) -> Result<i64, StorageError> {
        let sr = queries::structural::CryptoFindingRow {
            id: row.id, file: row.file.clone(), line: row.line,
            category: row.category.clone(), description: row.description.clone(),
            code: row.code.clone(), confidence: row.confidence, cwe_id: row.cwe_id,
            owasp: row.owasp.clone(), remediation: row.remediation.clone(),
            language: row.language.clone(),
        };
        self.db.with_writer(|conn| queries::structural::insert_crypto_finding(conn, &sr))
    }

    fn get_crypto_findings_by_file(&self, file: &str) -> Result<Vec<CryptoFindingRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_crypto_findings_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| CryptoFindingRow {
                id: r.id, file: r.file, line: r.line, category: r.category,
                description: r.description, code: r.code, confidence: r.confidence,
                cwe_id: r.cwe_id, owasp: r.owasp, remediation: r.remediation, language: r.language,
            }).collect())
        })
    }

    fn get_crypto_findings_by_category(&self, category: &str) -> Result<Vec<CryptoFindingRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_crypto_findings_by_category(conn, category)?;
            Ok(rows.into_iter().map(|r| CryptoFindingRow {
                id: r.id, file: r.file, line: r.line, category: r.category,
                description: r.description, code: r.code, confidence: r.confidence,
                cwe_id: r.cwe_id, owasp: r.owasp, remediation: r.remediation, language: r.language,
            }).collect())
        })
    }

    // ── owasp_findings ──

    fn upsert_owasp_finding(&self, row: &OwaspFindingRow) -> Result<(), StorageError> {
        let sr = queries::structural::OwaspFindingRow {
            id: row.id.clone(), detector: row.detector.clone(), file: row.file.clone(),
            line: row.line, description: row.description.clone(), severity: row.severity,
            cwes: row.cwes.clone(), owasp_categories: row.owasp_categories.clone(),
            confidence: row.confidence, remediation: row.remediation.clone(),
        };
        self.db.with_writer(|conn| queries::structural::upsert_owasp_finding(conn, &sr))
    }

    fn get_owasp_findings_by_file(&self, file: &str) -> Result<Vec<OwaspFindingRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_owasp_findings_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| OwaspFindingRow {
                id: r.id, detector: r.detector, file: r.file, line: r.line,
                description: r.description, severity: r.severity, cwes: r.cwes,
                owasp_categories: r.owasp_categories, confidence: r.confidence,
                remediation: r.remediation,
            }).collect())
        })
    }

    fn get_owasp_findings_by_detector(&self, detector: &str) -> Result<Vec<OwaspFindingRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_owasp_findings_by_detector(conn, detector)?;
            Ok(rows.into_iter().map(|r| OwaspFindingRow {
                id: r.id, detector: r.detector, file: r.file, line: r.line,
                description: r.description, severity: r.severity, cwes: r.cwes,
                owasp_categories: r.owasp_categories, confidence: r.confidence,
                remediation: r.remediation,
            }).collect())
        })
    }

    // ── decomposition_decisions ──

    fn insert_decomposition_decision(&self, row: &DecompositionDecisionRow) -> Result<i64, StorageError> {
        let sr = queries::structural::DecompositionDecisionRow {
            id: row.id, dna_profile_hash: row.dna_profile_hash.clone(),
            adjustment: row.adjustment.clone(), confidence: row.confidence,
            dna_similarity: row.dna_similarity, narrative: row.narrative.clone(),
            source_dna_hash: row.source_dna_hash.clone(), applied_weight: row.applied_weight,
        };
        self.db.with_writer(|conn| queries::structural::insert_decomposition_decision(conn, &sr))
    }

    fn get_decomposition_decisions(&self, dna_profile_hash: &str) -> Result<Vec<DecompositionDecisionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::structural::get_decomposition_decisions(conn, dna_profile_hash)?;
            Ok(rows.into_iter().map(|r| DecompositionDecisionRow {
                id: r.id, dna_profile_hash: r.dna_profile_hash, adjustment: r.adjustment,
                confidence: r.confidence, dna_similarity: r.dna_similarity,
                narrative: r.narrative, source_dna_hash: r.source_dna_hash,
                applied_weight: r.applied_weight,
            }).collect())
        })
    }

    // ── constants ──

    fn insert_constant(&self, row: &ConstantRow) -> Result<(), StorageError> {
        let sr = queries::constants::ConstantRow {
            id: row.id, name: row.name.clone(), value: row.value.clone(),
            file: row.file.clone(), line: row.line, is_used: row.is_used,
            language: row.language.clone(), is_named: row.is_named, created_at: row.created_at,
        };
        self.db.with_writer(|conn| queries::constants::insert(conn, &sr))
    }

    fn insert_constants_batch(&self, rows: &[ConstantRow]) -> Result<(), StorageError> {
        let srs: Vec<queries::constants::ConstantRow> = rows.iter().map(|r| queries::constants::ConstantRow {
            id: r.id, name: r.name.clone(), value: r.value.clone(),
            file: r.file.clone(), line: r.line, is_used: r.is_used,
            language: r.language.clone(), is_named: r.is_named, created_at: r.created_at,
        }).collect();
        self.db.with_writer(|conn| queries::constants::insert_batch(conn, &srs))
    }

    fn query_constants_by_file(&self, file: &str) -> Result<Vec<ConstantRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::constants::query_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| ConstantRow {
                id: r.id, name: r.name, value: r.value, file: r.file,
                line: r.line, is_used: r.is_used, language: r.language,
                is_named: r.is_named, created_at: r.created_at,
            }).collect())
        })
    }

    fn query_unused_constants(&self) -> Result<Vec<ConstantRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::constants::query_unused(conn)?;
            Ok(rows.into_iter().map(|r| ConstantRow {
                id: r.id, name: r.name, value: r.value, file: r.file,
                line: r.line, is_used: r.is_used, language: r.language,
                is_named: r.is_named, created_at: r.created_at,
            }).collect())
        })
    }

    fn query_magic_numbers(&self) -> Result<Vec<ConstantRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::constants::query_magic_numbers(conn)?;
            Ok(rows.into_iter().map(|r| ConstantRow {
                id: r.id, name: r.name, value: r.value, file: r.file,
                line: r.line, is_used: r.is_used, language: r.language,
                is_named: r.is_named, created_at: r.created_at,
            }).collect())
        })
    }

    fn delete_constants_by_file(&self, file: &str) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| queries::constants::delete_by_file(conn, file))
    }

    fn count_constants(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::constants::count)
    }

    // ── env_variables ──

    fn insert_env_variable(&self, row: &EnvVariableRow) -> Result<(), StorageError> {
        let sr = queries::env_variables::EnvVariableRow {
            id: row.id.unwrap_or(0), name: row.name.clone(), file: row.file.clone(),
            line: row.line, access_method: row.access_method.clone(),
            has_default: row.has_default, defined_in_env: row.defined_in_env,
            framework_prefix: row.framework_prefix.clone(), created_at: row.created_at.unwrap_or(0),
        };
        self.db.with_writer(|conn| queries::env_variables::insert(conn, &sr))
    }

    fn insert_env_variables_batch(&self, rows: &[EnvVariableRow]) -> Result<(), StorageError> {
        let srs: Vec<queries::env_variables::EnvVariableRow> = rows.iter().map(|r| queries::env_variables::EnvVariableRow {
            id: r.id.unwrap_or(0), name: r.name.clone(), file: r.file.clone(),
            line: r.line, access_method: r.access_method.clone(),
            has_default: r.has_default, defined_in_env: r.defined_in_env,
            framework_prefix: r.framework_prefix.clone(), created_at: r.created_at.unwrap_or(0),
        }).collect();
        self.db.with_writer(|conn| queries::env_variables::insert_batch(conn, &srs))
    }

    fn query_env_variables_by_name(&self, name: &str) -> Result<Vec<EnvVariableRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::env_variables::query_by_name(conn, name)?;
            Ok(rows.into_iter().map(|r| EnvVariableRow {
                id: Some(r.id), name: r.name, file: r.file, line: r.line,
                access_method: r.access_method, has_default: r.has_default,
                defined_in_env: r.defined_in_env, framework_prefix: r.framework_prefix,
                created_at: Some(r.created_at),
            }).collect())
        })
    }

    fn query_env_variables_by_file(&self, file: &str) -> Result<Vec<EnvVariableRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::env_variables::query_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| EnvVariableRow {
                id: Some(r.id), name: r.name, file: r.file, line: r.line,
                access_method: r.access_method, has_default: r.has_default,
                defined_in_env: r.defined_in_env, framework_prefix: r.framework_prefix,
                created_at: Some(r.created_at),
            }).collect())
        })
    }

    fn query_missing_env_variables(&self) -> Result<Vec<EnvVariableRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::env_variables::query_missing(conn)?;
            Ok(rows.into_iter().map(|r| EnvVariableRow {
                id: Some(r.id), name: r.name, file: r.file, line: r.line,
                access_method: r.access_method, has_default: r.has_default,
                defined_in_env: r.defined_in_env, framework_prefix: r.framework_prefix,
                created_at: Some(r.created_at),
            }).collect())
        })
    }

    fn delete_env_variables_by_file(&self, file: &str) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| queries::env_variables::delete_by_file(conn, file))
    }

    fn count_env_variables(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::env_variables::count)
    }

    // ── data_access ──

    fn insert_data_access(&self, row: &DataAccessRow) -> Result<(), StorageError> {
        let sr = queries::data_access::DataAccessRow {
            function_id: row.function_id, table_name: row.table_name.clone(),
            operation: row.operation.clone(), framework: row.framework.clone(),
            line: row.line, confidence: row.confidence,
        };
        self.db.with_writer(|conn| queries::data_access::insert(conn, &sr))
    }

    fn insert_data_access_batch(&self, rows: &[DataAccessRow]) -> Result<(), StorageError> {
        let srs: Vec<queries::data_access::DataAccessRow> = rows.iter().map(|r| queries::data_access::DataAccessRow {
            function_id: r.function_id, table_name: r.table_name.clone(),
            operation: r.operation.clone(), framework: r.framework.clone(),
            line: r.line, confidence: r.confidence,
        }).collect();
        self.db.with_writer(|conn| queries::data_access::insert_batch(conn, &srs))
    }

    fn query_data_access_by_function(&self, function_id: i64) -> Result<Vec<DataAccessRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::data_access::query_by_function(conn, function_id)?;
            Ok(rows.into_iter().map(|r| DataAccessRow {
                id: None, function_id: r.function_id, table_name: r.table_name,
                operation: r.operation, framework: r.framework, line: r.line,
                confidence: r.confidence,
            }).collect())
        })
    }

    fn query_data_access_by_table(&self, table_name: &str) -> Result<Vec<DataAccessRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::data_access::query_by_table(conn, table_name)?;
            Ok(rows.into_iter().map(|r| DataAccessRow {
                id: None, function_id: r.function_id, table_name: r.table_name,
                operation: r.operation, framework: r.framework, line: r.line,
                confidence: r.confidence,
            }).collect())
        })
    }

    fn delete_data_access_by_function(&self, function_id: i64) -> Result<usize, StorageError> {
        self.db.with_writer(|conn| queries::data_access::delete_by_function(conn, function_id))
    }

    fn count_data_access(&self) -> Result<i64, StorageError> {
        self.db.with_reader(queries::data_access::count)
    }

    // ── reachability_cache ──

    fn upsert_reachability(&self, row: &ReachabilityCacheRow) -> Result<(), StorageError> {
        let sr = queries::graph::ReachabilityCacheRow {
            source_node: row.source_node.clone(), direction: row.direction.clone(),
            reachable_set: row.reachable_set.clone(), sensitivity: row.sensitivity.clone(),
        };
        self.db.with_writer(|conn| queries::graph::upsert_reachability(conn, &sr))
    }

    fn get_reachability(&self, source_node: &str, direction: &str) -> Result<Option<ReachabilityCacheRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::graph::get_reachability(conn, source_node, direction)?;
            Ok(row.map(|r| ReachabilityCacheRow {
                source_node: r.source_node, direction: r.direction,
                reachable_set: r.reachable_set, sensitivity: r.sensitivity,
            }))
        })
    }

    fn clear_reachability_cache(&self) -> Result<(), StorageError> {
        self.db.with_writer(queries::graph::clear_reachability_cache)
    }

    // ── taint_flows ──

    fn insert_taint_flow(&self, row: &TaintFlowRow) -> Result<i64, StorageError> {
        let sr = queries::graph::TaintFlowRow {
            id: row.id, source_file: row.source_file.clone(), source_line: row.source_line,
            source_type: row.source_type.clone(), sink_file: row.sink_file.clone(),
            sink_line: row.sink_line, sink_type: row.sink_type.clone(),
            cwe_id: row.cwe_id, is_sanitized: row.is_sanitized,
            path: row.path.clone(), confidence: row.confidence,
        };
        self.db.with_writer(|conn| queries::graph::insert_taint_flow(conn, &sr))
    }

    fn get_taint_flows_by_file(&self, file: &str) -> Result<Vec<TaintFlowRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::graph::get_taint_flows_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| TaintFlowRow {
                id: r.id, source_file: r.source_file, source_line: r.source_line,
                source_type: r.source_type, sink_file: r.sink_file,
                sink_line: r.sink_line, sink_type: r.sink_type,
                cwe_id: r.cwe_id, is_sanitized: r.is_sanitized,
                path: r.path, confidence: r.confidence,
            }).collect())
        })
    }

    fn get_taint_flows_by_cwe(&self, cwe_id: u32) -> Result<Vec<TaintFlowRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::graph::get_taint_flows_by_cwe(conn, cwe_id)?;
            Ok(rows.into_iter().map(|r| TaintFlowRow {
                id: r.id, source_file: r.source_file, source_line: r.source_line,
                source_type: r.source_type, sink_file: r.sink_file,
                sink_line: r.sink_line, sink_type: r.sink_type,
                cwe_id: r.cwe_id, is_sanitized: r.is_sanitized,
                path: r.path, confidence: r.confidence,
            }).collect())
        })
    }

    // ── error_gaps ──

    fn insert_error_gap(&self, row: &ErrorGapRow) -> Result<i64, StorageError> {
        let sr = queries::graph::ErrorGapRow {
            id: row.id, file: row.file.clone(), function_id: row.function_id.clone(),
            gap_type: row.gap_type.clone(), error_type: row.error_type.clone(),
            propagation_chain: row.propagation_chain.clone(), framework: row.framework.clone(),
            cwe_id: row.cwe_id, severity: row.severity.clone(),
        };
        self.db.with_writer(|conn| queries::graph::insert_error_gap(conn, &sr))
    }

    fn get_error_gaps_by_file(&self, file: &str) -> Result<Vec<ErrorGapRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::graph::get_error_gaps_by_file(conn, file)?;
            Ok(rows.into_iter().map(|r| ErrorGapRow {
                id: r.id, file: r.file, function_id: r.function_id,
                gap_type: r.gap_type, error_type: r.error_type,
                propagation_chain: r.propagation_chain, framework: r.framework,
                cwe_id: r.cwe_id, severity: r.severity,
            }).collect())
        })
    }

    // ── impact_scores ──

    fn upsert_impact_score(&self, row: &ImpactScoreRow) -> Result<(), StorageError> {
        let sr = queries::graph::ImpactScoreRow {
            function_id: row.function_id.clone(), blast_radius: row.blast_radius,
            risk_score: row.risk_score, is_dead_code: row.is_dead_code,
            dead_code_reason: row.dead_code_reason.clone(),
            exclusion_category: row.exclusion_category.clone(),
        };
        self.db.with_writer(|conn| queries::graph::upsert_impact_score(conn, &sr))
    }

    fn get_impact_score(&self, function_id: &str) -> Result<Option<ImpactScoreRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::graph::get_impact_score(conn, function_id)?;
            Ok(row.map(|r| ImpactScoreRow {
                function_id: r.function_id, blast_radius: r.blast_radius,
                risk_score: r.risk_score, is_dead_code: r.is_dead_code,
                dead_code_reason: r.dead_code_reason,
                exclusion_category: r.exclusion_category,
            }))
        })
    }

    // ── test_coverage ──

    fn insert_test_coverage(&self, row: &TestCoverageRow) -> Result<(), StorageError> {
        let sr = queries::graph::TestCoverageRow {
            test_function_id: row.test_function_id.clone(),
            source_function_id: row.source_function_id.clone(),
            coverage_type: row.coverage_type.clone(),
        };
        self.db.with_writer(|conn| queries::graph::insert_test_coverage(conn, &sr))
    }

    fn get_test_coverage_for_source(&self, source_function_id: &str) -> Result<Vec<TestCoverageRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::graph::get_test_coverage_for_source(conn, source_function_id)?;
            Ok(rows.into_iter().map(|r| TestCoverageRow {
                test_function_id: r.test_function_id,
                source_function_id: r.source_function_id,
                coverage_type: r.coverage_type,
            }).collect())
        })
    }

    // ── test_quality ──

    fn upsert_test_quality(&self, row: &TestQualityRow) -> Result<(), StorageError> {
        let sr = queries::graph::TestQualityRow {
            function_id: row.function_id.clone(),
            coverage_breadth: row.coverage_breadth, coverage_depth: row.coverage_depth,
            assertion_density: row.assertion_density, mock_ratio: row.mock_ratio,
            isolation: row.isolation, freshness: row.freshness,
            stability: row.stability, overall_score: row.overall_score,
            smells: row.smells.clone(),
        };
        self.db.with_writer(|conn| queries::graph::upsert_test_quality(conn, &sr))
    }

    fn get_test_quality(&self, function_id: &str) -> Result<Option<TestQualityRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::graph::get_test_quality(conn, function_id)?;
            Ok(row.map(|r| TestQualityRow {
                function_id: r.function_id,
                coverage_breadth: r.coverage_breadth, coverage_depth: r.coverage_depth,
                assertion_density: r.assertion_density, mock_ratio: r.mock_ratio,
                isolation: r.isolation, freshness: r.freshness,
                stability: r.stability, overall_score: r.overall_score,
                smells: r.smells,
            }))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftEnforcement implementation
// ═══════════════════════════════════════════════════════════════════════════════

// ── Enforcement type conversion helpers ──

fn to_storage_violation(v: &ViolationRow) -> queries::enforcement::ViolationRow {
    queries::enforcement::ViolationRow {
        id: v.id.clone(), file: v.file.clone(), line: v.line, column: v.column,
        end_line: v.end_line, end_column: v.end_column, severity: v.severity.clone(),
        pattern_id: v.pattern_id.clone(), rule_id: v.rule_id.clone(), message: v.message.clone(),
        quick_fix_strategy: v.quick_fix_strategy.clone(), quick_fix_description: v.quick_fix_description.clone(),
        cwe_id: v.cwe_id, owasp_category: v.owasp_category.clone(),
        suppressed: v.suppressed, is_new: v.is_new,
    }
}

fn from_storage_violation(r: queries::enforcement::ViolationRow) -> ViolationRow {
    ViolationRow {
        id: r.id, file: r.file, line: r.line, column: r.column,
        end_line: r.end_line, end_column: r.end_column, severity: r.severity,
        pattern_id: r.pattern_id, rule_id: r.rule_id, message: r.message,
        quick_fix_strategy: r.quick_fix_strategy, quick_fix_description: r.quick_fix_description,
        cwe_id: r.cwe_id, owasp_category: r.owasp_category,
        suppressed: r.suppressed, is_new: r.is_new,
    }
}

fn to_storage_gate(g: &GateResultRow) -> queries::enforcement::GateResultRow {
    queries::enforcement::GateResultRow {
        gate_id: g.gate_id.clone(), status: g.status.clone(), passed: g.passed,
        score: g.score, summary: g.summary.clone(), violation_count: g.violation_count,
        warning_count: g.warning_count, execution_time_ms: g.execution_time_ms,
        details: g.details.clone(), error: g.error.clone(), run_at: g.run_at,
    }
}

fn from_storage_gate(r: queries::enforcement::GateResultRow) -> GateResultRow {
    GateResultRow {
        gate_id: r.gate_id, status: r.status, passed: r.passed,
        score: r.score, summary: r.summary, violation_count: r.violation_count,
        warning_count: r.warning_count, execution_time_ms: r.execution_time_ms,
        details: r.details, error: r.error, run_at: r.run_at,
    }
}

fn to_storage_audit(s: &AuditSnapshotRow) -> queries::enforcement::AuditSnapshotRow {
    queries::enforcement::AuditSnapshotRow {
        health_score: s.health_score, avg_confidence: s.avg_confidence,
        approval_ratio: s.approval_ratio, compliance_rate: s.compliance_rate,
        cross_validation_rate: s.cross_validation_rate, duplicate_free_rate: s.duplicate_free_rate,
        pattern_count: s.pattern_count, category_scores: s.category_scores.clone(),
        created_at: s.created_at,
    }
}

fn from_storage_audit(r: queries::enforcement::AuditSnapshotRow) -> AuditSnapshotRow {
    AuditSnapshotRow {
        health_score: r.health_score, avg_confidence: r.avg_confidence,
        approval_ratio: r.approval_ratio, compliance_rate: r.compliance_rate,
        cross_validation_rate: r.cross_validation_rate, duplicate_free_rate: r.duplicate_free_rate,
        pattern_count: r.pattern_count, category_scores: r.category_scores,
        created_at: r.created_at,
    }
}

fn from_storage_health(r: queries::enforcement::HealthTrendRow) -> HealthTrendRow {
    HealthTrendRow { metric_name: r.metric_name, metric_value: r.metric_value, recorded_at: r.recorded_at }
}

fn to_storage_feedback(f: &FeedbackRow) -> queries::enforcement::FeedbackRow {
    queries::enforcement::FeedbackRow {
        violation_id: f.violation_id.clone(), pattern_id: f.pattern_id.clone(),
        detector_id: f.detector_id.clone(), action: f.action.clone(),
        dismissal_reason: f.dismissal_reason.clone(), reason: f.reason.clone(),
        author: f.author.clone(), created_at: f.created_at,
    }
}

fn from_storage_feedback(r: queries::enforcement::FeedbackRow) -> FeedbackRow {
    FeedbackRow {
        violation_id: r.violation_id, pattern_id: r.pattern_id,
        detector_id: r.detector_id, action: r.action,
        dismissal_reason: r.dismissal_reason, reason: r.reason,
        author: r.author, created_at: r.created_at,
    }
}

fn to_storage_policy(r: &PolicyResultRow) -> queries::enforcement::PolicyResultRow {
    queries::enforcement::PolicyResultRow {
        id: r.id, policy_name: r.policy_name.clone(),
        aggregation_mode: r.aggregation_mode.clone(), overall_passed: r.overall_passed,
        overall_score: r.overall_score, gate_count: r.gate_count,
        gates_passed: r.gates_passed, gates_failed: r.gates_failed,
        details: r.details.clone(), run_at: r.run_at,
    }
}

fn from_storage_policy(r: queries::enforcement::PolicyResultRow) -> PolicyResultRow {
    PolicyResultRow {
        id: r.id, policy_name: r.policy_name,
        aggregation_mode: r.aggregation_mode, overall_passed: r.overall_passed,
        overall_score: r.overall_score, gate_count: r.gate_count,
        gates_passed: r.gates_passed, gates_failed: r.gates_failed,
        details: r.details, run_at: r.run_at,
    }
}

fn to_storage_degradation(r: &DegradationAlertRow) -> queries::enforcement::DegradationAlertRow {
    queries::enforcement::DegradationAlertRow {
        id: r.id, alert_type: r.alert_type.clone(), severity: r.severity.clone(),
        message: r.message.clone(), current_value: r.current_value,
        previous_value: r.previous_value, delta: r.delta, created_at: r.created_at,
    }
}

fn from_storage_degradation(r: queries::enforcement::DegradationAlertRow) -> DegradationAlertRow {
    DegradationAlertRow {
        id: r.id, alert_type: r.alert_type, severity: r.severity,
        message: r.message, current_value: r.current_value,
        previous_value: r.previous_value, delta: r.delta, created_at: r.created_at,
    }
}

impl IDriftEnforcement for DriftStorageEngine {
    fn insert_violation(&self, v: &ViolationRow) -> Result<(), StorageError> {
        let sv = to_storage_violation(v);
        self.db.with_writer(|conn| queries::enforcement::insert_violation(conn, &sv))
    }

    fn query_violations_by_file(&self, file: &str) -> Result<Vec<ViolationRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_violations_by_file(conn, file)?;
            Ok(rows.into_iter().map(from_storage_violation).collect())
        })
    }

    fn query_all_violations(&self) -> Result<Vec<ViolationRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_all_violations(conn)?;
            Ok(rows.into_iter().map(from_storage_violation).collect())
        })
    }

    fn insert_gate_result(&self, g: &GateResultRow) -> Result<(), StorageError> {
        let sg = to_storage_gate(g);
        self.db.with_writer(|conn| queries::enforcement::insert_gate_result(conn, &sg))
    }

    fn query_gate_results(&self) -> Result<Vec<GateResultRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_gate_results(conn)?;
            Ok(rows.into_iter().map(from_storage_gate).collect())
        })
    }

    fn insert_audit_snapshot(&self, s: &AuditSnapshotRow) -> Result<(), StorageError> {
        let ss = to_storage_audit(s);
        self.db.with_writer(|conn| queries::enforcement::insert_audit_snapshot(conn, &ss))
    }

    fn query_audit_snapshots(&self, limit: u32) -> Result<Vec<AuditSnapshotRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_audit_snapshots(conn, limit)?;
            Ok(rows.into_iter().map(from_storage_audit).collect())
        })
    }

    fn insert_health_trend(&self, metric_name: &str, metric_value: f64) -> Result<(), StorageError> {
        self.db.with_writer(|conn| queries::enforcement::insert_health_trend(conn, metric_name, metric_value))
    }

    fn query_health_trends(&self, metric_name: &str, limit: u32) -> Result<Vec<HealthTrendRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_health_trends(conn, metric_name, limit)?;
            Ok(rows.into_iter().map(from_storage_health).collect())
        })
    }

    fn insert_feedback(&self, f: &FeedbackRow) -> Result<(), StorageError> {
        let sf = to_storage_feedback(f);
        self.db.with_writer(|conn| queries::enforcement::insert_feedback(conn, &sf))
    }

    fn query_feedback_by_detector(&self, detector_id: &str) -> Result<Vec<FeedbackRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_feedback_by_detector(conn, detector_id)?;
            Ok(rows.into_iter().map(from_storage_feedback).collect())
        })
    }

    fn query_feedback_by_pattern(&self, pattern_id: &str) -> Result<Vec<FeedbackRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_feedback_by_pattern(conn, pattern_id)?;
            Ok(rows.into_iter().map(from_storage_feedback).collect())
        })
    }

    fn query_feedback_adjustments(&self, pattern_id: &str) -> Result<Vec<(f64, f64)>, StorageError> {
        self.db.with_reader(|conn| queries::enforcement::query_feedback_adjustments(conn, pattern_id))
    }

    fn get_violation_pattern_id(&self, violation_id: &str) -> Result<Option<String>, StorageError> {
        self.db.with_reader(|conn| queries::enforcement::get_violation_pattern_id(conn, violation_id))
    }

    fn query_feedback_stats(&self) -> Result<FeedbackStats, StorageError> {
        self.db.with_reader(|conn| {
            let ss = queries::enforcement::query_feedback_stats(conn)?;
            Ok(FeedbackStats {
                total_count: ss.total_count, fix_count: ss.fix_count,
                dismiss_count: ss.dismiss_count, suppress_count: ss.suppress_count,
                escalate_count: ss.escalate_count,
            })
        })
    }

    fn count_needs_review(&self) -> Result<u32, StorageError> {
        self.db.with_reader(queries::enforcement::count_needs_review)
    }

    fn insert_policy_result(&self, row: &PolicyResultRow) -> Result<(), StorageError> {
        let sr = to_storage_policy(row);
        self.db.with_writer(|conn| queries::enforcement::insert_policy_result(conn, &sr))
    }

    fn query_recent_policy_results(&self, limit: usize) -> Result<Vec<PolicyResultRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_recent_policy_results(conn, limit)?;
            Ok(rows.into_iter().map(from_storage_policy).collect())
        })
    }

    fn insert_degradation_alert(&self, row: &DegradationAlertRow) -> Result<(), StorageError> {
        let sr = to_storage_degradation(row);
        self.db.with_writer(|conn| queries::enforcement::insert_degradation_alert(conn, &sr))
    }

    fn query_recent_degradation_alerts(&self, limit: usize) -> Result<Vec<DegradationAlertRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_recent_degradation_alerts(conn, limit)?;
            Ok(rows.into_iter().map(from_storage_degradation).collect())
        })
    }

    fn query_degradation_alerts_by_type(&self, alert_type: &str) -> Result<Vec<DegradationAlertRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::enforcement::query_degradation_alerts_by_type(conn, alert_type)?;
            Ok(rows.into_iter().map(from_storage_degradation).collect())
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftAdvanced implementation
// ═══════════════════════════════════════════════════════════════════════════════

impl IDriftAdvanced for DriftStorageEngine {
    fn insert_simulation(
        &self,
        task_category: &str,
        task_description: &str,
        approach_count: i32,
        recommended_approach: Option<&str>,
        p10_effort: f64,
        p50_effort: f64,
        p90_effort: f64,
    ) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::insert_simulation(
                conn, task_category, task_description, approach_count,
                recommended_approach, p10_effort, p50_effort, p90_effort,
            )
        })
    }

    fn get_simulations(&self, limit: usize) -> Result<Vec<SimulationRow>, StorageError> {
        self.db.with_reader(|conn| {
            let rows = queries::advanced::get_simulations(conn, limit)?;
            Ok(rows.into_iter().map(|r| SimulationRow {
                id: r.id, task_category: r.task_category, task_description: r.task_description,
                approach_count: r.approach_count, recommended_approach: r.recommended_approach,
                p10_effort: r.p10_effort, p50_effort: r.p50_effort, p90_effort: r.p90_effort,
                created_at: r.created_at,
            }).collect())
        })
    }

    fn insert_decision(
        &self,
        category: &str,
        description: &str,
        commit_sha: Option<&str>,
        confidence: f64,
        related_patterns: Option<&str>,
        author: Option<&str>,
        files_changed: Option<&str>,
    ) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::insert_decision(
                conn, category, description, commit_sha, confidence,
                related_patterns, author, files_changed,
            )
        })
    }

    fn insert_context_cache(
        &self,
        session_id: &str,
        intent: &str,
        depth: &str,
        token_count: i32,
        content_hash: &str,
    ) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::insert_context_cache(conn, session_id, intent, depth, token_count, content_hash)
        })
    }

    fn create_migration_project(
        &self,
        name: &str,
        source_language: &str,
        target_language: &str,
        source_framework: Option<&str>,
        target_framework: Option<&str>,
    ) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::create_migration_project(conn, name, source_language, target_language, source_framework, target_framework)
        })
    }

    fn create_migration_module(
        &self,
        project_id: i64,
        module_name: &str,
    ) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::create_migration_module(conn, project_id, module_name)
        })
    }

    fn update_module_status(
        &self,
        module_id: i64,
        status: &str,
    ) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::update_module_status(conn, module_id, status)
        })
    }

    fn insert_migration_correction(
        &self,
        module_id: i64,
        section: &str,
        original_text: &str,
        corrected_text: &str,
        reason: Option<&str>,
    ) -> Result<i64, StorageError> {
        self.db.with_writer(|conn| {
            queries::advanced::insert_migration_correction(conn, module_id, section, original_text, corrected_text, reason)
        })
    }

    fn get_migration_correction(
        &self,
        correction_id: i64,
    ) -> Result<Option<CorrectionRow>, StorageError> {
        self.db.with_reader(|conn| {
            let row = queries::advanced::get_migration_correction(conn, correction_id)?;
            Ok(row.map(|r| CorrectionRow {
                id: r.id, module_id: r.module_id, section: r.section,
                original_text: r.original_text, corrected_text: r.corrected_text,
                reason: r.reason, created_at: r.created_at,
            }))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftBatchWriter implementation
// ═══════════════════════════════════════════════════════════════════════════════

impl IDriftBatchWriter for DriftStorageEngine {
    fn send_raw(&self, _command_name: &str, _payload: &[u8]) -> Result<(), StorageError> {
        // Type-erased batch sending for cloud implementations.
        // The SQLite engine uses send_batch() directly instead.
        // TODO: implement deserialization when cloud backend needs it.
        Err(StorageError::NotSupported {
            operation: "send_raw".to_string(),
            reason: "Use send_batch() with typed BatchCommand for SQLite backend".to_string(),
        })
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.batch.flush()
    }

    fn flush_sync(&self) -> Result<WriteStats, StorageError> {
        self.batch.flush_sync()?;
        // BatchWriter::flush_sync returns () — we return default stats.
        // The real stats accumulate on the writer thread and are returned on shutdown.
        Ok(WriteStats::default())
    }

    fn stats(&self) -> WriteStats {
        // Stats are accumulated on the writer thread — no way to query them
        // without shutting down. Return defaults for now.
        WriteStats::default()
    }

    fn shutdown(self: Box<Self>) -> Result<WriteStats, StorageError> {
        // Cannot consume BatchWriter from Box<Self> easily.
        // Flush sync and return defaults.
        self.batch.flush_sync()?;
        Ok(WriteStats::default())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDriftReader implementation (bridge evidence interface)
// ═══════════════════════════════════════════════════════════════════════════════

impl IDriftReader for DriftStorageEngine {
    fn pattern_confidence(&self, pattern_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT posterior_mean FROM pattern_confidence WHERE pattern_id = ?1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map(rusqlite::params![pattern_id], |row| row.get(0))
                .map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }

    fn pattern_occurrence_rate(&self, pattern_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let file_count: f64 = conn.query_row(
                "SELECT COALESCE(NULLIF(CAST(COUNT(DISTINCT file) AS REAL), 0.0), 1.0) FROM detections",
                [], |row| row.get(0),
            ).map_err(sqe)?;
            let pattern_files: f64 = conn.query_row(
                "SELECT CAST(COUNT(DISTINCT file) AS REAL) FROM detections WHERE pattern_id = ?1",
                rusqlite::params![pattern_id], |row| row.get(0),
            ).map_err(sqe)?;
            if pattern_files == 0.0 { Ok(None) } else { Ok(Some(pattern_files / file_count)) }
        })
    }

    fn false_positive_rate(&self, pattern_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let total: i64 = conn.query_row(
                "SELECT COUNT(*) FROM feedback WHERE pattern_id = ?1",
                rusqlite::params![pattern_id], |row| row.get(0),
            ).map_err(sqe)?;
            if total == 0 { return Ok(None); }
            let dismiss: i64 = conn.query_row(
                "SELECT COUNT(*) FROM feedback WHERE pattern_id = ?1 AND action = 'dismiss'",
                rusqlite::params![pattern_id], |row| row.get(0),
            ).map_err(sqe)?;
            Ok(Some(dismiss as f64 / total as f64))
        })
    }

    fn constraint_verified(&self, constraint_id: &str) -> Result<Option<bool>, StorageError> {
        self.db.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT passed FROM constraint_verifications WHERE constraint_id = ?1 ORDER BY verified_at DESC LIMIT 1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map(rusqlite::params![constraint_id], |row| row.get(0))
                .map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }

    fn coupling_metric(&self, module: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT instability FROM coupling_metrics WHERE module = ?1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map(rusqlite::params![module], |row| row.get(0))
                .map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }

    fn dna_health(&self) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let val: Option<f64> = conn.query_row(
                "SELECT AVG(confidence * consistency) FROM dna_genes",
                [], |row| row.get(0),
            ).map_err(sqe)?;
            Ok(val)
        })
    }

    fn test_coverage(&self, function_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT overall_score FROM test_quality WHERE function_id = ?1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map(rusqlite::params![function_id], |row| row.get(0))
                .map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }

    fn error_handling_gaps(&self, file_prefix: &str) -> Result<Option<u32>, StorageError> {
        self.db.with_reader(|conn| {
            let like = format!("{file_prefix}%");
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM error_gaps WHERE file LIKE ?1",
                rusqlite::params![like], |row| row.get(0),
            ).map_err(sqe)?;
            if count == 0 { Ok(None) } else { Ok(Some(count as u32)) }
        })
    }

    fn decision_evidence(&self, decision_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let id: i64 = decision_id.parse().unwrap_or(0);
            let mut stmt = conn.prepare_cached(
                "SELECT confidence FROM decisions WHERE id = ?1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map(rusqlite::params![id], |row| row.get(0))
                .map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }

    fn boundary_data(&self, boundary_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let id: i64 = boundary_id.parse().unwrap_or(0);
            let mut stmt = conn.prepare_cached(
                "SELECT confidence FROM boundaries WHERE id = ?1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map(rusqlite::params![id], |row| row.get(0))
                .map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }

    fn taint_flow_risk(&self, file: &str) -> Result<Option<u32>, StorageError> {
        self.db.with_reader(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM taint_flows WHERE source_file = ?1 AND is_sanitized = 0",
                rusqlite::params![file], |row| row.get(0),
            ).map_err(sqe)?;
            if count == 0 { Ok(None) } else { Ok(Some(count as u32)) }
        })
    }

    fn call_graph_coverage(&self, function_id: &str) -> Result<Option<f64>, StorageError> {
        self.db.with_reader(|conn| {
            let fid: i64 = function_id.parse().unwrap_or(0);
            let total: f64 = conn.query_row(
                "SELECT CAST(COUNT(*) AS REAL) FROM functions",
                [], |row| row.get(0),
            ).map_err(sqe)?;
            if total == 0.0 { return Ok(None); }
            let callees: f64 = conn.query_row(
                "SELECT CAST(COUNT(DISTINCT callee_id) AS REAL) FROM call_edges WHERE caller_id = ?1",
                rusqlite::params![fid], |row| row.get(0),
            ).map_err(sqe)?;
            Ok(Some(callees / total))
        })
    }

    fn count_matching_patterns(&self, pattern_ids: &[String]) -> Result<u32, StorageError> {
        if pattern_ids.is_empty() { return Ok(0); }
        self.db.with_reader(|conn| {
            let placeholders: String = pattern_ids.iter().enumerate()
                .map(|(i, _)| format!("?{}", i + 1))
                .collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT COUNT(*) FROM pattern_confidence WHERE pattern_id IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql).map_err(sqe)?;
            let params: Vec<&dyn rusqlite::types::ToSql> = pattern_ids
                .iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();
            let count: i64 = stmt.query_row(params.as_slice(), |row| row.get(0)).map_err(sqe)?;
            Ok(count as u32)
        })
    }

    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError> {
        self.db.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT completed_at FROM scan_history WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1"
            ).map_err(sqe)?;
            let mut rows = stmt.query_map([], |row| {
                let ts: i64 = row.get(0)?;
                Ok(ts.to_string())
            }).map_err(sqe)?;
            match rows.next() {
                Some(Ok(val)) => Ok(Some(val)),
                Some(Err(e)) => Err(sqe(e)),
                None => Ok(None),
            }
        })
    }
}
