//! `IDriftAnalysis` trait — functions, detections, patterns, boundaries, call edges, scan history.
//!
//! Maps to `drift-storage/src/queries/` modules: `functions.rs`, `detections.rs`,
//! `patterns.rs`, `boundaries.rs`, `call_edges.rs`, `scan_history.rs`.

use crate::errors::StorageError;
use std::sync::Arc;

// ─── Row Types ──────────────────────────────────────────────────────

/// A function record.
#[derive(Debug, Clone)]
pub struct FunctionRow {
    pub id: i64,
    pub file: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub language: String,
    pub line: i64,
    pub end_line: i64,
    pub parameter_count: i64,
    pub return_type: Option<String>,
    pub is_exported: bool,
    pub is_async: bool,
    pub body_hash: Option<Vec<u8>>,
    pub signature_hash: Option<Vec<u8>>,
}

/// A detection record.
#[derive(Debug, Clone)]
pub struct DetectionRow {
    pub id: i64,
    pub file: String,
    pub line: i64,
    pub column_num: i64,
    pub pattern_id: String,
    pub category: String,
    pub confidence: f64,
    pub detection_method: String,
    pub cwe_ids: Option<String>,
    pub owasp: Option<String>,
    pub matched_text: Option<String>,
    pub created_at: i64,
}

/// Summary row for framework detection aggregation.
#[derive(Debug, Clone)]
pub struct DetectionSummaryRow {
    pub detection_method: String,
    pub count: i64,
    pub avg_confidence: f64,
}

/// A pattern confidence row.
#[derive(Debug, Clone)]
pub struct PatternConfidenceRow {
    pub pattern_id: String,
    pub alpha: f64,
    pub beta: f64,
    pub posterior_mean: f64,
    pub credible_interval_low: f64,
    pub credible_interval_high: f64,
    pub tier: String,
    pub momentum: String,
    pub last_updated: i64,
}

/// An outlier row.
#[derive(Debug, Clone)]
pub struct OutlierRow {
    pub id: i64,
    pub pattern_id: String,
    pub file: String,
    pub line: i64,
    pub deviation_score: f64,
    pub significance: String,
    pub method: String,
    pub created_at: i64,
}

/// A convention row.
#[derive(Debug, Clone)]
pub struct ConventionRow {
    pub id: i64,
    pub pattern_id: String,
    pub category: String,
    pub scope: String,
    pub dominance_ratio: f64,
    pub promotion_status: String,
    pub discovered_at: i64,
    pub last_seen: i64,
    pub expires_at: Option<i64>,
}

/// A boundary record.
#[derive(Debug, Clone)]
pub struct BoundaryRow {
    pub id: i64,
    pub file: String,
    pub framework: String,
    pub model_name: String,
    pub table_name: Option<String>,
    pub field_name: Option<String>,
    pub sensitivity: Option<String>,
    pub confidence: f64,
    pub created_at: i64,
}

/// A call edge record.
#[derive(Debug, Clone)]
pub struct CallEdgeRow {
    pub caller_id: i64,
    pub callee_id: i64,
    pub resolution: String,
    pub confidence: f64,
    pub call_site_line: i64,
}

/// A scan history record.
#[derive(Debug, Clone)]
pub struct ScanHistoryRow {
    pub id: i64,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub root_path: String,
    pub total_files: Option<i64>,
    pub added_files: Option<i64>,
    pub modified_files: Option<i64>,
    pub removed_files: Option<i64>,
    pub unchanged_files: Option<i64>,
    pub duration_ms: Option<i64>,
    pub status: String,
    pub error: Option<String>,
}

// ─── Trait ───────────────────────────────────────────────────────────

/// Analysis storage operations: functions, detections, patterns, boundaries,
/// call edges, and scan history.
pub trait IDriftAnalysis: Send + Sync {
    // ── functions ──

    /// Get all functions for a given file.
    fn get_functions_by_file(&self, file: &str) -> Result<Vec<FunctionRow>, StorageError>;

    /// Get a function by qualified name.
    fn get_function_by_qualified_name(
        &self,
        qualified_name: &str,
    ) -> Result<Option<FunctionRow>, StorageError>;

    /// Delete all functions for a given file.
    fn delete_functions_by_file(&self, file: &str) -> Result<usize, StorageError>;

    /// Count total functions.
    fn count_functions(&self) -> Result<i64, StorageError>;

    /// Count entry point functions (zero incoming call edges).
    fn count_entry_points(&self) -> Result<i64, StorageError>;

    // ── detections ──

    /// Insert a batch of detections. Returns count inserted.
    fn insert_detections(&self, detections: &[DetectionRow]) -> Result<usize, StorageError>;

    /// Get all detections for a given file.
    fn get_detections_by_file(&self, file: &str) -> Result<Vec<DetectionRow>, StorageError>;

    /// Get detections by category.
    fn get_detections_by_category(&self, category: &str) -> Result<Vec<DetectionRow>, StorageError>;

    /// Get all detections, ordered by confidence desc, with a limit.
    fn query_all_detections(&self, limit: usize) -> Result<Vec<DetectionRow>, StorageError>;

    /// Delete all detections for a given file.
    fn delete_detections_by_file(&self, file: &str) -> Result<usize, StorageError>;

    /// Count total detections.
    fn count_detections(&self) -> Result<i64, StorageError>;

    /// Get detections by detection method.
    fn get_detections_by_method(&self, method: &str) -> Result<Vec<DetectionRow>, StorageError>;

    /// Get detections by pattern ID prefix.
    fn get_detections_by_pattern_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<DetectionRow>, StorageError>;

    /// Get detections that reference a specific CWE ID.
    fn get_detections_by_cwe(&self, cwe_id: u32) -> Result<Vec<DetectionRow>, StorageError>;

    /// Get a summary of detections grouped by detection method.
    fn get_framework_detection_summary(&self) -> Result<Vec<DetectionSummaryRow>, StorageError>;

    // ── patterns ──

    /// Insert or update a pattern confidence score.
    fn upsert_confidence(&self, row: &PatternConfidenceRow) -> Result<(), StorageError>;

    /// Query pattern confidence by tier with keyset pagination.
    fn query_confidence_by_tier(
        &self,
        tier: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PatternConfidenceRow>, StorageError>;

    /// Query all pattern confidence scores.
    fn query_all_confidence(&self) -> Result<Vec<PatternConfidenceRow>, StorageError>;

    /// Insert an outlier row.
    fn insert_outlier(&self, row: &OutlierRow) -> Result<(), StorageError>;

    /// Query outliers by pattern_id.
    fn query_outliers_by_pattern(
        &self,
        pattern_id: &str,
    ) -> Result<Vec<OutlierRow>, StorageError>;

    /// Insert a convention row.
    fn insert_convention(&self, row: &ConventionRow) -> Result<(), StorageError>;

    /// Query conventions by category.
    fn query_conventions_by_category(
        &self,
        category: &str,
    ) -> Result<Vec<ConventionRow>, StorageError>;

    /// Query all conventions.
    fn query_all_conventions(&self) -> Result<Vec<ConventionRow>, StorageError>;

    // ── boundaries ──

    /// Insert a batch of boundary records. Returns count inserted.
    fn insert_boundaries(&self, boundaries: &[BoundaryRow]) -> Result<usize, StorageError>;

    /// Get all boundaries for a given file.
    fn get_boundaries_by_file(&self, file: &str) -> Result<Vec<BoundaryRow>, StorageError>;

    /// Get all boundaries by framework.
    fn get_boundaries_by_framework(
        &self,
        framework: &str,
    ) -> Result<Vec<BoundaryRow>, StorageError>;

    /// Get all sensitive field boundaries.
    fn get_sensitive_boundaries(&self) -> Result<Vec<BoundaryRow>, StorageError>;

    /// Delete all boundaries for a given file.
    fn delete_boundaries_by_file(&self, file: &str) -> Result<usize, StorageError>;

    /// Count total boundaries.
    fn count_boundaries(&self) -> Result<i64, StorageError>;

    // ── call_edges ──

    /// Insert a batch of call edges. Returns count inserted.
    fn insert_call_edges(&self, edges: &[CallEdgeRow]) -> Result<usize, StorageError>;

    /// Get all edges where the given function is the caller.
    fn get_edges_by_caller(&self, caller_id: i64) -> Result<Vec<CallEdgeRow>, StorageError>;

    /// Get all edges where the given function is the callee.
    fn get_edges_by_callee(&self, callee_id: i64) -> Result<Vec<CallEdgeRow>, StorageError>;

    /// Delete all edges involving functions from a given file.
    fn delete_edges_by_file(&self, file: &str) -> Result<usize, StorageError>;

    /// Count total call edges.
    fn count_call_edges(&self) -> Result<i64, StorageError>;

    /// Count edges with non-fuzzy resolution.
    fn count_resolved_edges(&self) -> Result<i64, StorageError>;

    // ── scan_history ──

    /// Insert a new scan history record (status = 'running'). Returns the row id.
    fn insert_scan_start(&self, started_at: i64, root_path: &str) -> Result<i64, StorageError>;

    /// Update a scan history record with completion data.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<(), StorageError>;

    /// Query recent scan history entries.
    fn query_recent_scans(&self, limit: usize) -> Result<Vec<ScanHistoryRow>, StorageError>;

    /// Count total scan history entries.
    fn count_scans(&self) -> Result<i64, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftAnalysis + ?Sized> IDriftAnalysis for Arc<T> {
    fn get_functions_by_file(&self, file: &str) -> Result<Vec<FunctionRow>, StorageError> {
        (**self).get_functions_by_file(file)
    }
    fn get_function_by_qualified_name(&self, qn: &str) -> Result<Option<FunctionRow>, StorageError> {
        (**self).get_function_by_qualified_name(qn)
    }
    fn delete_functions_by_file(&self, file: &str) -> Result<usize, StorageError> {
        (**self).delete_functions_by_file(file)
    }
    fn count_functions(&self) -> Result<i64, StorageError> {
        (**self).count_functions()
    }
    fn count_entry_points(&self) -> Result<i64, StorageError> {
        (**self).count_entry_points()
    }
    fn insert_detections(&self, d: &[DetectionRow]) -> Result<usize, StorageError> {
        (**self).insert_detections(d)
    }
    fn get_detections_by_file(&self, file: &str) -> Result<Vec<DetectionRow>, StorageError> {
        (**self).get_detections_by_file(file)
    }
    fn get_detections_by_category(&self, cat: &str) -> Result<Vec<DetectionRow>, StorageError> {
        (**self).get_detections_by_category(cat)
    }
    fn query_all_detections(&self, limit: usize) -> Result<Vec<DetectionRow>, StorageError> {
        (**self).query_all_detections(limit)
    }
    fn delete_detections_by_file(&self, file: &str) -> Result<usize, StorageError> {
        (**self).delete_detections_by_file(file)
    }
    fn count_detections(&self) -> Result<i64, StorageError> {
        (**self).count_detections()
    }
    fn get_detections_by_method(&self, m: &str) -> Result<Vec<DetectionRow>, StorageError> {
        (**self).get_detections_by_method(m)
    }
    fn get_detections_by_pattern_prefix(&self, p: &str) -> Result<Vec<DetectionRow>, StorageError> {
        (**self).get_detections_by_pattern_prefix(p)
    }
    fn get_detections_by_cwe(&self, cwe_id: u32) -> Result<Vec<DetectionRow>, StorageError> {
        (**self).get_detections_by_cwe(cwe_id)
    }
    fn get_framework_detection_summary(&self) -> Result<Vec<DetectionSummaryRow>, StorageError> {
        (**self).get_framework_detection_summary()
    }
    fn upsert_confidence(&self, row: &PatternConfidenceRow) -> Result<(), StorageError> {
        (**self).upsert_confidence(row)
    }
    fn query_confidence_by_tier(&self, tier: &str, after_id: Option<&str>, limit: usize) -> Result<Vec<PatternConfidenceRow>, StorageError> {
        (**self).query_confidence_by_tier(tier, after_id, limit)
    }
    fn query_all_confidence(&self) -> Result<Vec<PatternConfidenceRow>, StorageError> {
        (**self).query_all_confidence()
    }
    fn insert_outlier(&self, row: &OutlierRow) -> Result<(), StorageError> {
        (**self).insert_outlier(row)
    }
    fn query_outliers_by_pattern(&self, pid: &str) -> Result<Vec<OutlierRow>, StorageError> {
        (**self).query_outliers_by_pattern(pid)
    }
    fn insert_convention(&self, row: &ConventionRow) -> Result<(), StorageError> {
        (**self).insert_convention(row)
    }
    fn query_conventions_by_category(&self, cat: &str) -> Result<Vec<ConventionRow>, StorageError> {
        (**self).query_conventions_by_category(cat)
    }
    fn query_all_conventions(&self) -> Result<Vec<ConventionRow>, StorageError> {
        (**self).query_all_conventions()
    }
    fn insert_boundaries(&self, b: &[BoundaryRow]) -> Result<usize, StorageError> {
        (**self).insert_boundaries(b)
    }
    fn get_boundaries_by_file(&self, file: &str) -> Result<Vec<BoundaryRow>, StorageError> {
        (**self).get_boundaries_by_file(file)
    }
    fn get_boundaries_by_framework(&self, fw: &str) -> Result<Vec<BoundaryRow>, StorageError> {
        (**self).get_boundaries_by_framework(fw)
    }
    fn get_sensitive_boundaries(&self) -> Result<Vec<BoundaryRow>, StorageError> {
        (**self).get_sensitive_boundaries()
    }
    fn delete_boundaries_by_file(&self, file: &str) -> Result<usize, StorageError> {
        (**self).delete_boundaries_by_file(file)
    }
    fn count_boundaries(&self) -> Result<i64, StorageError> {
        (**self).count_boundaries()
    }
    fn insert_call_edges(&self, edges: &[CallEdgeRow]) -> Result<usize, StorageError> {
        (**self).insert_call_edges(edges)
    }
    fn get_edges_by_caller(&self, id: i64) -> Result<Vec<CallEdgeRow>, StorageError> {
        (**self).get_edges_by_caller(id)
    }
    fn get_edges_by_callee(&self, id: i64) -> Result<Vec<CallEdgeRow>, StorageError> {
        (**self).get_edges_by_callee(id)
    }
    fn delete_edges_by_file(&self, file: &str) -> Result<usize, StorageError> {
        (**self).delete_edges_by_file(file)
    }
    fn count_call_edges(&self) -> Result<i64, StorageError> {
        (**self).count_call_edges()
    }
    fn count_resolved_edges(&self) -> Result<i64, StorageError> {
        (**self).count_resolved_edges()
    }
    fn insert_scan_start(&self, started_at: i64, root_path: &str) -> Result<i64, StorageError> {
        (**self).insert_scan_start(started_at, root_path)
    }
    fn update_scan_complete(&self, id: i64, completed_at: i64, total_files: i64, added_files: i64, modified_files: i64, removed_files: i64, unchanged_files: i64, duration_ms: i64, status: &str, error: Option<&str>) -> Result<(), StorageError> {
        (**self).update_scan_complete(id, completed_at, total_files, added_files, modified_files, removed_files, unchanged_files, duration_ms, status, error)
    }
    fn query_recent_scans(&self, limit: usize) -> Result<Vec<ScanHistoryRow>, StorageError> {
        (**self).query_recent_scans(limit)
    }
    fn count_scans(&self) -> Result<i64, StorageError> {
        (**self).count_scans()
    }
}
