//! `IDriftReader` trait — read-only bridge evidence interface.
//!
//! The bridge crate needs read-only access to drift.db for grounding evidence
//! collection. This trait replaces the `ATTACH DATABASE` pattern with a clean
//! abstraction that works for both SQLite (local) and Postgres (cloud).
//!
//! Maps 1:1 to `cortex-drift-bridge/src/query/drift_queries.rs`.

use crate::errors::StorageError;
use std::sync::Arc;

/// Read-only interface to drift.db for cross-DB evidence collection.
///
/// Each method corresponds to one evidence type in the bridge grounding system.
/// All methods are read-only — no writes allowed.
pub trait IDriftReader: Send + Sync {
    /// Get the posterior mean confidence for a pattern.
    fn pattern_confidence(&self, pattern_id: &str) -> Result<Option<f64>, StorageError>;

    /// Get the occurrence rate for a pattern (detection count / file count).
    fn pattern_occurrence_rate(&self, pattern_id: &str) -> Result<Option<f64>, StorageError>;

    /// Get the false positive rate for a pattern (dismiss count / total feedback).
    fn false_positive_rate(&self, pattern_id: &str) -> Result<Option<f64>, StorageError>;

    /// Check if a constraint has been verified (latest verification passed).
    fn constraint_verified(&self, constraint_id: &str) -> Result<Option<bool>, StorageError>;

    /// Get the coupling metric distance for a module.
    fn coupling_metric(&self, module: &str) -> Result<Option<f64>, StorageError>;

    /// Get overall DNA health (average gene consistency).
    fn dna_health(&self) -> Result<Option<f64>, StorageError>;

    /// Get test coverage score for a function.
    fn test_coverage(&self, function_id: &str) -> Result<Option<f64>, StorageError>;

    /// Get count of error handling gaps for files matching a prefix.
    fn error_handling_gaps(&self, file_prefix: &str) -> Result<Option<u32>, StorageError>;

    /// Get decision confidence for a decision.
    fn decision_evidence(&self, decision_id: &str) -> Result<Option<f64>, StorageError>;

    /// Get boundary confidence for a boundary.
    fn boundary_data(&self, boundary_id: &str) -> Result<Option<f64>, StorageError>;

    /// Get count of unsanitized taint flows for a file.
    fn taint_flow_risk(&self, file: &str) -> Result<Option<u32>, StorageError>;

    /// Get call graph coverage for a function (callee count / total functions).
    fn call_graph_coverage(&self, function_id: &str) -> Result<Option<f64>, StorageError>;

    /// Count how many of the given pattern IDs exist in the confidence table.
    fn count_matching_patterns(&self, pattern_ids: &[String]) -> Result<u32, StorageError>;

    /// Get the latest scan timestamp as an ISO 8601 string.
    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftReader + ?Sized> IDriftReader for Arc<T> {
    fn pattern_confidence(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        (**self).pattern_confidence(pid)
    }
    fn pattern_occurrence_rate(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        (**self).pattern_occurrence_rate(pid)
    }
    fn false_positive_rate(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        (**self).false_positive_rate(pid)
    }
    fn constraint_verified(&self, cid: &str) -> Result<Option<bool>, StorageError> {
        (**self).constraint_verified(cid)
    }
    fn coupling_metric(&self, module: &str) -> Result<Option<f64>, StorageError> {
        (**self).coupling_metric(module)
    }
    fn dna_health(&self) -> Result<Option<f64>, StorageError> {
        (**self).dna_health()
    }
    fn test_coverage(&self, fid: &str) -> Result<Option<f64>, StorageError> {
        (**self).test_coverage(fid)
    }
    fn error_handling_gaps(&self, fp: &str) -> Result<Option<u32>, StorageError> {
        (**self).error_handling_gaps(fp)
    }
    fn decision_evidence(&self, did: &str) -> Result<Option<f64>, StorageError> {
        (**self).decision_evidence(did)
    }
    fn boundary_data(&self, bid: &str) -> Result<Option<f64>, StorageError> {
        (**self).boundary_data(bid)
    }
    fn taint_flow_risk(&self, file: &str) -> Result<Option<u32>, StorageError> {
        (**self).taint_flow_risk(file)
    }
    fn call_graph_coverage(&self, fid: &str) -> Result<Option<f64>, StorageError> {
        (**self).call_graph_coverage(fid)
    }
    fn count_matching_patterns(&self, pids: &[String]) -> Result<u32, StorageError> {
        (**self).count_matching_patterns(pids)
    }
    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError> {
        (**self).latest_scan_timestamp()
    }
}
