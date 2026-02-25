//! `IDriftBatchWriter` trait — batch write operations.
//!
//! Abstracts the existing `BatchWriter` behind a trait so cloud
//! implementations can batch into HTTP payloads instead of SQLite transactions.

use crate::errors::StorageError;
use std::sync::Arc;

/// Statistics from the batch writer.
#[derive(Debug, Default, Clone)]
pub struct WriteStats {
    pub file_metadata_rows: usize,
    pub parse_cache_rows: usize,
    pub function_rows: usize,
    pub call_edge_rows: usize,
    pub detection_rows: usize,
    pub boundary_rows: usize,
    pub pattern_confidence_rows: usize,
    pub outlier_rows: usize,
    pub convention_rows: usize,
    pub scan_history_rows: usize,
    pub data_access_rows: usize,
    pub reachability_rows: usize,
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
}

/// Batch writer trait — abstracts the channel-based batch writer.
///
/// The SQLite implementation sends `BatchCommand` variants through a channel
/// to a dedicated writer thread. A future Postgres implementation could batch
/// into HTTP POST payloads.
pub trait IDriftBatchWriter: Send + Sync {
    /// Send a serializable batch command (type-erased via `Box<dyn Any>`).
    /// Implementations cast back to `BatchCommand` internally.
    ///
    /// For the SQLite implementation, this delegates to `BatchWriter::send()`.
    /// For cloud implementations, this accumulates into an HTTP batch payload.
    fn send_raw(&self, command_name: &str, payload: &[u8]) -> Result<(), StorageError>;

    /// Flush pending writes (fire-and-forget, does NOT wait for completion).
    fn flush(&self) -> Result<(), StorageError>;

    /// Flush and wait for all pending writes to complete.
    fn flush_sync(&self) -> Result<WriteStats, StorageError>;

    /// Get current write statistics.
    fn stats(&self) -> WriteStats;

    /// Gracefully shut down the batch writer.
    fn shutdown(self: Box<Self>) -> Result<WriteStats, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftBatchWriter + ?Sized> IDriftBatchWriter for Arc<T> {
    fn send_raw(&self, command_name: &str, payload: &[u8]) -> Result<(), StorageError> {
        (**self).send_raw(command_name, payload)
    }
    fn flush(&self) -> Result<(), StorageError> {
        (**self).flush()
    }
    fn flush_sync(&self) -> Result<WriteStats, StorageError> {
        (**self).flush_sync()
    }
    fn stats(&self) -> WriteStats {
        (**self).stats()
    }
    fn shutdown(self: Box<Self>) -> Result<WriteStats, StorageError> {
        // Cannot consume Arc through Box<Arc<T>>, so flush_sync instead.
        self.flush_sync()
    }
}
