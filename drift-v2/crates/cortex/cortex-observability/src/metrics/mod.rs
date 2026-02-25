//! Central metrics registry.
//!
//! [`MetricsCollector`] owns all domain-specific metric collectors and provides
//! a unified interface for recording and querying metrics.

pub mod consolidation_metrics;
pub mod embedding_metrics;
pub mod retrieval_metrics;
pub mod session_metrics;
pub mod storage_metrics;

pub use consolidation_metrics::ConsolidationMetricsCollector;
pub use embedding_metrics::EmbeddingMetrics;
pub use retrieval_metrics::RetrievalMetrics;
pub use session_metrics::SessionMetrics;
pub use storage_metrics::StorageMetrics;

/// Central metrics registry that owns all domain-specific collectors.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MetricsCollector {
    pub retrieval: RetrievalMetrics,
    pub consolidation: ConsolidationMetricsCollector,
    pub storage: StorageMetrics,
    pub embedding: EmbeddingMetrics,
    pub session: SessionMetrics,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all metrics (useful for testing or periodic rotation).
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}
