//! # cortex-observability
//!
//! Health reporting across all subsystems, metrics collection (retrieval, consolidation, storage,
//! embedding, session), structured tracing with span definitions, and degradation event tracking
//! with alerting.

pub mod degradation;
pub mod engine;
pub mod health;
pub mod metrics;
pub mod query_log;
pub mod tracing_setup;

pub use engine::ObservabilityEngine;
pub use health::{HealthChecker, HealthReporter, HealthSnapshot, DriftSummary, TrendIndicator};
pub use metrics::MetricsCollector;
pub use query_log::QueryLog;
