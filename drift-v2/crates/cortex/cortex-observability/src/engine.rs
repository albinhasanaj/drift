//! [`ObservabilityEngine`] — owns health, metrics, tracing, degradation, and query log subsystems.

use cortex_core::errors::CortexResult;
use cortex_core::models::{DegradationEvent, HealthReport};
use cortex_core::traits::IHealthReporter;

use crate::degradation::{evaluate_alerts, DegradationAlert, DegradationTracker};
use crate::health::{HealthChecker, HealthSnapshot, Recommendation};
use crate::metrics::MetricsCollector;
use crate::query_log::QueryLog;

/// Central observability engine that orchestrates all subsystems.
#[derive(Debug)]
pub struct ObservabilityEngine {
    pub health: HealthChecker,
    pub metrics: MetricsCollector,
    pub degradation: DegradationTracker,
    pub query_log: QueryLog,
}

impl ObservabilityEngine {
    /// Create a new engine with default configuration.
    pub fn new() -> Self {
        Self {
            health: HealthChecker::new(),
            metrics: MetricsCollector::new(),
            degradation: DegradationTracker::new(),
            query_log: QueryLog::new(),
        }
    }

    /// Update the health snapshot and generate a report.
    pub fn health_report(&mut self, snapshot: HealthSnapshot) -> CortexResult<HealthReport> {
        self.health.set_snapshot(snapshot);
        self.health.report()
    }

    /// Get current recommendations.
    pub fn recommendations(&self) -> Vec<Recommendation> {
        self.health.recommendations()
    }

    /// Record a degradation event.
    pub fn record_degradation(&mut self, event: DegradationEvent) {
        self.degradation.record(event);
    }

    /// Mark a component as recovered from degradation.
    pub fn mark_recovered(&mut self, component: &str) {
        self.degradation.mark_recovered(component);
    }

    /// Evaluate degradation alerts.
    pub fn degradation_alerts(&self) -> Vec<DegradationAlert> {
        evaluate_alerts(&self.degradation)
    }

    /// Reset all metrics (for testing or periodic rotation).
    pub fn reset_metrics(&mut self) {
        self.metrics.reset();
    }

    /// F-01/F-02/F-03: Serialize current metrics and query log state to JSON.
    /// Used during shutdown to persist metrics to storage via temporal events.
    pub fn metrics_snapshot(&self) -> CortexResult<serde_json::Value> {
        let metrics_json = serde_json::to_value(&self.metrics)
            .map_err(cortex_core::errors::CortexError::SerializationError)?;
        let query_count = self.query_log.count();
        let avg_latency_ms = self.query_log.avg_latency().as_millis() as u64;

        Ok(serde_json::json!({
            "metrics": metrics_json,
            "query_log_count": query_count,
            "query_avg_latency_ms": avg_latency_ms,
        }))
    }
}

impl Default for ObservabilityEngine {
    fn default() -> Self {
        Self::new()
    }
}
