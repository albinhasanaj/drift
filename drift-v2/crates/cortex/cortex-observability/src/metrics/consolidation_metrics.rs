//! CX15 metrics exposure: precision, lift, compression ratio, contradiction rate, stability.

use cortex_core::models::ConsolidationMetrics;
use serde::{Deserialize, Serialize};

/// Aggregated consolidation metrics over a time window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConsolidationMetricsCollector {
    /// All recorded consolidation metrics.
    samples: Vec<ConsolidationMetrics>,
    /// Number of contradictions detected during consolidation.
    pub contradictions_detected: u64,
    /// Total consolidation runs.
    pub total_runs: u64,
}

impl ConsolidationMetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record metrics from a consolidation run.
    pub fn record(&mut self, metrics: ConsolidationMetrics, contradictions: u64) {
        self.samples.push(metrics);
        self.contradictions_detected += contradictions;
        self.total_runs += 1;
    }

    /// Average precision across all runs.
    pub fn avg_precision(&self) -> f64 {
        Self::avg(&self.samples, |m| m.precision)
    }

    /// Average compression ratio.
    pub fn avg_compression_ratio(&self) -> f64 {
        Self::avg(&self.samples, |m| m.compression_ratio)
    }

    /// Average lift.
    pub fn avg_lift(&self) -> f64 {
        Self::avg(&self.samples, |m| m.lift)
    }

    /// Average stability.
    pub fn avg_stability(&self) -> f64 {
        Self::avg(&self.samples, |m| m.stability)
    }

    /// Contradiction rate per run.
    pub fn contradiction_rate(&self) -> f64 {
        if self.total_runs == 0 {
            return 0.0;
        }
        self.contradictions_detected as f64 / self.total_runs as f64
    }

    fn avg(samples: &[ConsolidationMetrics], f: fn(&ConsolidationMetrics) -> f64) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let sum: f64 = samples.iter().map(f).sum();
        sum / samples.len() as f64
    }
}
