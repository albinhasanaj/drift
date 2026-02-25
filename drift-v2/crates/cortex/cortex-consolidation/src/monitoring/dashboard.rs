//! Surface consolidation metrics through observability.

use cortex_core::models::ConsolidationMetrics;

use super::auto_tuning::TunableThresholds;
use super::metrics::QualityAssessment;

/// Snapshot of consolidation health for observability.
#[derive(Debug, Clone)]
pub struct ConsolidationDashboard {
    /// Total consolidation runs.
    pub total_runs: usize,
    /// Successful runs (passed quality gate).
    pub successful_runs: usize,
    /// Latest metrics.
    pub latest_metrics: Option<ConsolidationMetrics>,
    /// Latest quality assessment.
    pub latest_assessment: Option<QualityAssessment>,
    /// Current tunable thresholds.
    pub thresholds: TunableThresholds,
    /// Success rate (0.0–1.0).
    pub success_rate: f64,
}

impl ConsolidationDashboard {
    /// Create a new empty dashboard.
    pub fn new() -> Self {
        Self {
            total_runs: 0,
            successful_runs: 0,
            latest_metrics: None,
            latest_assessment: None,
            thresholds: TunableThresholds::default(),
            success_rate: 0.0,
        }
    }

    /// Record a consolidation run.
    pub fn record_run(&mut self, metrics: ConsolidationMetrics, assessment: QualityAssessment) {
        self.total_runs += 1;
        if assessment.overall_pass {
            self.successful_runs += 1;
        }
        self.success_rate = if self.total_runs > 0 {
            self.successful_runs as f64 / self.total_runs as f64
        } else {
            0.0
        };
        self.latest_metrics = Some(metrics);
        self.latest_assessment = Some(assessment);
    }
}

impl Default for ConsolidationDashboard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_runs() {
        let mut dash = ConsolidationDashboard::new();
        assert_eq!(dash.total_runs, 0);

        dash.record_run(
            ConsolidationMetrics {
                precision: 0.9,
                compression_ratio: 4.0,
                lift: 2.0,
                stability: 0.9,
            },
            QualityAssessment {
                precision_ok: true,
                compression_ok: true,
                lift_ok: true,
                stability_ok: true,
                overall_pass: true,
                issues: vec![],
            },
        );

        assert_eq!(dash.total_runs, 1);
        assert_eq!(dash.successful_runs, 1);
        assert!((dash.success_rate - 1.0).abs() < f64::EPSILON);
    }
}
