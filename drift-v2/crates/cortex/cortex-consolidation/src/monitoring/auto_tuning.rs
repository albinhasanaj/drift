//! Feedback loop every 100 events or weekly: adjust thresholds, log adjustments to audit trail.

use super::metrics::QualityAssessment;

/// Number of consolidation events between auto-tuning checks.
pub const TUNING_EVENT_INTERVAL: usize = 100;

/// Tunable thresholds for the consolidation pipeline.
#[derive(Debug, Clone)]
pub struct TunableThresholds {
    /// Minimum confidence for selection (Phase 1).
    pub min_confidence: f64,
    /// Novelty threshold for abstraction (Phase 4).
    pub novelty_threshold: f64,
    /// Overlap threshold for integration (Phase 5).
    pub overlap_threshold: f64,
    /// Number of consolidation events since last tuning.
    pub events_since_tuning: usize,
}

impl Default for TunableThresholds {
    fn default() -> Self {
        Self {
            min_confidence: 0.3,
            novelty_threshold: 0.85,
            overlap_threshold: 0.90,
            events_since_tuning: 0,
        }
    }
}

/// An adjustment made by the auto-tuner.
#[derive(Debug, Clone)]
pub struct TuningAdjustment {
    pub parameter: String,
    pub old_value: f64,
    pub new_value: f64,
    pub reason: String,
}

/// Check if auto-tuning should run and apply adjustments if needed.
///
/// Returns any adjustments made (empty if no tuning needed).
pub fn maybe_tune(
    thresholds: &mut TunableThresholds,
    recent_assessments: &[QualityAssessment],
) -> Vec<TuningAdjustment> {
    thresholds.events_since_tuning += 1;

    if thresholds.events_since_tuning < TUNING_EVENT_INTERVAL {
        return vec![];
    }

    thresholds.events_since_tuning = 0;
    tune(thresholds, recent_assessments)
}

/// Apply tuning based on recent quality assessments.
fn tune(
    thresholds: &mut TunableThresholds,
    assessments: &[QualityAssessment],
) -> Vec<TuningAdjustment> {
    if assessments.is_empty() {
        return vec![];
    }

    let mut adjustments = Vec::new();

    // Count failures by category.
    let precision_failures = assessments.iter().filter(|a| !a.precision_ok).count();
    let compression_failures = assessments.iter().filter(|a| !a.compression_ok).count();
    let total = assessments.len();

    // If precision is failing frequently, raise the minimum confidence.
    if precision_failures as f64 / total as f64 > 0.3 {
        let old = thresholds.min_confidence;
        thresholds.min_confidence = (old + 0.05).min(0.8);
        adjustments.push(TuningAdjustment {
            parameter: "min_confidence".to_string(),
            old_value: old,
            new_value: thresholds.min_confidence,
            reason: format!(
                "precision failing in {}/{} assessments",
                precision_failures, total
            ),
        });
    }

    // If compression is failing, lower the novelty threshold to merge more aggressively.
    if compression_failures as f64 / total as f64 > 0.3 {
        let old = thresholds.novelty_threshold;
        thresholds.novelty_threshold = (old - 0.05).max(0.5);
        adjustments.push(TuningAdjustment {
            parameter: "novelty_threshold".to_string(),
            old_value: old,
            new_value: thresholds.novelty_threshold,
            reason: format!(
                "compression failing in {}/{} assessments",
                compression_failures, total
            ),
        });
    }

    adjustments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tuning_before_interval() {
        let mut thresholds = TunableThresholds::default();
        let adjustments = maybe_tune(&mut thresholds, &[]);
        assert!(adjustments.is_empty());
        assert_eq!(thresholds.events_since_tuning, 1);
    }

    #[test]
    fn tunes_after_interval() {
        let mut thresholds = TunableThresholds {
            events_since_tuning: TUNING_EVENT_INTERVAL - 1,
            ..Default::default()
        };

        // Create assessments with precision failures.
        let bad_assessments: Vec<QualityAssessment> = (0..10)
            .map(|_| QualityAssessment {
                precision_ok: false,
                compression_ok: true,
                lift_ok: true,
                stability_ok: true,
                overall_pass: false,
                issues: vec![],
            })
            .collect();

        let adjustments = maybe_tune(&mut thresholds, &bad_assessments);
        assert!(!adjustments.is_empty());
        assert!(thresholds.min_confidence > 0.3);
    }

    #[test]
    fn compression_failures_lower_novelty() {
        let mut thresholds = TunableThresholds::default();
        let assessments: Vec<QualityAssessment> = (0..10)
            .map(|_| QualityAssessment {
                precision_ok: true,
                compression_ok: false,
                lift_ok: true,
                stability_ok: true,
                overall_pass: false,
                issues: vec![],
            })
            .collect();

        let adjustments = tune(&mut thresholds, &assessments);
        assert!(!adjustments.is_empty());
        assert!(thresholds.novelty_threshold < 0.85);
    }
}
