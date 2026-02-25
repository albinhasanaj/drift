//! FeedbackStatsProvider trait — resolves circular dependency with Quality Gates.
//!
//! Quality Gates need feedback stats (FP rates) to make enforcement decisions,
//! but the Feedback Loop needs gate results to track violations. This trait
//! breaks the cycle: gates depend on the trait, feedback implements it.

/// Trait for providing feedback statistics to quality gates.
/// This resolves the circular dependency between gates and feedback.
pub trait FeedbackStatsProvider: Send + Sync {
    /// Get the false positive rate for a specific detector.
    fn fp_rate_for_detector(&self, detector_id: &str) -> f64;

    /// Get the false positive rate for a specific pattern.
    fn fp_rate_for_pattern(&self, pattern_id: &str) -> f64;

    /// Check if a detector is currently disabled.
    fn is_detector_disabled(&self, detector_id: &str) -> bool;

    /// Get the total number of feedback actions for a detector.
    fn total_actions_for_detector(&self, detector_id: &str) -> u64;
}

/// No-op implementation for when feedback data is not available.
pub struct NoOpFeedbackStats;

impl FeedbackStatsProvider for NoOpFeedbackStats {
    fn fp_rate_for_detector(&self, _detector_id: &str) -> f64 {
        0.0
    }

    fn fp_rate_for_pattern(&self, _pattern_id: &str) -> f64 {
        0.0
    }

    fn is_detector_disabled(&self, _detector_id: &str) -> bool {
        false
    }

    fn total_actions_for_detector(&self, _detector_id: &str) -> u64 {
        0
    }
}
