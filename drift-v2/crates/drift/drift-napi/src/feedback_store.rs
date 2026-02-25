//! DbFeedbackStore — bridges the `feedback` table in drift.db to the
//! `FeedbackStore` trait consumed by `ConfidenceScorer`.
//!
//! This closes the feedback loop: user actions (dismiss/fix/suppress/escalate)
//! written via NAPI → feedback table → DbFeedbackStore → ConfidenceScorer
//! adjusts (alpha, beta) → confidence changes on next analysis run.

use std::sync::Arc;

use drift_analysis::patterns::confidence::scorer::FeedbackStore;

use crate::runtime::DriftRuntime;

/// Database-backed feedback store that reads from the `feedback` table.
///
/// Each call to `get_adjustments()` queries all feedback rows for the given
/// pattern_id and converts them to `(alpha_delta, beta_delta)` tuples using
/// the same mapping as `ConfidenceFeedback::compute_adjustment()`.
pub struct DbFeedbackStore {
    rt: Arc<DriftRuntime>,
}

impl DbFeedbackStore {
    pub fn new(rt: Arc<DriftRuntime>) -> Self {
        Self { rt }
    }
}

impl FeedbackStore for DbFeedbackStore {
    fn get_adjustments(&self, pattern_id: &str) -> Vec<(f64, f64)> {
        self.rt
            .storage
            .with_reader(|conn| {
                drift_storage::queries::enforcement::query_feedback_adjustments(conn, pattern_id)
            })
            .unwrap_or_default()
    }
}
