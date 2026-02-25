//! Feed back into confidence scoring — dismissed violations reduce pattern confidence.

use super::types::*;

/// Confidence adjustment from feedback actions.
pub struct ConfidenceFeedback;

impl ConfidenceFeedback {
    pub fn new() -> Self {
        Self
    }

    /// Compute the confidence adjustment for a feedback action.
    /// Returns (alpha_delta, beta_delta) for Bayesian parameter updates.
    pub fn compute_adjustment(
        &self,
        action: FeedbackAction,
        dismissal_reason: Option<DismissalReason>,
    ) -> (f64, f64) {
        match action {
            FeedbackAction::Fix => {
                // Fix = positive signal → increase alpha
                (1.0, 0.0)
            }
            FeedbackAction::Dismiss => {
                match dismissal_reason {
                    Some(DismissalReason::FalsePositive) => {
                        // Strong negative signal → increase beta
                        (0.0, 0.5)
                    }
                    Some(DismissalReason::NotApplicable) => {
                        // Moderate negative signal
                        (0.0, 0.25)
                    }
                    Some(DismissalReason::WontFix) => {
                        // No confidence change (intentional deviation)
                        (0.0, 0.0)
                    }
                    Some(DismissalReason::Duplicate) => {
                        // No confidence change
                        (0.0, 0.0)
                    }
                    None => {
                        // Generic dismiss → moderate negative
                        (0.0, 0.25)
                    }
                }
            }
            FeedbackAction::Suppress => {
                // Suppress = mild negative signal
                (0.0, 0.1)
            }
            FeedbackAction::Escalate => {
                // Escalate = positive signal (violation is real)
                (0.5, 0.0)
            }
        }
    }

    /// Apply a feedback action to Bayesian parameters and return updated (alpha, beta, confidence).
    pub fn apply_adjustment(
        &self,
        alpha: f64,
        beta: f64,
        action: FeedbackAction,
        dismissal_reason: Option<DismissalReason>,
    ) -> (f64, f64, f64) {
        let (da, db) = self.compute_adjustment(action, dismissal_reason);
        let new_alpha = (alpha + da).max(0.0);
        let new_beta = (beta + db).max(0.0);
        let confidence = Self::bayesian_confidence(new_alpha, new_beta);
        (new_alpha, new_beta, confidence)
    }

    /// Apply a batch of feedback records to Bayesian parameters.
    /// Returns the final (alpha, beta, confidence) after all adjustments.
    pub fn apply_batch(
        &self,
        mut alpha: f64,
        mut beta: f64,
        records: &[(FeedbackAction, Option<DismissalReason>)],
    ) -> (f64, f64, f64) {
        for (action, reason) in records {
            let (da, db) = self.compute_adjustment(*action, *reason);
            alpha = (alpha + da).max(0.0);
            beta = (beta + db).max(0.0);
        }
        let confidence = Self::bayesian_confidence(alpha, beta);
        (alpha, beta, confidence)
    }

    /// Compute the new confidence from Bayesian parameters.
    pub fn bayesian_confidence(alpha: f64, beta: f64) -> f64 {
        if alpha + beta <= 0.0 {
            return 0.5;
        }
        alpha / (alpha + beta)
    }
}

impl Default for ConfidenceFeedback {
    fn default() -> Self {
        Self::new()
    }
}
