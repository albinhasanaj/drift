//! Auto-approve patterns meeting stability criteria.
//!
//! Criteria: confidence ≥ 0.90, outlierRatio ≤ 0.50, locations ≥ 3

use super::types::*;

/// Auto-approver for patterns meeting stability criteria.
pub struct AutoApprover {
    pub min_confidence: f64,
    pub max_outlier_ratio: f64,
    pub min_locations: usize,
}

impl AutoApprover {
    pub fn new() -> Self {
        Self {
            min_confidence: 0.90,
            max_outlier_ratio: 0.50,
            min_locations: 3,
        }
    }

    /// Classify patterns into auto-approve, review, or likely-false-positive.
    pub fn classify(
        &self,
        patterns: &[PatternAuditData],
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut auto_approved = Vec::new();
        let mut needs_review = Vec::new();
        let mut likely_fp = Vec::new();

        for p in patterns {
            if p.status == PatternStatus::Approved {
                continue; // Already approved
            }

            let outlier_ratio = if p.location_count + p.outlier_count > 0 {
                p.outlier_count as f64 / (p.location_count + p.outlier_count) as f64
            } else {
                0.0
            };

            if p.confidence >= self.min_confidence
                && outlier_ratio <= self.max_outlier_ratio
                && p.location_count >= self.min_locations
                && !p.has_error_issues
            {
                auto_approved.push(p.id.clone());
            } else if p.confidence >= 0.70 {
                needs_review.push(p.id.clone());
            } else {
                likely_fp.push(p.id.clone());
            }
        }

        (auto_approved, needs_review, likely_fp)
    }
}

impl Default for AutoApprover {
    fn default() -> Self {
        Self::new()
    }
}
