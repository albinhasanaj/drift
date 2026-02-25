//! 5-factor health scoring.
//!
//! health_score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
//!                + crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100

use std::collections::HashMap;

use super::types::*;

/// Weights for the 5-factor health score (preserved from v1).
const W_CONFIDENCE: f64 = 0.30;
const W_APPROVAL: f64 = 0.20;
const W_COMPLIANCE: f64 = 0.20;
const W_CROSS_VALIDATION: f64 = 0.15;
const W_DUPLICATE_FREE: f64 = 0.15;

/// Computes 5-factor health scores.
pub struct HealthScorer;

impl HealthScorer {
    pub fn new() -> Self {
        Self
    }

    /// Compute the overall health score from pattern data.
    pub fn compute(
        &self,
        patterns: &[PatternAuditData],
        duplicate_groups: &[DuplicateGroup],
    ) -> (f64, HealthBreakdown) {
        if patterns.is_empty() {
            // New project with no data — return sensible default
            let breakdown = HealthBreakdown {
                avg_confidence: 0.0,
                approval_ratio: 0.0,
                compliance_rate: 1.0,
                cross_validation_rate: 0.0,
                duplicate_free_rate: 1.0,
                raw_score: 0.3, // compliance + duplicate_free contribute
            };
            return (30.0, breakdown);
        }

        let avg_confidence = self.compute_avg_confidence(patterns);
        let approval_ratio = self.compute_approval_ratio(patterns);
        let compliance_rate = self.compute_compliance_rate(patterns);
        let cross_validation_rate = self.compute_cross_validation_rate(patterns);
        let duplicate_free_rate =
            self.compute_duplicate_free_rate(patterns, duplicate_groups);

        let raw_score = avg_confidence * W_CONFIDENCE
            + approval_ratio * W_APPROVAL
            + compliance_rate * W_COMPLIANCE
            + cross_validation_rate * W_CROSS_VALIDATION
            + duplicate_free_rate * W_DUPLICATE_FREE;

        let score = (raw_score * 100.0).clamp(0.0, 100.0);

        let breakdown = HealthBreakdown {
            avg_confidence,
            approval_ratio,
            compliance_rate,
            cross_validation_rate,
            duplicate_free_rate,
            raw_score,
        };

        (score, breakdown)
    }

    /// Compute per-category health scores.
    pub fn compute_per_category(
        &self,
        patterns: &[PatternAuditData],
        duplicate_groups: &[DuplicateGroup],
    ) -> HashMap<String, CategoryHealth> {
        let mut categories: HashMap<String, Vec<&PatternAuditData>> = HashMap::new();
        for p in patterns {
            categories.entry(p.category.clone()).or_default().push(p);
        }

        let mut result = HashMap::new();
        for (category, cat_patterns) in &categories {
            let owned: Vec<PatternAuditData> =
                cat_patterns.iter().map(|p| (*p).clone()).collect();
            let (score, _) = self.compute(&owned, duplicate_groups);

            let avg_confidence = if cat_patterns.is_empty() {
                0.0
            } else {
                cat_patterns.iter().map(|p| p.confidence).sum::<f64>()
                    / cat_patterns.len() as f64
            };

            let compliance_rate = self.compute_compliance_rate(&owned);

            result.insert(
                category.clone(),
                CategoryHealth {
                    category: category.clone(),
                    score,
                    pattern_count: cat_patterns.len(),
                    avg_confidence,
                    compliance_rate,
                    trend: TrendDirection::Stable,
                },
            );
        }

        result
    }

    fn compute_avg_confidence(&self, patterns: &[PatternAuditData]) -> f64 {
        if patterns.is_empty() {
            return 0.0;
        }
        patterns.iter().map(|p| p.confidence).sum::<f64>() / patterns.len() as f64
    }

    fn compute_approval_ratio(&self, patterns: &[PatternAuditData]) -> f64 {
        if patterns.is_empty() {
            return 0.0;
        }
        let approved = patterns
            .iter()
            .filter(|p| p.status == PatternStatus::Approved)
            .count();
        approved as f64 / patterns.len() as f64
    }

    fn compute_compliance_rate(&self, patterns: &[PatternAuditData]) -> f64 {
        let total_locations: usize = patterns.iter().map(|p| p.location_count).sum();
        let total_outliers: usize = patterns.iter().map(|p| p.outlier_count).sum();
        if total_locations + total_outliers == 0 {
            return 1.0;
        }
        total_locations as f64 / (total_locations + total_outliers) as f64
    }

    fn compute_cross_validation_rate(&self, patterns: &[PatternAuditData]) -> f64 {
        if patterns.is_empty() {
            return 0.0;
        }
        let in_graph = patterns.iter().filter(|p| p.in_call_graph).count();
        in_graph as f64 / patterns.len() as f64
    }

    fn compute_duplicate_free_rate(
        &self,
        patterns: &[PatternAuditData],
        duplicate_groups: &[DuplicateGroup],
    ) -> f64 {
        if patterns.is_empty() {
            return 1.0;
        }
        let in_dup_groups: usize = duplicate_groups
            .iter()
            .map(|g| g.pattern_ids.len())
            .sum();
        let dup_ratio = in_dup_groups as f64 / patterns.len() as f64;
        (1.0 - dup_ratio).max(0.0)
    }
}

impl Default for HealthScorer {
    fn default() -> Self {
        Self::new()
    }
}
