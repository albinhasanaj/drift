//! Top-level ConfidenceScorer — takes aggregated patterns, computes Beta posteriors,
//! assigns tiers, tracks momentum.
//!
//! Phase A hardening: 6-factor model with DataQuality, closed feedback loop,
//! symmetric temporal decay, momentum-aware batch scoring, diagnostics.

use std::collections::HashMap;
use std::fmt;

use crate::engine::types::PatternCategory;
use crate::patterns::aggregation::types::AggregatedPattern;

use super::beta::BetaPosterior;
use super::factors::{self, FactorInput};
use super::momentum::{self, MomentumTracker};
use super::types::{ConfidenceScore, ConfidenceTier, MomentumDirection};

/// Trait for retrieving accumulated feedback adjustments for a pattern.
///
/// The feedback loop: when a user marks a finding as Fix/Dismiss/Suppress/Escalate,
/// the enforcement layer computes (alpha_delta, beta_delta) via ConfidenceFeedback.
/// Those deltas are stored and retrieved here to adjust future confidence scores.
pub trait FeedbackStore: Send + Sync {
    /// Get all accumulated (alpha_delta, beta_delta) adjustments for a pattern.
    fn get_adjustments(&self, pattern_id: &str) -> Vec<(f64, f64)>;
}

/// In-memory feedback store for tests and single-run usage.
#[derive(Debug, Default, Clone)]
pub struct InMemoryFeedbackStore {
    adjustments: HashMap<String, Vec<(f64, f64)>>,
}

impl InMemoryFeedbackStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a feedback adjustment for a pattern.
    pub fn record(&mut self, pattern_id: &str, alpha_delta: f64, beta_delta: f64) {
        self.adjustments
            .entry(pattern_id.to_string())
            .or_default()
            .push((alpha_delta, beta_delta));
    }
}

impl FeedbackStore for InMemoryFeedbackStore {
    fn get_adjustments(&self, pattern_id: &str) -> Vec<(f64, f64)> {
        self.adjustments.get(pattern_id).cloned().unwrap_or_default()
    }
}

/// Configuration for the confidence scorer.
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// Total files in the project (for spread calculation).
    pub total_files: u64,
    /// Default days since first seen (when unknown).
    pub default_age_days: u64,
    /// Default upstream data quality when not specified per-pattern.
    /// `None` uses the factor model's DEFAULT_DATA_QUALITY (0.7).
    pub default_data_quality: Option<f64>,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            total_files: 100,
            default_age_days: 7,
            default_data_quality: None,
        }
    }
}

/// The top-level confidence scorer.
///
/// Takes aggregated patterns and produces ConfidenceScore for each.
/// Supports optional feedback store for closed-loop confidence adjustment.
pub struct ConfidenceScorer {
    config: ScorerConfig,
    feedback_store: Option<Box<dyn FeedbackStore>>,
}

impl ConfidenceScorer {
    /// Create a new scorer with the given configuration.
    pub fn new(config: ScorerConfig) -> Self {
        Self {
            config,
            feedback_store: None,
        }
    }

    /// Create a scorer with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ScorerConfig::default())
    }

    /// Attach a feedback store for closed-loop confidence adjustment.
    pub fn with_feedback_store(mut self, store: Box<dyn FeedbackStore>) -> Self {
        self.feedback_store = Some(store);
        self
    }

    /// Score a single aggregated pattern.
    ///
    /// Combines Beta distribution posterior with 6-factor model.
    /// `category_total_locations`: sum of all patterns' location counts in the same category.
    /// `data_quality`: upstream data quality signal in [0.0, 1.0], or None for default.
    pub fn score(
        &self,
        pattern: &AggregatedPattern,
        momentum: MomentumDirection,
        days_since_first_seen: u64,
        category_total_locations: Option<u64>,
        data_quality: Option<f64>,
    ) -> ConfidenceScore {
        // Step 1: Compute raw Beta posterior from observation counts
        let total_observations = self.config.total_files;
        let successes = pattern.file_spread as u64;
        let (base_alpha, base_beta) = BetaPosterior::posterior_params(successes, total_observations);

        // Step 2: Compute 6-factor adjustments
        // Use category-relative denominator for frequency (PI-CONF-11)
        let total_locs = category_total_locations
            .unwrap_or(total_observations)
            .max(1);

        let factor_input = FactorInput {
            occurrences: pattern.location_count as u64,
            total_locations: total_locs,
            variance: pattern.confidence_stddev.powi(2),
            days_since_first_seen,
            file_count: pattern.file_spread as u64,
            total_files: self.config.total_files,
            momentum,
            data_quality: data_quality.or(self.config.default_data_quality),
        };

        let factor_values = factors::compute_factors(&factor_input);
        let (alpha_adj, beta_adj) = factors::factors_to_alpha_beta(
            &factor_values,
            pattern.location_count as u64,
        );

        // Step 3: Combine base posterior with factor adjustments
        let mut final_alpha = base_alpha + alpha_adj;
        let mut final_beta = base_beta + beta_adj;

        // Step 4: Apply feedback adjustments if store is available (PI-CONF-05/06/07)
        if let Some(ref store) = self.feedback_store {
            let adjustments = store.get_adjustments(&pattern.pattern_id);
            for (alpha_delta, beta_delta) in &adjustments {
                final_alpha = (final_alpha + alpha_delta).max(0.01);
                final_beta = (final_beta + beta_delta).max(0.01);
            }
        }

        // Step 5: Build the score
        ConfidenceScore::from_params(final_alpha, final_beta, momentum)
    }

    /// Score all patterns in a batch with per-pattern momentum and category-relative frequency.
    ///
    /// `momentum_trackers`: optional map of pattern_id -> MomentumTracker.
    /// When provided, each pattern gets its actual momentum direction.
    /// When absent, all patterns get MomentumDirection::Stable.
    pub fn score_batch(
        &self,
        patterns: &[AggregatedPattern],
        momentum_trackers: Option<&HashMap<String, MomentumTracker>>,
    ) -> Vec<(String, ConfidenceScore)> {
        // Compute per-category total locations for frequency factor (PI-CONF-11)
        let mut category_totals: HashMap<PatternCategory, u64> = HashMap::new();
        for p in patterns {
            *category_totals.entry(p.category).or_insert(0) += p.location_count as u64;
        }

        patterns
            .iter()
            .map(|p| {
                let momentum = momentum_trackers
                    .and_then(|trackers| trackers.get(&p.pattern_id))
                    .map(|t| t.direction())
                    .unwrap_or(MomentumDirection::Stable);

                let cat_total = category_totals.get(&p.category).copied();

                let score = self.score(
                    p,
                    momentum,
                    self.config.default_age_days,
                    cat_total,
                    None,
                );
                (p.pattern_id.clone(), score)
            })
            .collect()
    }

    /// Score with full context including momentum tracker.
    pub fn score_with_momentum(
        &self,
        pattern: &AggregatedPattern,
        tracker: &MomentumTracker,
        days_since_first_seen: u64,
        days_since_last_seen: u64,
    ) -> ConfidenceScore {
        let momentum = tracker.direction();
        let mut score = self.score(pattern, momentum, days_since_first_seen, None, None);

        // Apply temporal decay if pattern hasn't been seen recently (PI-CONF-08)
        // Decay BOTH alpha and beta proportionally to preserve posterior_mean
        // but widen the credible interval (reduce effective sample size).
        let decay = momentum::temporal_decay(days_since_last_seen);
        if decay < 1.0 {
            score.alpha *= decay;
            score.beta *= decay;
            // Recompute derived values
            score.posterior_mean = BetaPosterior::posterior_mean(score.alpha, score.beta);
            score.tier = ConfidenceTier::from_posterior_mean(score.posterior_mean);
            score.credible_interval = super::beta::credible_interval(score.alpha, score.beta, 0.95);
        }

        score.momentum = momentum;
        score
    }

    /// Compute diagnostics for a batch of scored patterns.
    pub fn diagnostics(
        &self,
        scores: &[(String, ConfidenceScore)],
        patterns: &[AggregatedPattern],
    ) -> ConfidenceDiagnostics {
        let total = scores.len();
        let mut tier_counts = HashMap::new();
        let mut category_scores: HashMap<PatternCategory, Vec<f64>> = HashMap::new();
        let mut total_mean = 0.0;
        let mut total_ci_width = 0.0;
        let mut feedback_adjusted = 0usize;

        for (i, (pattern_id, score)) in scores.iter().enumerate() {
            *tier_counts.entry(score.tier).or_insert(0usize) += 1;
            total_mean += score.posterior_mean;
            total_ci_width += score.credible_interval.1 - score.credible_interval.0;

            if let Some(ref store) = self.feedback_store {
                if !store.get_adjustments(pattern_id).is_empty() {
                    feedback_adjusted += 1;
                }
            }

            if let Some(p) = patterns.get(i) {
                category_scores
                    .entry(p.category)
                    .or_default()
                    .push(score.posterior_mean);
            }
        }

        let avg_mean = if total > 0 { total_mean / total as f64 } else { 0.0 };
        let avg_ci_width = if total > 0 { total_ci_width / total as f64 } else { 0.0 };

        let established_count = tier_counts.get(&ConfidenceTier::Established).copied().unwrap_or(0);
        let inflation_warning = total > 0 && (established_count as f64 / total as f64) > 0.8;

        let per_category: HashMap<PatternCategory, CategoryConfidenceSummary> = category_scores
            .into_iter()
            .map(|(cat, vals)| {
                let count = vals.len();
                let avg = vals.iter().sum::<f64>() / count as f64;
                (cat, CategoryConfidenceSummary { count, avg_posterior_mean: avg })
            })
            .collect();

        ConfidenceDiagnostics {
            total_patterns: total,
            tier_distribution: tier_counts,
            avg_posterior_mean: avg_mean,
            avg_ci_width,
            feedback_adjusted_count: feedback_adjusted,
            inflation_warning,
            per_category,
        }
    }
}

/// Diagnostics summary for a batch of confidence scores.
#[derive(Debug, Clone)]
pub struct ConfidenceDiagnostics {
    /// Total patterns scored.
    pub total_patterns: usize,
    /// Distribution of tiers.
    pub tier_distribution: HashMap<ConfidenceTier, usize>,
    /// Average posterior mean across all patterns.
    pub avg_posterior_mean: f64,
    /// Average credible interval width.
    pub avg_ci_width: f64,
    /// Number of patterns with feedback adjustments applied.
    pub feedback_adjusted_count: usize,
    /// Warning: >80% of patterns are Established (likely inflated).
    pub inflation_warning: bool,
    /// Per-category confidence summary.
    pub per_category: HashMap<PatternCategory, CategoryConfidenceSummary>,
}

impl fmt::Display for ConfidenceDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConfidenceDiagnostics {{ total={}, avg_mean={:.3}, avg_ci_width={:.3}, feedback_adjusted={}, inflation_warning={} }}",
            self.total_patterns,
            self.avg_posterior_mean,
            self.avg_ci_width,
            self.feedback_adjusted_count,
            self.inflation_warning,
        )
    }
}

/// Per-category confidence summary.
#[derive(Debug, Clone)]
pub struct CategoryConfidenceSummary {
    pub count: usize,
    pub avg_posterior_mean: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::PatternCategory;
    use crate::patterns::aggregation::types::PatternLocation;

    fn make_pattern(id: &str, locations: u32, files: u32) -> AggregatedPattern {
        let locs: Vec<PatternLocation> = (0..locations)
            .map(|i| PatternLocation {
                file: format!("file_{}.ts", i % files),
                line: i + 1,
                column: 0,
                confidence: 0.9,
                is_outlier: false,
                matched_text: None,
            })
            .collect();
        AggregatedPattern {
            pattern_id: id.to_string(),
            category: PatternCategory::Structural,
            location_count: locations,
            outlier_count: 0,
            file_spread: files,
            hierarchy: None,
            locations: locs,
            aliases: Vec::new(),
            merged_from: Vec::new(),
            confidence_mean: 0.9,
            confidence_stddev: 0.05,
            confidence_values: vec![0.9; locations as usize],
            is_dirty: false,
            location_hash: 0,
        }
    }

    fn make_config(total_files: u64, age_days: u64) -> ScorerConfig {
        ScorerConfig {
            total_files,
            default_age_days: age_days,
            default_data_quality: None,
        }
    }

    #[test]
    fn test_score_high_spread_pattern() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let pattern = make_pattern("test", 95, 95);
        let score = scorer.score(&pattern, MomentumDirection::Rising, 30, None, None);
        assert_eq!(score.tier, ConfidenceTier::Established);
        assert!(score.posterior_mean >= 0.85);
    }

    #[test]
    fn test_score_low_spread_pattern() {
        let scorer = ConfidenceScorer::new(make_config(100, 7));
        let pattern = make_pattern("test", 3, 2);
        let score = scorer.score(&pattern, MomentumDirection::Stable, 1, None, None);
        assert!(score.tier != ConfidenceTier::Established);
    }

    #[test]
    fn test_score_batch() {
        let scorer = ConfidenceScorer::with_defaults();
        let patterns = vec![
            make_pattern("a", 50, 40),
            make_pattern("b", 10, 5),
        ];
        let scores = scorer.score_batch(&patterns, None);
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0].0, "a");
        assert_eq!(scores[1].0, "b");
    }

    #[test]
    fn test_temporal_decay_widens_ci() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let pattern = make_pattern("test", 90, 85);
        let mut tracker = MomentumTracker::new();
        for _ in 0..5 {
            tracker.record(90);
        }

        let fresh = scorer.score_with_momentum(&pattern, &tracker, 30, 0);
        let stale = scorer.score_with_momentum(&pattern, &tracker, 30, 60);

        // Symmetric decay preserves posterior_mean but widens CI
        let fresh_width = fresh.credible_interval.1 - fresh.credible_interval.0;
        let stale_width = stale.credible_interval.1 - stale.credible_interval.0;
        assert!(
            stale_width > fresh_width,
            "Stale CI ({:.4}) should be wider than fresh CI ({:.4})",
            stale_width,
            fresh_width
        );
    }

    // --- PIT-CONF-01: data_quality=0.4 scores lower than data_quality=0.9 ---
    #[test]
    fn test_data_quality_affects_score() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let pattern = make_pattern("test", 50, 40);

        let high_q = scorer.score(&pattern, MomentumDirection::Stable, 30, None, Some(0.9));
        let low_q = scorer.score(&pattern, MomentumDirection::Stable, 30, None, Some(0.4));

        assert!(
            high_q.posterior_mean > low_q.posterior_mean,
            "High data quality ({:.4}) should score higher than low ({:.4})",
            high_q.posterior_mean,
            low_q.posterior_mean
        );
    }

    // --- PIT-CONF-03: 5 FP dismissals lower confidence ---
    #[test]
    fn test_feedback_fp_dismissals_lower_confidence() {
        let mut store = InMemoryFeedbackStore::new();
        // 5 FalsePositive dismissals: each adds (0.0, 0.5) per ConfidenceFeedback
        for _ in 0..5 {
            store.record("test", 0.0, 0.5);
        }

        let scorer_no_fb = ConfidenceScorer::new(make_config(100, 30));
        let scorer_with_fb = ConfidenceScorer::new(make_config(100, 30))
            .with_feedback_store(Box::new(store));

        let pattern = make_pattern("test", 50, 40);
        let no_fb = scorer_no_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);
        let with_fb = scorer_with_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);

        assert!(
            with_fb.posterior_mean < no_fb.posterior_mean,
            "5 FP dismissals should lower confidence: no_fb={:.4}, with_fb={:.4}",
            no_fb.posterior_mean,
            with_fb.posterior_mean
        );
    }

    // --- PIT-CONF-04: 5 Fix actions raise confidence ---
    #[test]
    fn test_feedback_fix_actions_raise_confidence() {
        let mut store = InMemoryFeedbackStore::new();
        // 5 Fix actions: each adds (1.0, 0.0) per ConfidenceFeedback
        for _ in 0..5 {
            store.record("test", 1.0, 0.0);
        }

        let scorer_no_fb = ConfidenceScorer::new(make_config(100, 30));
        let scorer_with_fb = ConfidenceScorer::new(make_config(100, 30))
            .with_feedback_store(Box::new(store));

        let pattern = make_pattern("test", 20, 10);
        let no_fb = scorer_no_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);
        let with_fb = scorer_with_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);

        assert!(
            with_fb.posterior_mean > no_fb.posterior_mean,
            "5 Fix actions should raise confidence: no_fb={:.4}, with_fb={:.4}",
            no_fb.posterior_mean,
            with_fb.posterior_mean
        );
    }

    // --- PIT-CONF-05: WontFix does not change confidence ---
    #[test]
    fn test_feedback_wontfix_no_change() {
        let mut store = InMemoryFeedbackStore::new();
        // WontFix: (0.0, 0.0) per ConfidenceFeedback
        for _ in 0..5 {
            store.record("test", 0.0, 0.0);
        }

        let scorer_no_fb = ConfidenceScorer::new(make_config(100, 30));
        let scorer_with_fb = ConfidenceScorer::new(make_config(100, 30))
            .with_feedback_store(Box::new(store));

        let pattern = make_pattern("test", 50, 40);
        let no_fb = scorer_no_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);
        let with_fb = scorer_with_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);

        assert!(
            (with_fb.posterior_mean - no_fb.posterior_mean).abs() < 1e-10,
            "WontFix should not change confidence: no_fb={:.4}, with_fb={:.4}",
            no_fb.posterior_mean,
            with_fb.posterior_mean
        );
    }

    // --- PIT-CONF-06: Temporal decay preserves posterior_mean, widens CI ---
    #[test]
    fn test_temporal_decay_symmetric_preserves_mean() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let pattern = make_pattern("test", 80, 70);
        let mut tracker = MomentumTracker::new();
        for _ in 0..5 {
            tracker.record(80);
        }

        let fresh = scorer.score_with_momentum(&pattern, &tracker, 30, 0);
        let stale = scorer.score_with_momentum(&pattern, &tracker, 30, 30);

        // Posterior mean should be approximately preserved (both alpha and beta decay)
        assert!(
            (fresh.posterior_mean - stale.posterior_mean).abs() < 0.05,
            "Symmetric decay should approximately preserve posterior_mean: fresh={:.4}, stale={:.4}",
            fresh.posterior_mean,
            stale.posterior_mean
        );

        // CI should widen (less effective sample size)
        let fresh_width = fresh.credible_interval.1 - fresh.credible_interval.0;
        let stale_width = stale.credible_interval.1 - stale.credible_interval.0;
        assert!(
            stale_width > fresh_width,
            "Stale CI should be wider: fresh_width={:.4}, stale_width={:.4}",
            fresh_width,
            stale_width
        );
    }

    // --- PIT-CONF-07: score_batch with trackers: Rising > Falling ---
    #[test]
    fn test_score_batch_with_momentum_trackers() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let patterns = vec![
            make_pattern("rising", 50, 40),
            make_pattern("falling", 50, 40),
        ];

        let mut trackers = HashMap::new();
        let mut rising_tracker = MomentumTracker::new();
        for i in 0..10 {
            rising_tracker.record(10 + i * 5);
        }
        trackers.insert("rising".to_string(), rising_tracker);

        let mut falling_tracker = MomentumTracker::new();
        for i in 0..10 {
            falling_tracker.record(100 - i * 10);
        }
        trackers.insert("falling".to_string(), falling_tracker);

        let scores = scorer.score_batch(&patterns, Some(&trackers));
        let rising_score = &scores[0].1;
        let falling_score = &scores[1].1;

        assert!(
            rising_score.posterior_mean > falling_score.posterior_mean,
            "Rising ({:.4}) should score higher than Falling ({:.4})",
            rising_score.posterior_mean,
            falling_score.posterior_mean
        );
    }

    // --- PIT-CONF-08: Frequency factor uses category-relative denominator ---
    #[test]
    fn test_frequency_category_relative() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let pattern = make_pattern("test", 50, 40);

        // 50 locations in category of 100 total -> frequency = 0.5
        let score_small_cat = scorer.score(
            &pattern, MomentumDirection::Stable, 30, Some(100), None,
        );
        // 50 locations in category of 500 total -> frequency = 0.1
        let score_large_cat = scorer.score(
            &pattern, MomentumDirection::Stable, 30, Some(500), None,
        );

        assert!(
            score_small_cat.posterior_mean > score_large_cat.posterior_mean,
            "Pattern in smaller category ({:.4}) should score higher than in larger ({:.4})",
            score_small_cat.posterior_mean,
            score_large_cat.posterior_mean
        );
    }

    // --- PIT-CONF-10: Diagnostics warn when >80% Established ---
    #[test]
    fn test_diagnostics_inflation_warning() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        // Score each pattern individually with high data quality and its own
        // location count as category total (simulating single-pattern categories)
        let patterns: Vec<AggregatedPattern> = (0..10)
            .map(|i| make_pattern(&format!("p{}", i), 99, 99))
            .collect();
        let scores: Vec<(String, ConfidenceScore)> = patterns
            .iter()
            .map(|p| {
                let s = scorer.score(
                    p,
                    MomentumDirection::Rising,
                    30,
                    Some(p.location_count as u64), // category total = own locations
                    Some(1.0),                      // perfect data quality
                );
                (p.pattern_id.clone(), s)
            })
            .collect();
        let diag = scorer.diagnostics(&scores, &patterns);

        assert_eq!(diag.total_patterns, 10);
        assert!(
            diag.inflation_warning,
            "Should warn about inflation when most patterns are Established. Tier dist: {:?}",
            diag.tier_distribution
        );
    }

    // --- PIT-CONF-13: FeedbackStore round-trip ---
    #[test]
    fn test_feedback_store_round_trip() {
        let mut store = InMemoryFeedbackStore::new();
        store.record("p1", 1.0, 0.0);
        store.record("p1", 0.0, 0.5);
        store.record("p2", 0.5, 0.0);

        let p1_adj = store.get_adjustments("p1");
        assert_eq!(p1_adj.len(), 2);
        assert_eq!(p1_adj[0], (1.0, 0.0));
        assert_eq!(p1_adj[1], (0.0, 0.5));

        let p2_adj = store.get_adjustments("p2");
        assert_eq!(p2_adj.len(), 1);

        let empty = store.get_adjustments("nonexistent");
        assert!(empty.is_empty());
    }

    // --- PIT-CONF-15: Uniform prior = Tentative tier ---
    #[test]
    fn test_uniform_prior_is_tentative() {
        let score = ConfidenceScore::uniform_prior();
        assert_eq!(score.tier, ConfidenceTier::Tentative);
        assert!((score.posterior_mean - 0.5).abs() < 1e-10);
    }

    // --- PIT-CONF-17: score_with_feedback with empty feedback = score ---
    #[test]
    fn test_empty_feedback_same_as_no_feedback() {
        let store = InMemoryFeedbackStore::new();
        let scorer_no_fb = ConfidenceScorer::new(make_config(100, 30));
        let scorer_with_fb = ConfidenceScorer::new(make_config(100, 30))
            .with_feedback_store(Box::new(store));

        let pattern = make_pattern("test", 50, 40);
        let no_fb = scorer_no_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);
        let with_fb = scorer_with_fb.score(&pattern, MomentumDirection::Stable, 30, None, None);

        assert!(
            (no_fb.posterior_mean - with_fb.posterior_mean).abs() < 1e-10,
            "Empty feedback store should produce same result: no_fb={:.4}, with_fb={:.4}",
            no_fb.posterior_mean,
            with_fb.posterior_mean
        );
    }

    // --- PIT-CONF-18: Extreme feedback does not produce negative alpha ---
    #[test]
    fn test_extreme_feedback_no_negative_alpha() {
        let mut store = InMemoryFeedbackStore::new();
        // 100 FP dismissals: each adds (0.0, 0.5)
        for _ in 0..100 {
            store.record("test", 0.0, 0.5);
        }

        let scorer = ConfidenceScorer::new(make_config(100, 30))
            .with_feedback_store(Box::new(store));

        let pattern = make_pattern("test", 5, 3);
        let score = scorer.score(&pattern, MomentumDirection::Stable, 30, None, None);

        assert!(
            score.alpha > 0.0,
            "Alpha should never be negative or zero: {}",
            score.alpha
        );
        assert!(
            score.beta > 0.0,
            "Beta should never be negative or zero: {}",
            score.beta
        );
        assert!(score.posterior_mean.is_finite());
    }

    // --- PIT-CONF-02: Weights sum to 1.0 (tested in factors.rs, cross-check here) ---
    #[test]
    fn test_weights_sum() {
        use super::super::factors::*;
        let sum = WEIGHT_FREQUENCY + WEIGHT_CONSISTENCY + WEIGHT_AGE
            + WEIGHT_SPREAD + WEIGHT_MOMENTUM + WEIGHT_DATA_QUALITY;
        assert!((sum - 1.0).abs() < 1e-10, "Weights must sum to 1.0, got {}", sum);
    }

    // --- PIT-CONF-12: Calibration test: Fuzzy-backed < ImportBased-backed ---
    #[test]
    fn test_calibration_fuzzy_vs_import_based() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));
        let pattern = make_pattern("test", 50, 40);

        // Fuzzy resolution: data_quality = 0.40
        let fuzzy = scorer.score(&pattern, MomentumDirection::Stable, 30, None, Some(0.40));
        // ImportBased resolution: data_quality = 0.75
        let import = scorer.score(&pattern, MomentumDirection::Stable, 30, None, Some(0.75));

        assert!(
            import.posterior_mean > fuzzy.posterior_mean,
            "ImportBased ({:.4}) should score higher than Fuzzy ({:.4})",
            import.posterior_mean,
            fuzzy.posterior_mean
        );
    }

    // --- PIT-CONF-11: Per-category summary has different averages ---
    #[test]
    fn test_diagnostics_per_category() {
        let scorer = ConfidenceScorer::new(make_config(100, 30));

        let mut p1 = make_pattern("structural", 80, 70);
        p1.category = PatternCategory::Structural;

        let mut p2 = make_pattern("security", 10, 5);
        p2.category = PatternCategory::Security;

        let patterns = vec![p1, p2];
        let scores = scorer.score_batch(&patterns, None);
        let diag = scorer.diagnostics(&scores, &patterns);

        assert!(diag.per_category.len() >= 2, "Should have at least 2 categories");
        let structural = diag.per_category.get(&PatternCategory::Structural).unwrap();
        let security = diag.per_category.get(&PatternCategory::Security).unwrap();
        assert!(
            structural.avg_posterior_mean != security.avg_posterior_mean,
            "Different categories should have different averages"
        );
    }
}
