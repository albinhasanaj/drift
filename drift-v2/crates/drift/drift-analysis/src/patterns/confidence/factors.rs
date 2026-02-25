//! 6-factor model: Frequency, Consistency, Age, Spread, Momentum, DataQuality.
//!
//! Each factor contributes to alpha/beta updates on the Beta distribution.
//! Weights: frequency=0.25, consistency=0.20, age=0.10, spread=0.15, momentum=0.15, data_quality=0.15.
//!
//! The DataQuality factor accounts for upstream data quality — resolution confidence,
//! taint precision, detector language coverage. Without it, confidence scores are
//! calibrated against theoretical perfect data rather than actual degraded inputs.

use super::types::MomentumDirection;

/// Weights for the 6-factor model.
pub const WEIGHT_FREQUENCY: f64 = 0.25;
pub const WEIGHT_CONSISTENCY: f64 = 0.20;
pub const WEIGHT_AGE: f64 = 0.10;
pub const WEIGHT_SPREAD: f64 = 0.15;
pub const WEIGHT_MOMENTUM: f64 = 0.15;
pub const WEIGHT_DATA_QUALITY: f64 = 0.15;

/// Default data quality when no upstream quality signal is available.
/// 0.7 = moderate quality assumption (neither optimistic nor pessimistic).
pub const DEFAULT_DATA_QUALITY: f64 = 0.7;

/// Input data for the 6-factor model.
#[derive(Debug, Clone)]
pub struct FactorInput {
    /// Number of pattern occurrences.
    pub occurrences: u64,
    /// Total applicable locations in the same category (sum of all patterns' locations).
    pub total_locations: u64,
    /// Confidence variance across locations (0 = perfectly consistent).
    pub variance: f64,
    /// Days since first seen.
    pub days_since_first_seen: u64,
    /// Number of files containing the pattern.
    pub file_count: u64,
    /// Total files in scope.
    pub total_files: u64,
    /// Momentum direction.
    pub momentum: MomentumDirection,
    /// Upstream data quality signal in [0.0, 1.0].
    /// Computed from resolution confidence, taint precision, detector language coverage.
    /// `None` uses `DEFAULT_DATA_QUALITY` (0.7).
    pub data_quality: Option<f64>,
}

/// Computed factor values (each normalized to [0.0, 1.0]).
#[derive(Debug, Clone)]
pub struct FactorValues {
    pub frequency: f64,
    pub consistency: f64,
    pub age: f64,
    pub spread: f64,
    pub momentum: f64,
    pub data_quality: f64,
}

/// Compute all 6 factors from input data.
pub fn compute_factors(input: &FactorInput) -> FactorValues {
    FactorValues {
        frequency: compute_frequency(input.occurrences, input.total_locations),
        consistency: compute_consistency(input.variance),
        age: compute_age(input.days_since_first_seen),
        spread: compute_spread(input.file_count, input.total_files),
        momentum: compute_momentum(input.momentum),
        data_quality: compute_data_quality(input.data_quality),
    }
}

/// Compute the weighted composite score from factor values.
pub fn weighted_score(factors: &FactorValues) -> f64 {
    let score = factors.frequency * WEIGHT_FREQUENCY
        + factors.consistency * WEIGHT_CONSISTENCY
        + factors.age * WEIGHT_AGE
        + factors.spread * WEIGHT_SPREAD
        + factors.momentum * WEIGHT_MOMENTUM
        + factors.data_quality * WEIGHT_DATA_QUALITY;
    score.clamp(0.0, 1.0)
}

/// Convert factor values into alpha/beta adjustments for the Beta distribution.
///
/// The weighted score determines how much evidence to add:
/// - High score → more alpha (successes)
/// - Low score → more beta (failures)
///
/// `sample_size` controls the strength of the update (more data → stronger update).
pub fn factors_to_alpha_beta(factors: &FactorValues, sample_size: u64) -> (f64, f64) {
    let score = weighted_score(factors);
    let n = (sample_size as f64).max(1.0);

    // Sample-size-adaptive blending: larger samples → stronger Bayesian update
    let blend_weight = (n / (n + 10.0)).min(1.0); // Sigmoid-like ramp

    let alpha_contribution = score * blend_weight * n;
    let beta_contribution = (1.0 - score) * blend_weight * n;

    (alpha_contribution.max(0.0), beta_contribution.max(0.0))
}

/// Factor 1: Frequency — how often the pattern appears.
fn compute_frequency(occurrences: u64, total_locations: u64) -> f64 {
    if total_locations == 0 {
        return 0.0;
    }
    let freq = occurrences as f64 / total_locations as f64;
    freq.clamp(0.0, 1.0)
}

/// Factor 2: Consistency — how uniformly across files (1 - variance).
fn compute_consistency(variance: f64) -> f64 {
    if !variance.is_finite() || variance < 0.0 {
        return 1.0; // Treat invalid variance as perfectly consistent
    }
    (1.0 - variance).clamp(0.0, 1.0)
}

/// Factor 3: Age — how long established (linear ramp over 30 days).
fn compute_age(days_since_first_seen: u64) -> f64 {
    const MIN_AGE_FACTOR: f64 = 0.1;
    const MAX_AGE_DAYS: f64 = 30.0;

    if days_since_first_seen == 0 {
        return MIN_AGE_FACTOR;
    }
    let days = days_since_first_seen as f64;
    if days >= MAX_AGE_DAYS {
        return 1.0;
    }
    let normalized = days / MAX_AGE_DAYS;
    MIN_AGE_FACTOR + normalized * (1.0 - MIN_AGE_FACTOR)
}

/// Factor 4: Spread — how many files contain the pattern.
fn compute_spread(file_count: u64, total_files: u64) -> f64 {
    if total_files == 0 {
        return 0.0;
    }
    let spread = file_count as f64 / total_files as f64;
    spread.clamp(0.0, 1.0)
}

/// Factor 5: Momentum — trend direction.
fn compute_momentum(direction: MomentumDirection) -> f64 {
    match direction {
        MomentumDirection::Rising => 0.8,
        MomentumDirection::Stable => 0.5,
        MomentumDirection::Falling => 0.2,
    }
}

/// Factor 6: DataQuality — upstream data quality signal.
///
/// Accounts for resolution confidence, taint precision, detector language coverage.
/// A finding backed by Fuzzy resolution (0.40) should score lower than one backed
/// by ImportBased resolution (0.75). Without this factor, all findings are treated
/// as if they have perfect upstream data.
fn compute_data_quality(data_quality: Option<f64>) -> f64 {
    match data_quality {
        Some(q) => q.clamp(0.0, 1.0),
        None => DEFAULT_DATA_QUALITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_zero_total() {
        assert_eq!(compute_frequency(5, 0), 0.0);
    }

    #[test]
    fn test_frequency_normal() {
        let f = compute_frequency(50, 100);
        assert!((f - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_consistency_zero_variance() {
        assert!((compute_consistency(0.0) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_consistency_high_variance() {
        assert!(compute_consistency(0.8) < 0.3);
    }

    #[test]
    fn test_age_brand_new() {
        assert!((compute_age(0) - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_age_mature() {
        assert!((compute_age(30) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_spread_zero_files() {
        assert_eq!(compute_spread(0, 0), 0.0);
    }

    #[test]
    fn test_momentum_values() {
        assert!(compute_momentum(MomentumDirection::Rising) > compute_momentum(MomentumDirection::Stable));
        assert!(compute_momentum(MomentumDirection::Stable) > compute_momentum(MomentumDirection::Falling));
    }

    #[test]
    fn test_weighted_score_sums_correctly() {
        let sum = WEIGHT_FREQUENCY + WEIGHT_CONSISTENCY + WEIGHT_AGE + WEIGHT_SPREAD + WEIGHT_MOMENTUM + WEIGHT_DATA_QUALITY;
        assert!((sum - 1.0).abs() < 1e-10, "Weights must sum to 1.0, got {}", sum);
    }

    #[test]
    fn test_data_quality_default() {
        assert!((compute_data_quality(None) - DEFAULT_DATA_QUALITY).abs() < 1e-10);
    }

    #[test]
    fn test_data_quality_explicit() {
        assert!((compute_data_quality(Some(0.4)) - 0.4).abs() < 1e-10);
        assert!((compute_data_quality(Some(0.9)) - 0.9).abs() < 1e-10);
    }

    #[test]
    fn test_data_quality_clamped() {
        assert!((compute_data_quality(Some(-0.5)) - 0.0).abs() < 1e-10);
        assert!((compute_data_quality(Some(1.5)) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_low_data_quality_lowers_score() {
        let base_input = FactorInput {
            occurrences: 50,
            total_locations: 100,
            variance: 0.05,
            days_since_first_seen: 30,
            file_count: 40,
            total_files: 100,
            momentum: MomentumDirection::Stable,
            data_quality: Some(0.9),
        };
        let low_quality_input = FactorInput {
            data_quality: Some(0.3),
            ..base_input.clone()
        };

        let high_factors = compute_factors(&base_input);
        let low_factors = compute_factors(&low_quality_input);

        let high_score = weighted_score(&high_factors);
        let low_score = weighted_score(&low_factors);

        assert!(
            high_score > low_score,
            "High data quality ({}) should score higher than low ({})",
            high_score,
            low_score
        );
    }
}
