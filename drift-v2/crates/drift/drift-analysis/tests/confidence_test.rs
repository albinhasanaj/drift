//! Phase 3 Confidence Tests — T3-BAY-01 through T3-BAY-10.

use drift_analysis::engine::types::PatternCategory;
use drift_analysis::patterns::aggregation::types::{AggregatedPattern, PatternLocation};
use drift_analysis::patterns::confidence::beta::{self, BetaPosterior};
use drift_analysis::patterns::confidence::factors::{self, FactorInput};
use drift_analysis::patterns::confidence::momentum::{self, MomentumTracker};
use drift_analysis::patterns::confidence::scorer::{ConfidenceScorer, ScorerConfig};
use drift_analysis::patterns::confidence::types::{ConfidenceScore, ConfidenceTier, MomentumDirection};

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

// ---- T3-BAY-01: Beta posteriors with correct tier classification ----

#[test]
fn t3_bay_01_tier_classification() {
    // Established: posterior_mean ≥ 0.85
    let score = ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable);
    assert_eq!(score.tier, ConfidenceTier::Established);
    assert!(score.posterior_mean >= 0.85);

    // Emerging: 0.70 ≤ posterior_mean < 0.85
    let score = ConfidenceScore::from_params(75.0, 25.0, MomentumDirection::Stable);
    assert_eq!(score.tier, ConfidenceTier::Emerging);
    assert!(score.posterior_mean >= 0.70);
    assert!(score.posterior_mean < 0.85);

    // Tentative: 0.50 ≤ posterior_mean < 0.70
    let score = ConfidenceScore::from_params(55.0, 45.0, MomentumDirection::Stable);
    assert_eq!(score.tier, ConfidenceTier::Tentative);
    assert!(score.posterior_mean >= 0.50);
    assert!(score.posterior_mean < 0.70);

    // Uncertain: posterior_mean < 0.50
    let score = ConfidenceScore::from_params(10.0, 90.0, MomentumDirection::Stable);
    assert_eq!(score.tier, ConfidenceTier::Uncertain);
    assert!(score.posterior_mean < 0.50);
}

// ---- T3-BAY-02: Momentum tracking across 10 scans ----

#[test]
fn t3_bay_02_momentum_tracking() {
    // Rising trend
    let mut rising = MomentumTracker::new();
    for i in 0..10 {
        rising.record(10 + i * 5);
    }
    assert_eq!(rising.direction(), MomentumDirection::Rising);

    // Falling trend
    let mut falling = MomentumTracker::new();
    for i in 0..10 {
        falling.record(100 - i * 10);
    }
    assert_eq!(falling.direction(), MomentumDirection::Falling);

    // Stable trend
    let mut stable = MomentumTracker::new();
    for _ in 0..10 {
        stable.record(50);
    }
    assert_eq!(stable.direction(), MomentumDirection::Stable);
}

// ---- T3-BAY-03: Temporal decay reduces confidence ----

#[test]
fn t3_bay_03_temporal_decay() {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 30,
    default_data_quality: None,
    });
    let pattern = make_pattern("test", 95, 95);
    let mut tracker = MomentumTracker::new();
    for _ in 0..5 {
        tracker.record(95);
    }

    let fresh = scorer.score_with_momentum(&pattern, &tracker, 30, 0);
    let stale_30 = scorer.score_with_momentum(&pattern, &tracker, 30, 30);
    let stale_60 = scorer.score_with_momentum(&pattern, &tracker, 30, 60);

    assert!(stale_30.posterior_mean < fresh.posterior_mean,
        "30-day stale should have lower confidence: fresh={}, stale_30={}", fresh.posterior_mean, stale_30.posterior_mean);
    assert!(stale_60.posterior_mean <= stale_30.posterior_mean + 1e-12,
        "60-day stale should be equal or lower (within f64 precision): stale_30={}, stale_60={}", stale_30.posterior_mean, stale_60.posterior_mean);

    // Verify temporal decay function directly
    assert_eq!(momentum::temporal_decay(0), 1.0);
    assert_eq!(momentum::temporal_decay(7), 1.0);
    assert!(momentum::temporal_decay(30) < 1.0);
    assert!(momentum::temporal_decay(90) <= 0.1 + 1e-10);
}

// ---- T3-BAY-04: Numerical stability with alpha near zero ----

#[test]
fn t3_bay_04_alpha_near_zero() {
    let mean = BetaPosterior::posterior_mean(0.001, 1000.0);
    assert!(mean.is_finite(), "Mean should be finite");
    assert!((0.0..=1.0).contains(&mean), "Mean should be in [0,1], got {}", mean);
    assert!(mean < 0.01, "Mean should be near zero");

    let var = BetaPosterior::posterior_variance(0.001, 1000.0);
    assert!(var.is_finite(), "Variance should be finite");
    assert!(var >= 0.0, "Variance should be non-negative");

    let (low, high) = beta::credible_interval(0.001, 1000.0, 0.95);
    assert!(low.is_finite() && high.is_finite());
    assert!(low <= high);
    assert!(low >= 0.0 && high <= 1.0);

    // Score should not panic
    let score = ConfidenceScore::from_params(0.001, 1000.0, MomentumDirection::Stable);
    assert!(score.posterior_mean.is_finite());
    assert_eq!(score.tier, ConfidenceTier::Uncertain);
}

// ---- T3-BAY-05: Numerical stability with alpha near infinity ----

#[test]
fn t3_bay_05_alpha_near_infinity() {
    let mean = BetaPosterior::posterior_mean(100000.0, 1.0);
    assert!(mean.is_finite());
    assert!(mean > 0.99, "Mean should approach 1.0, got {}", mean);

    let var = BetaPosterior::posterior_variance(100000.0, 1.0);
    assert!(var.is_finite());
    assert!(var < 0.001, "Variance should be very small");

    let (low, high) = beta::credible_interval(100000.0, 1.0, 0.95);
    assert!(low.is_finite() && high.is_finite());
    assert!(high - low < 0.01, "CI should be very narrow, got width {}", high - low);

    let score = ConfidenceScore::from_params(100000.0, 1.0, MomentumDirection::Stable);
    assert_eq!(score.tier, ConfidenceTier::Established);
}

// ---- T3-BAY-06: Uniform prior (α=β=1) ----

#[test]
fn t3_bay_06_uniform_prior() {
    let (a, b) = BetaPosterior::posterior_params(0, 0);
    assert_eq!(a, 1.0);
    assert_eq!(b, 1.0);

    let mean = BetaPosterior::posterior_mean(1.0, 1.0);
    assert!((mean - 0.5).abs() < 1e-10, "Uniform prior mean should be 0.5");

    let (low, high) = beta::credible_interval(1.0, 1.0, 0.95);
    let width = high - low;
    assert!(width > 0.8, "Uniform prior CI should be wide, got width {}", width);

    let score = ConfidenceScore::uniform_prior();
    assert!((score.posterior_mean - 0.5).abs() < 1e-10);
    assert_eq!(score.tier, ConfidenceTier::Tentative);
}

// ---- T3-BAY-07: 5-factor model independently affects alpha/beta ----

#[test]
fn t3_bay_07_five_factor_independence() {
    let base = FactorInput {
        occurrences: 50,
        total_locations: 100,
        variance: 0.1,
        days_since_first_seen: 15,
        file_count: 50,
        total_files: 100,
        momentum: MomentumDirection::Stable,
        data_quality: None,
    };

    let base_factors = factors::compute_factors(&base);
    let base_score = factors::weighted_score(&base_factors);

    // Toggle frequency up
    let mut high_freq = base.clone();
    high_freq.occurrences = 95;
    let high_freq_score = factors::weighted_score(&factors::compute_factors(&high_freq));
    assert!(high_freq_score > base_score, "Higher frequency should increase score");

    // Toggle consistency up (lower variance)
    let mut high_consistency = base.clone();
    high_consistency.variance = 0.01;
    let high_consistency_score = factors::weighted_score(&factors::compute_factors(&high_consistency));
    assert!(high_consistency_score > base_score, "Lower variance should increase score");

    // Toggle age up
    let mut old = base.clone();
    old.days_since_first_seen = 30;
    let old_score = factors::weighted_score(&factors::compute_factors(&old));
    assert!(old_score > base_score, "Older pattern should increase score");

    // Toggle spread up
    let mut wide = base.clone();
    wide.file_count = 90;
    let wide_score = factors::weighted_score(&factors::compute_factors(&wide));
    assert!(wide_score > base_score, "Wider spread should increase score");

    // Toggle momentum to rising
    let mut rising = base.clone();
    rising.momentum = MomentumDirection::Rising;
    let rising_score = factors::weighted_score(&factors::compute_factors(&rising));
    assert!(rising_score > base_score, "Rising momentum should increase score");

    // Verify factors_to_alpha_beta produces different values
    let (base_a, _base_b) = factors::factors_to_alpha_beta(&base_factors, 50);
    let (high_a, _) = factors::factors_to_alpha_beta(&factors::compute_factors(&high_freq), 50);
    assert!(high_a > base_a, "Higher frequency should increase alpha contribution");
}

// ---- T3-BAY-08: Credible interval narrows with more data ----

#[test]
fn t3_bay_08_ci_narrows_with_data() {
    let (low_small, high_small) = beta::credible_interval(5.0, 5.0, 0.95);
    let (low_large, high_large) = beta::credible_interval(50.0, 50.0, 0.95);
    let (low_huge, high_huge) = beta::credible_interval(500.0, 500.0, 0.95);

    let width_small = high_small - low_small;
    let width_large = high_large - low_large;
    let width_huge = high_huge - low_huge;

    assert!(width_large < width_small,
        "More data should narrow CI: small={}, large={}", width_small, width_large);
    assert!(width_huge < width_large,
        "Even more data should narrow further: large={}, huge={}", width_large, width_huge);
}

// ---- T3-BAY-09: Tier boundary precision ----

#[test]
fn t3_bay_09_tier_boundaries() {
    // Exactly 0.85 → Established
    assert_eq!(ConfidenceTier::from_posterior_mean(0.85), ConfidenceTier::Established);
    // Just below → Emerging
    assert_eq!(ConfidenceTier::from_posterior_mean(0.849), ConfidenceTier::Emerging);
    // Exactly 0.70 → Emerging
    assert_eq!(ConfidenceTier::from_posterior_mean(0.70), ConfidenceTier::Emerging);
    // Just below → Tentative
    assert_eq!(ConfidenceTier::from_posterior_mean(0.699), ConfidenceTier::Tentative);
    // Exactly 0.50 → Tentative
    assert_eq!(ConfidenceTier::from_posterior_mean(0.50), ConfidenceTier::Tentative);
    // Just below → Uncertain
    assert_eq!(ConfidenceTier::from_posterior_mean(0.499), ConfidenceTier::Uncertain);
    // Zero
    assert_eq!(ConfidenceTier::from_posterior_mean(0.0), ConfidenceTier::Uncertain);
    // One
    assert_eq!(ConfidenceTier::from_posterior_mean(1.0), ConfidenceTier::Established);
}

// ---- T3-BAY-10: NaN/Inf input handling ----

#[test]
fn t3_bay_10_nan_inf_handling() {
    // NaN alpha
    let mean = BetaPosterior::posterior_mean(f64::NAN, 1.0);
    assert!(mean.is_finite(), "NaN alpha should produce finite mean");

    // Inf alpha
    let mean = BetaPosterior::posterior_mean(f64::INFINITY, 1.0);
    assert!(mean.is_finite(), "Inf alpha should produce finite mean");

    // NaN beta
    let mean = BetaPosterior::posterior_mean(1.0, f64::NAN);
    assert!(mean.is_finite(), "NaN beta should produce finite mean");

    // Zero sum
    let mean = BetaPosterior::posterior_mean(0.0, 0.0);
    assert!(mean.is_finite(), "Zero sum should produce finite mean");
    assert!((mean - 0.5).abs() < 1e-10, "Zero sum should fallback to 0.5");

    // Negative values
    let (low, high) = beta::credible_interval(-1.0, -1.0, 0.95);
    assert!(low.is_finite() && high.is_finite());

    // Variance with bad inputs
    let var = BetaPosterior::posterior_variance(f64::NAN, 1.0);
    assert!(var.is_finite());

    let var = BetaPosterior::posterior_variance(0.0, 0.0);
    assert!(var.is_finite());
}
