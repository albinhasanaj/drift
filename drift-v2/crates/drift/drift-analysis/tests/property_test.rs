#![allow(clippy::manual_range_contains, unused_variables)]
//! Phase 3 — Property-Based Tests
//!
//! Tests invariants that must hold for ANY valid input, not just hand-crafted cases.
//! Catches the class of bugs nobody thought to write a test for.

use drift_analysis::patterns::aggregation::pipeline::AggregationPipeline;
use drift_analysis::patterns::aggregation::similarity::jaccard_similarity;
use drift_analysis::patterns::aggregation::types::{AggregatedPattern, PatternLocation};
use drift_analysis::patterns::confidence::beta::{self, BetaPosterior};
use drift_analysis::patterns::confidence::scorer::{ConfidenceScorer, ScorerConfig};
use drift_analysis::patterns::confidence::types::MomentumDirection;
use drift_analysis::patterns::outliers::selector::OutlierDetector;

use drift_analysis::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use drift_core::types::collections::FxHashSet;
use smallvec::smallvec;

// ─── Helpers ───────────────────────────────────────────────────────────────

fn make_match(id: &str, file: &str, line: u32) -> PatternMatch {
    PatternMatch {
        pattern_id: id.to_string(),
        file: file.to_string(),
        line,
        column: 0,
        matched_text: "x".to_string(),
        confidence: 0.9,
        category: PatternCategory::Structural,
        cwe_ids: smallvec![],
        owasp: None,
        detection_method: DetectionMethod::AstVisitor,
    }
}

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

// ═══════════════════════════════════════════════════════════════════════════
// BETA DISTRIBUTION INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════

/// For any valid (alpha, beta): 0 ≤ mean ≤ 1, variance ≥ 0, CI_low ≤ CI_high
#[test]
fn property_beta_invariants_sweep() {
    let alphas = [0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 1000.0, 100_000.0];
    let betas = [0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 1000.0, 100_000.0];

    for &a in &alphas {
        for &b in &betas {
            let mean = BetaPosterior::posterior_mean(a, b);
            assert!(mean >= 0.0 && mean <= 1.0, "mean out of [0,1] for a={}, b={}: {}", a, b, mean);
            assert!(mean.is_finite(), "NaN/Inf mean for a={}, b={}", a, b);

            let var = BetaPosterior::posterior_variance(a, b);
            assert!(var >= 0.0, "negative variance for a={}, b={}: {}", a, b, var);
            assert!(var.is_finite(), "NaN/Inf variance for a={}, b={}", a, b);

            let (lo, hi) = beta::credible_interval(a, b, 0.95);
            assert!(lo <= hi, "inverted CI for a={}, b={}: [{}, {}]", a, b, lo, hi);
            assert!(lo >= 0.0 && hi <= 1.0, "CI out of [0,1] for a={}, b={}", a, b);
        }
    }
}

/// Posterior mean must converge to k/n as evidence grows
#[test]
fn property_beta_mean_converges_to_frequency() {
    for ratio in [0.1, 0.25, 0.5, 0.75, 0.9] {
        for n in [100u64, 1000, 10_000] {
            let k = (n as f64 * ratio) as u64;
            let (a, b) = BetaPosterior::posterior_params(k, n);
            let mean = BetaPosterior::posterior_mean(a, b);
            let expected = k as f64 / n as f64;
            assert!(
                (mean - expected).abs() < 0.05,
                "Mean {} should converge to {} for k={}, n={}",
                mean, expected, k, n
            );
        }
    }
}

/// CI width must decrease as evidence increases (for same ratio)
#[test]
fn property_beta_ci_narrows_with_evidence() {
    for ratio in [0.3, 0.5, 0.7] {
        let mut prev_width = f64::MAX;
        for n in [5u64, 10, 50, 100, 500, 1000] {
            let k = (n as f64 * ratio) as u64;
            let (a, b) = BetaPosterior::posterior_params(k, n);
            let (lo, hi) = beta::credible_interval(a, b, 0.95);
            let width = hi - lo;
            assert!(
                width <= prev_width + 1e-10,
                "CI should narrow: ratio={}, n={}, width={}, prev={}",
                ratio, n, width, prev_width
            );
            prev_width = width;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// JACCARD SIMILARITY INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════

/// J(A, A) = 1.0 for any non-empty set
#[test]
fn property_jaccard_self_similarity() {
    for size in [1, 5, 50, 500] {
        let set: FxHashSet<String> = (0..size).map(|i| format!("elem_{}", i)).collect();
        let sim = jaccard_similarity(&set, &set);
        assert!(
            (sim - 1.0).abs() < 1e-10,
            "J(A,A) should be 1.0 for size={}, got {}",
            size, sim
        );
    }
}

/// J(A, B) = J(B, A) — symmetry
#[test]
fn property_jaccard_symmetry() {
    for overlap in [0, 10, 50, 90, 100] {
        let a: FxHashSet<String> = (0..100).map(|i| format!("a_{}", i)).collect();
        let b: FxHashSet<String> = (0..100)
            .map(|i| {
                if i < overlap {
                    format!("a_{}", i) // shared
                } else {
                    format!("b_{}", i) // unique to b
                }
            })
            .collect();

        let ab = jaccard_similarity(&a, &b);
        let ba = jaccard_similarity(&b, &a);
        assert!(
            (ab - ba).abs() < 1e-15,
            "J(A,B) != J(B,A): {} vs {} for overlap={}",
            ab, ba, overlap
        );
    }
}

/// 0 ≤ J(A, B) ≤ 1 for any sets
#[test]
fn property_jaccard_bounded() {
    for size_a in [0, 1, 10, 100] {
        for size_b in [0, 1, 10, 100] {
            let a: FxHashSet<String> = (0..size_a).map(|i| format!("a_{}", i)).collect();
            let b: FxHashSet<String> = (0..size_b).map(|i| format!("b_{}", i)).collect();
            let sim = jaccard_similarity(&a, &b);
            assert!(
                sim >= 0.0 && sim <= 1.0,
                "J out of [0,1]: {} for |A|={}, |B|={}",
                sim, size_a, size_b
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIDENCE SCORER INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Higher file spread → higher confidence (all else equal)
#[test]
fn property_confidence_monotonic_in_spread() {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 14,
    default_data_quality: None,
    });

    let mut prev_mean = 0.0;
    for spread in [1, 5, 10, 25, 50, 75, 95] {
        let pattern = make_pattern("test", spread as u32, spread as u32);
        let score = scorer.score(&pattern, MomentumDirection::Stable, 14, None, None);
        assert!(
            score.posterior_mean >= prev_mean - 0.01, // small tolerance for factor interactions
            "Confidence should increase with spread: spread={}, mean={}, prev={}",
            spread, score.posterior_mean, prev_mean
        );
        prev_mean = score.posterior_mean;
    }
}

/// Score must always be in [0, 1] regardless of inputs
#[test]
fn property_confidence_always_bounded() {
    let configs = [
        ScorerConfig { total_files: 1, default_age_days: 0, default_data_quality: None },
        ScorerConfig { total_files: 100, default_age_days: 365, default_data_quality: None },
        ScorerConfig { total_files: 1_000_000, default_age_days: 1, default_data_quality: None },
    ];

    let momentums = [MomentumDirection::Rising, MomentumDirection::Falling, MomentumDirection::Stable];

    for config in &configs {
        let scorer = ConfidenceScorer::new(config.clone());
        for &momentum in &momentums {
            for locs in [1, 10, 100, 1000] {
                for files in [1, 5, 50] {
                    let pattern = make_pattern("test", locs, files.min(locs));
                    let score = scorer.score(&pattern, momentum, config.default_age_days, None, None);
                    assert!(
                        score.posterior_mean >= 0.0 && score.posterior_mean <= 1.0,
                        "Score out of [0,1]: {} for locs={}, files={}, total={}, momentum={:?}",
                        score.posterior_mean, locs, files, config.total_files, momentum
                    );
                    assert!(score.alpha > 0.0, "Alpha must be positive");
                    assert!(score.beta > 0.0, "Beta must be positive");
                    assert!(score.posterior_mean.is_finite());
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OUTLIER DETECTION INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Outlier indices must be valid (within input bounds)
#[test]
fn property_outlier_indices_in_bounds() {
    let detector = OutlierDetector::new();

    for n in [3, 10, 50, 200] {
        let values: Vec<f64> = (0..n).map(|i| (i as f64) * 0.5 + 1.0).collect();
        let results = detector.detect(&values);
        for r in &results {
            assert!(
                r.index < n,
                "Outlier index {} out of bounds for n={}",
                r.index, n
            );
        }
    }
}

/// Outlier count must be ≤ input size
#[test]
fn property_outlier_count_bounded() {
    let detector = OutlierDetector::new();

    for n in [1, 5, 20, 100, 500] {
        let values: Vec<f64> = (0..n).map(|i| i as f64).collect();
        let results = detector.detect(&values);
        assert!(
            results.len() <= n,
            "More outliers ({}) than data points ({}) — impossible",
            results.len(), n
        );
    }
}

/// Deviation scores must be non-negative
#[test]
fn property_outlier_deviation_nonnegative() {
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = vec![5.0; 50];
    values[0] = 100.0;
    values[49] = -50.0;

    let results = detector.detect(&values);
    for r in &results {
        assert!(
            r.deviation_score.value() >= 0.0,
            "Deviation score must be non-negative, got {} at index {}",
            r.deviation_score.value(), r.index
        );
    }
}

/// Empty input → no outliers, no panic
#[test]
fn property_outlier_empty_input() {
    let detector = OutlierDetector::new();
    let results = detector.detect(&[]);
    assert!(results.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// AGGREGATION PIPELINE INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Number of unique pattern IDs in output ≤ number of unique IDs in input
#[test]
fn property_aggregation_no_phantom_patterns() {
    for num_patterns in [1, 5, 20, 100] {
        let mut matches = Vec::new();
        for p in 0..num_patterns {
            for f in 0..10 {
                matches.push(make_match(
                    &format!("pat_{}", p),
                    &format!("file_{}.ts", f),
                    1,
                ));
            }
        }

        let pipeline = AggregationPipeline::with_defaults();
        let result = pipeline.run(&matches);

        let input_ids: FxHashSet<String> = matches.iter().map(|m| m.pattern_id.clone()).collect();
        let output_ids: FxHashSet<String> = result.patterns.iter().map(|p| p.pattern_id.clone()).collect();

        assert!(
            output_ids.len() <= input_ids.len(),
            "Output has {} patterns but input only had {} unique IDs",
            output_ids.len(), input_ids.len()
        );

        // Every output ID must exist in input
        for id in &output_ids {
            assert!(
                input_ids.contains(id),
                "Phantom pattern '{}' appeared in output but not in input",
                id
            );
        }
    }
}

/// file_spread ≤ location_count (can't appear in more files than locations)
#[test]
fn property_aggregation_spread_leq_locations() {
    let mut matches = Vec::new();
    for p in 0..10 {
        for f in 0..20 {
            for line in 0..3 {
                matches.push(make_match(
                    &format!("pat_{}", p),
                    &format!("file_{}.ts", f),
                    line,
                ));
            }
        }
    }

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&matches);

    for p in &result.patterns {
        assert!(
            p.file_spread <= p.location_count,
            "Pattern {} has file_spread={} > location_count={}",
            p.pattern_id, p.file_spread, p.location_count
        );
    }
}

/// Single-location patterns: every pattern with 1 match in 1 file
#[test]
fn property_aggregation_single_location_patterns() {
    let matches: Vec<PatternMatch> = (0..100)
        .map(|i| make_match(&format!("solo_{}", i), &format!("file_{}.ts", i), 1))
        .collect();

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&matches);

    assert_eq!(result.patterns.len(), 100);
    for p in &result.patterns {
        assert_eq!(p.location_count, 1);
        assert_eq!(p.file_spread, 1);
        assert_eq!(p.locations.len(), 1);
    }
}
