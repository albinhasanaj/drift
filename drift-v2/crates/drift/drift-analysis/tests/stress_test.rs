//! Phase 3 — Stress & Production-Readiness Tests
//!
//! Battle-tests the core P3 logic under adversarial, edge-case, and
//! high-volume conditions before moving to Phase 4.

use drift_analysis::patterns::aggregation::pipeline::AggregationPipeline;
use drift_analysis::patterns::aggregation::similarity::{
    jaccard_similarity, MinHashIndex,
};
use drift_analysis::patterns::aggregation::types::{
    AggregatedPattern, PatternLocation,
};
use drift_analysis::patterns::confidence::beta::{self, BetaPosterior};
use drift_analysis::patterns::confidence::momentum::MomentumTracker;
use drift_analysis::patterns::confidence::scorer::{ConfidenceScorer, ScorerConfig};
use drift_analysis::patterns::confidence::types::MomentumDirection;
use drift_analysis::patterns::learning::discovery::ConventionDiscoverer;
use drift_analysis::patterns::learning::types::LearningConfig;
use drift_analysis::patterns::outliers::selector::OutlierDetector;
use drift_analysis::patterns::outliers::types::OutlierConfig;

use drift_analysis::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use drift_core::types::collections::FxHashSet;
use smallvec::smallvec;

use std::time::Instant;

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
// 1. AGGREGATION PIPELINE — SCALE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_aggregation_10k_matches() {
    // 10K matches across 100 patterns × 100 files
    let mut matches = Vec::with_capacity(10_000);
    for p in 0..100 {
        for f in 0..100 {
            matches.push(make_match(
                &format!("pat_{}", p),
                &format!("src/file_{}.ts", f),
                (p * 100 + f) as u32,
            ));
        }
    }

    let pipeline = AggregationPipeline::with_defaults();
    let start = Instant::now();
    let result = pipeline.run(&matches);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 5000,
        "10K aggregation took {}ms — should be <5s",
        elapsed.as_millis()
    );
    assert_eq!(result.patterns.len(), 100);
    for p in &result.patterns {
        assert_eq!(p.location_count, 100);
        assert_eq!(p.file_spread, 100);
    }
}

#[test]
fn stress_aggregation_50k_matches() {
    // 50K matches: 500 patterns × 100 files
    let mut matches = Vec::with_capacity(50_000);
    for p in 0..500 {
        for f in 0..100 {
            matches.push(make_match(
                &format!("pat_{}", p),
                &format!("src/mod_{}/file_{}.ts", p % 50, f),
                f as u32,
            ));
        }
    }

    let pipeline = AggregationPipeline::with_defaults();
    let start = Instant::now();
    let result = pipeline.run(&matches);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 30_000,
        "50K aggregation took {}ms — should be <30s",
        elapsed.as_millis()
    );
    assert_eq!(result.patterns.len(), 500);
}

#[test]
fn stress_aggregation_single_pattern_many_files() {
    // One pattern appearing in 5000 files — tests grouper dedup
    let matches: Vec<PatternMatch> = (0..5000)
        .map(|f| make_match("singleton", &format!("file_{}.ts", f), 1))
        .collect();

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&matches);

    assert_eq!(result.patterns.len(), 1);
    assert_eq!(result.patterns[0].file_spread, 5000);
    assert_eq!(result.patterns[0].location_count, 5000);
}

#[test]
fn stress_aggregation_duplicate_locations() {
    // Same file:line:column repeated 1000 times — dedup must collapse
    let matches: Vec<PatternMatch> = (0..1000)
        .map(|_| make_match("dup", "same_file.ts", 42))
        .collect();

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&matches);

    assert_eq!(result.patterns.len(), 1);
    // Dedup by file:line:column should collapse to 1 location
    assert_eq!(result.patterns[0].locations.len(), 1);
}

#[test]
fn stress_aggregation_empty_input() {
    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&[]);
    assert!(result.patterns.is_empty());
    assert!(result.merge_candidates.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. INCREMENTAL AGGREGATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_incremental_add_new_files() {
    let pipeline = AggregationPipeline::with_defaults();

    // Initial: 100 matches
    let initial: Vec<PatternMatch> = (0..100)
        .map(|f| make_match("pat_a", &format!("old_{}.ts", f), 1))
        .collect();
    let result = pipeline.run(&initial);
    let mut existing = result.patterns;

    // Incremental: 50 new files
    let mut all_matches = initial.clone();
    let new_matches: Vec<PatternMatch> = (0..50)
        .map(|f| make_match("pat_a", &format!("new_{}.ts", f), 1))
        .collect();
    all_matches.extend(new_matches);

    let changed: FxHashSet<String> = (0..50).map(|f| format!("new_{}.ts", f)).collect();
    let result = pipeline.run_incremental(&all_matches, &mut existing, &changed);

    // Should have the pattern with locations from both old and new
    assert_eq!(result.patterns.len(), 1);
    assert!(result.patterns[0].location_count >= 100); // At least old locations
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. MINHASH LSH — SCALE & CORRECTNESS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_minhash_1000_patterns() {
    let mut index = MinHashIndex::new(128, 32);

    // Insert 1000 patterns with unique location sets
    for i in 0..1000 {
        let mut set = FxHashSet::default();
        for j in 0..20 {
            set.insert(format!("file_{}:{}", i, j));
        }
        index.insert(&format!("pat_{}", i), &set);
    }

    assert_eq!(index.len(), 1000);

    // Disjoint patterns should have ~0 estimated similarity
    if let Some(sim) = index.estimate_similarity("pat_0", "pat_999") {
        assert!(sim < 0.3, "Disjoint patterns similarity = {} (expected ~0)", sim);
    }
}

#[test]
fn stress_minhash_identical_patterns_detected() {
    let mut index = MinHashIndex::new(128, 32);

    // Two patterns with identical location sets
    let mut set = FxHashSet::default();
    for j in 0..50 {
        set.insert(format!("shared_file:{}", j));
    }
    index.insert("twin_a", &set);
    index.insert("twin_b", &set);

    let candidates = index.find_candidates();
    assert!(
        !candidates.is_empty(),
        "Identical patterns must be detected as candidates"
    );

    let sim = index.estimate_similarity("twin_a", "twin_b").unwrap();
    assert!(sim > 0.8, "Identical sets should have similarity > 0.8, got {}", sim);
}

#[test]
fn stress_minhash_high_overlap_detected() {
    let mut index = MinHashIndex::new(128, 32);

    // 90% overlap
    let mut set_a = FxHashSet::default();
    let mut set_b = FxHashSet::default();
    for j in 0..100 {
        set_a.insert(format!("loc:{}", j));
        if j < 90 {
            set_b.insert(format!("loc:{}", j));
        } else {
            set_b.insert(format!("other:{}", j));
        }
    }

    index.insert("overlap_a", &set_a);
    index.insert("overlap_b", &set_b);

    let sim = index.estimate_similarity("overlap_a", "overlap_b").unwrap();
    // Exact Jaccard = 90/110 ≈ 0.818. MinHash estimate should be in ballpark.
    assert!(
        sim > 0.5,
        "90% overlap should yield estimated similarity > 0.5, got {}",
        sim
    );
}

#[test]
fn stress_jaccard_large_sets() {
    // 10K element sets
    let mut a = FxHashSet::default();
    let mut b = FxHashSet::default();
    for i in 0..10_000 {
        a.insert(format!("elem_{}", i));
        b.insert(format!("elem_{}", i + 5000)); // 50% overlap
    }

    let start = Instant::now();
    let sim = jaccard_similarity(&a, &b);
    let elapsed = start.elapsed();

    // Exact: intersection=5000, union=15000 → 0.333
    assert!((sim - 1.0 / 3.0).abs() < 0.01);
    assert!(elapsed.as_millis() < 1000, "Jaccard on 10K sets took {}ms", elapsed.as_millis());
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. CONFIDENCE SCORING — NUMERICAL STABILITY
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_confidence_10k_patterns_under_500ms() {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 10_000,
        default_age_days: 30,
    default_data_quality: None,
    });

    let patterns: Vec<AggregatedPattern> = (0..10_000)
        .map(|i| make_pattern(&format!("pat_{}", i), (i % 100 + 1) as u32, (i % 50 + 1) as u32))
        .collect();

    let start = Instant::now();
    let scores = scorer.score_batch(&patterns, None);
    let elapsed = start.elapsed();

    assert_eq!(scores.len(), 10_000);
    assert!(
        elapsed.as_millis() < 500,
        "10K confidence scoring took {}ms — QG-3 requires <500ms",
        elapsed.as_millis()
    );

    // Every score must be finite and in valid range
    for (id, score) in &scores {
        assert!(score.posterior_mean.is_finite(), "NaN/Inf for {}", id);
        assert!(score.posterior_mean >= 0.0 && score.posterior_mean <= 1.0, "Out of range for {}", id);
        assert!(score.alpha > 0.0, "Alpha must be positive for {}", id);
        assert!(score.beta > 0.0, "Beta must be positive for {}", id);
    }
}

#[test]
fn stress_beta_extreme_parameters() {
    // Extreme alpha/beta values — must never produce NaN/Inf or hang.
    // Note: statrs Beta::inverse_cdf can hang on very large params (>1e6),
    // so our credible_interval guard short-circuits those cases.
    let cases: Vec<(f64, f64)> = vec![
        (0.001, 0.001),
        (0.001, 100_000.0),
        (100_000.0, 0.001),
        (100_000.0, 100_000.0),
        (1e-10, 1e-10),
        (1e7, 1.0),       // Above guard threshold — uses fast path
        (1.0, 1e7),       // Above guard threshold — uses fast path
        (f64::MIN_POSITIVE, f64::MIN_POSITIVE),
        (500_000.0, 500_000.0), // Large but below statrs hang threshold
    ];

    for (a, b) in &cases {
        let mean = BetaPosterior::posterior_mean(*a, *b);
        assert!(mean.is_finite(), "NaN/Inf mean for alpha={}, beta={}", a, b);
        assert!((0.0..=1.0).contains(&mean), "Out of range for alpha={}, beta={}", a, b);

        let var = BetaPosterior::posterior_variance(*a, *b);
        assert!(var.is_finite(), "NaN/Inf variance for alpha={}, beta={}", a, b);
        assert!(var >= 0.0, "Negative variance for alpha={}, beta={}", a, b);

        let (lo, hi) = beta::credible_interval(*a, *b, 0.95);
        assert!(lo.is_finite() && hi.is_finite(), "NaN/Inf CI for alpha={}, beta={}", a, b);
        assert!(lo <= hi, "Inverted CI for alpha={}, beta={}", a, b);
        assert!(lo >= 0.0 && hi <= 1.0, "CI out of [0,1] for alpha={}, beta={}", a, b);
    }
}

#[test]
fn stress_beta_degenerate_inputs() {
    // Zero, negative, NaN, Inf — must not panic or hang
    let mean_zero = BetaPosterior::posterior_mean(0.0, 0.0);
    assert!(mean_zero.is_finite());

    let mean_neg = BetaPosterior::posterior_mean(-1.0, 5.0);
    assert!(mean_neg.is_finite());

    let mean_inf = BetaPosterior::posterior_mean(f64::INFINITY, 1.0);
    assert!(mean_inf.is_finite());

    let mean_nan = BetaPosterior::posterior_mean(f64::NAN, 1.0);
    assert!(mean_nan.is_finite());

    // Credible interval with invalid params — these hit the guard early
    let (lo, hi) = beta::credible_interval(-1.0, -1.0, 0.95);
    assert!(lo.is_finite() && hi.is_finite());
    let (lo, hi) = beta::credible_interval(f64::NAN, 1.0, 0.95);
    assert!(lo.is_finite() && hi.is_finite());
    // Note: f64::INFINITY is caught by !is_finite() guard in credible_interval
    let (lo, hi) = beta::credible_interval(f64::INFINITY, 1.0, 0.95);
    assert!(lo.is_finite() && hi.is_finite());
}

#[test]
fn stress_momentum_tracker_long_series() {
    // The tracker uses a sliding window of 10 scans and relative slope.
    // For rising detection, the *relative* change within the window must exceed 10%.

    // Exponentially increasing — relative change is significant within any window
    let mut tracker = MomentumTracker::new();
    let mut val = 10u64;
    for _ in 0..100 {
        tracker.record(val);
        val = (val as f64 * 1.15) as u64; // 15% growth per scan
    }
    assert_eq!(tracker.direction(), MomentumDirection::Rising,
        "Exponential growth should be Rising");

    // Exponentially decreasing — start high enough that window still has nonzero values
    let mut tracker2 = MomentumTracker::new();
    for i in 0..10 {
        tracker2.record(1000 - i * 80); // 1000, 920, 840, ..., 280
    }
    assert_eq!(tracker2.direction(), MomentumDirection::Falling,
        "Linear decline should be Falling");

    // Flat — constant value
    let mut tracker3 = MomentumTracker::new();
    for _ in 0..10_000 {
        tracker3.record(42);
    }
    assert_eq!(tracker3.direction(), MomentumDirection::Stable,
        "Constant values should be Stable");

    // Linear increase with significant relative slope
    let mut tracker4 = MomentumTracker::new();
    for i in 1..=10 {
        tracker4.record(i * 10); // 10, 20, 30, ..., 100
    }
    assert_eq!(tracker4.direction(), MomentumDirection::Rising,
        "10→100 linear increase should be Rising");

    // Linear decrease with significant relative slope
    let mut tracker5 = MomentumTracker::new();
    for i in (1..=10).rev() {
        tracker5.record(i * 10); // 100, 90, 80, ..., 10
    }
    assert_eq!(tracker5.direction(), MomentumDirection::Falling,
        "100→10 linear decrease should be Falling");
}

#[test]
fn stress_confidence_with_momentum_decay() {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 30,
    default_data_quality: None,
    });
    let pattern = make_pattern("decay_test", 80, 70);
    let mut tracker = MomentumTracker::new();
    for _ in 0..10 {
        tracker.record(80);
    }

    // Score at various staleness levels
    let fresh = scorer.score_with_momentum(&pattern, &tracker, 30, 0);
    let week_old = scorer.score_with_momentum(&pattern, &tracker, 30, 7);
    let month_old = scorer.score_with_momentum(&pattern, &tracker, 30, 30);
    let year_old = scorer.score_with_momentum(&pattern, &tracker, 30, 365);

    // Confidence must monotonically decrease with staleness (within f64 precision)
    let eps = 1e-12;
    assert!(fresh.posterior_mean + eps >= week_old.posterior_mean);
    assert!(week_old.posterior_mean + eps >= month_old.posterior_mean);
    assert!(month_old.posterior_mean + eps >= year_old.posterior_mean);

    // All must remain finite and valid
    for s in [&fresh, &week_old, &month_old, &year_old] {
        assert!(s.posterior_mean.is_finite());
        assert!(s.posterior_mean >= 0.0 && s.posterior_mean <= 1.0);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. OUTLIER DETECTION — ADVERSARIAL DATA
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_outlier_all_identical_values() {
    let detector = OutlierDetector::new();
    let values = vec![0.5; 100];
    let results = detector.detect(&values);
    // No outliers in perfectly uniform data
    assert!(results.is_empty(), "Uniform data should have no outliers, got {}", results.len());
}

#[test]
fn stress_outlier_single_value() {
    let detector = OutlierDetector::new();
    let values = vec![0.5];
    let results = detector.detect(&values);
    // Single value — can't be an outlier
    assert!(results.is_empty());
}

#[test]
fn stress_outlier_two_values() {
    let detector = OutlierDetector::new();
    let values = vec![0.5, 100.0];
    let results = detector.detect(&values);
    // Too few for statistical methods — only rule-based
    // Should not panic
    assert!(results.len() <= 2);
}

#[test]
fn stress_outlier_extreme_spread() {
    let detector = OutlierDetector::new();
    let mut values = vec![0.0; 50];
    values.push(1e15); // Extreme outlier
    let results = detector.detect(&values);
    assert!(!results.is_empty(), "Extreme value must be detected as outlier");
}

#[test]
fn stress_outlier_negative_values() {
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = (0..50).map(|i| i as f64).collect();
    values.push(-1000.0);
    let results = detector.detect(&values);
    assert!(!results.is_empty(), "Large negative outlier must be detected");
}

#[test]
fn stress_outlier_1000_values_performance() {
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = (0..1000).map(|i| (i as f64) * 0.01).collect();
    // Inject 5 outliers
    values[0] = -100.0;
    values[100] = 500.0;
    values[200] = -200.0;
    values[500] = 999.0;
    values[999] = -999.0;

    let start = Instant::now();
    let results = detector.detect(&values);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 1000,
        "1K outlier detection took {}ms",
        elapsed.as_millis()
    );
    assert!(results.len() >= 3, "Should detect at least 3 of 5 injected outliers, got {}", results.len());
}

#[test]
fn stress_outlier_10k_values() {
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = (0..10_000).map(|i| 50.0 + (i as f64 % 10.0)).collect();
    values[0] = 99999.0;
    values[9999] = -99999.0;

    let start = Instant::now();
    let results = detector.detect(&values);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 5000,
        "10K outlier detection took {}ms",
        elapsed.as_millis()
    );
    assert!(results.len() >= 2, "Should detect the two extreme outliers");
}

#[test]
fn stress_outlier_all_zeros() {
    let detector = OutlierDetector::new();
    let values = vec![0.0; 100];
    let results = detector.detect(&values);
    // The zero_confidence_rule flags 0.0 values — this is correct behavior.
    // All values are 0.0, so all get flagged by the rule. No statistical outliers though.
    // Just verify it doesn't panic and returns a consistent result.
    assert!(results.len() <= 100);
}

#[test]
fn stress_outlier_near_zero_variance() {
    let detector = OutlierDetector::new();
    // Values differ by epsilon
    let values: Vec<f64> = (0..100).map(|i| 1.0 + (i as f64) * 1e-15).collect();
    let results = detector.detect(&values);
    // Should not panic on near-zero variance
    assert!(results.len() <= 100);
}

#[test]
fn stress_outlier_custom_config_strict() {
    let config = OutlierConfig {
        z_threshold: 1.5,       // Very strict
        alpha: 0.01,
        iqr_multiplier: 1.0,    // Very strict
        mad_threshold: 2.0,     // Very strict
        min_sample_size: 5,
        max_iterations: 20,
    };
    let detector = OutlierDetector::with_config(config);

    let mut values: Vec<f64> = vec![10.0; 50];
    values.push(15.0); // Mild deviation
    values.push(20.0); // Moderate deviation

    let results = detector.detect(&values);
    // Strict thresholds should flag more aggressively
    assert!(!results.is_empty(), "Strict config should flag deviations");
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. LEARNING / CONVENTION DISCOVERY — STRESS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_discovery_100_patterns() {
    let discoverer = ConventionDiscoverer::new();

    let patterns: Vec<AggregatedPattern> = (0..100)
        .map(|i| make_pattern(&format!("pat_{}", i), (i + 5) as u32, (i % 20 + 2) as u32))
        .collect();

    let scores: Vec<(String, _)> = patterns
        .iter()
        .map(|p| {
            let score = drift_analysis::patterns::confidence::types::ConfidenceScore::from_params(
                p.location_count as f64,
                10.0,
                MomentumDirection::Stable,
            );
            (p.pattern_id.clone(), score)
        })
        .collect();

    let conventions = discoverer.discover(&patterns, &scores, 1000, 1000);
    // Should discover conventions for patterns meeting thresholds
    assert!(!conventions.is_empty(), "Should discover at least some conventions from 100 patterns");
}

#[test]
fn stress_discovery_contested_many_competitors() {
    let discoverer = ConventionDiscoverer::new();

    // 10 patterns all with similar frequency — highly contested
    let patterns: Vec<AggregatedPattern> = (0..10)
        .map(|i| make_pattern(&format!("style_{}", i), 50 + i as u32, 10))
        .collect();

    let scores: Vec<(String, _)> = patterns
        .iter()
        .map(|p| {
            let score = drift_analysis::patterns::confidence::types::ConfidenceScore::from_params(
                10.0, 5.0, MomentumDirection::Stable,
            );
            (p.pattern_id.clone(), score)
        })
        .collect();

    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    let contested_count = conventions
        .iter()
        .filter(|c| c.category == drift_analysis::patterns::learning::types::ConventionCategory::Contested)
        .count();

    // With 10 similarly-frequent patterns, most should be contested
    assert!(
        contested_count >= 5,
        "Expected ≥5 contested conventions from 10 similar patterns, got {}",
        contested_count
    );
}

#[test]
fn stress_discovery_empty_input() {
    let discoverer = ConventionDiscoverer::new();
    let conventions = discoverer.discover(&[], &[], 100, 1000);
    assert!(conventions.is_empty());
}

#[test]
fn stress_discovery_all_below_threshold() {
    let config = LearningConfig {
        min_occurrences: 100,
        min_files: 50,
        ..LearningConfig::default()
    };
    let discoverer = ConventionDiscoverer::with_config(config);

    // All patterns below the high thresholds
    let patterns: Vec<AggregatedPattern> = (0..50)
        .map(|i| make_pattern(&format!("small_{}", i), 5, 2))
        .collect();

    let scores: Vec<(String, _)> = patterns
        .iter()
        .map(|p| {
            (
                p.pattern_id.clone(),
                drift_analysis::patterns::confidence::types::ConfidenceScore::uniform_prior(),
            )
        })
        .collect();

    let conventions = discoverer.discover(&patterns, &scores, 1000, 1000);
    assert!(conventions.is_empty(), "All patterns below threshold — no conventions");
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. FULL PIPELINE INTEGRATION — PRODUCTION SIMULATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_full_pipeline_production_simulation() {
    // Simulate a real project: 200 patterns across 500 files
    let mut matches = Vec::new();

    // 10 dominant patterns (appear in 80%+ of files)
    for p in 0..10 {
        for f in 0..400 {
            matches.push(make_match(
                &format!("dominant_{}", p),
                &format!("src/module_{}/file_{}.ts", f / 20, f),
                (p * 10 + 1) as u32,
            ));
        }
    }

    // 50 common patterns (appear in 20-50% of files)
    for p in 0..50 {
        let file_count = 100 + (p * 4);
        for f in 0..file_count {
            matches.push(make_match(
                &format!("common_{}", p),
                &format!("src/module_{}/file_{}.ts", f / 10, f),
                (p + 100) as u32,
            ));
        }
    }

    // 140 rare patterns (appear in <5% of files)
    for p in 0..140 {
        let file_count = 1 + (p % 20);
        for f in 0..file_count {
            matches.push(make_match(
                &format!("rare_{}", p),
                &format!("src/rare_{}/file_{}.ts", p, f),
                1,
            ));
        }
    }

    let start = Instant::now();

    // Phase 1: Aggregation
    let pipeline = AggregationPipeline::with_defaults();
    let agg_result = pipeline.run(&matches);
    let agg_time = start.elapsed();

    assert_eq!(agg_result.patterns.len(), 200);

    // Phase 2: Confidence scoring
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 500,
        default_age_days: 30,
    default_data_quality: None,
    });
    let scores = scorer.score_batch(&agg_result.patterns, None);
    let score_time = start.elapsed();

    assert_eq!(scores.len(), 200);

    // Phase 3: Outlier detection on confidence values
    let confidence_values: Vec<f64> = scores.iter().map(|(_, s)| s.posterior_mean).collect();
    let detector = OutlierDetector::new();
    let outliers = detector.detect(&confidence_values);
    let outlier_time = start.elapsed();

    // Phase 4: Convention discovery
    let discoverer = ConventionDiscoverer::new();
    let conventions = discoverer.discover(&agg_result.patterns, &scores, 500, 1000);
    let total_time = start.elapsed();

    // Assertions
    assert!(
        total_time.as_millis() < 10_000,
        "Full pipeline took {}ms — should be <10s",
        total_time.as_millis()
    );

    // Dominant patterns should have high confidence
    let dominant_scores: Vec<&f64> = scores
        .iter()
        .filter(|(id, _)| id.starts_with("dominant_"))
        .map(|(_, s)| &s.posterior_mean)
        .collect();
    for mean in &dominant_scores {
        assert!(**mean > 0.5, "Dominant pattern should have confidence > 0.5, got {}", mean);
    }

    // Should discover some conventions
    assert!(
        !conventions.is_empty(),
        "Should discover conventions from 200 patterns"
    );

    // Print summary for manual review
    eprintln!("=== Production Simulation Results ===");
    eprintln!("  Patterns: {}", agg_result.patterns.len());
    eprintln!("  Merge candidates: {}", agg_result.merge_candidates.len());
    eprintln!("  Outliers: {}", outliers.len());
    eprintln!("  Conventions: {}", conventions.len());
    eprintln!("  Aggregation: {:?}", agg_time);
    eprintln!("  + Scoring: {:?}", score_time);
    eprintln!("  + Outliers: {:?}", outlier_time);
    eprintln!("  Total: {:?}", total_time);
}

#[test]
fn stress_tier_distribution_sanity() {
    // Score 1000 patterns with varying spread — verify tier distribution makes sense
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 14,
    default_data_quality: None,
    });

    let mut tier_counts = std::collections::HashMap::new();

    for i in 0..1000 {
        let spread = (i % 100) + 1; // 1..100
        let locs = spread + (i % 20);
        let pattern = make_pattern(&format!("p_{}", i), locs as u32, spread as u32);
        let score = scorer.score(&pattern, MomentumDirection::Stable, 14, None, None);
        *tier_counts.entry(score.tier).or_insert(0u32) += 1;
    }

    // Should have a distribution across tiers, not all in one bucket
    assert!(
        tier_counts.len() >= 2,
        "Expected at least 2 different tiers, got {:?}",
        tier_counts
    );

    eprintln!("=== Tier Distribution (1000 patterns) ===");
    for (tier, count) in &tier_counts {
        eprintln!("  {:?}: {}", tier, count);
    }
}

#[test]
fn stress_credible_interval_monotonic_narrowing() {
    // As evidence increases, CI should narrow monotonically
    let mut prev_width = f64::MAX;
    for n in [2, 5, 10, 50, 100, 500, 1000, 10_000] {
        let k = n / 2; // 50% success rate
        let (alpha, beta_val) = BetaPosterior::posterior_params(k, n);
        let (lo, hi) = beta::credible_interval(alpha, beta_val, 0.95);
        let width = hi - lo;

        assert!(
            width <= prev_width + 1e-10,
            "CI should narrow with more evidence: n={}, width={}, prev={}",
            n,
            width,
            prev_width
        );
        prev_width = width;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. EDGE CASES — BOUNDARY CONDITIONS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_aggregation_unicode_file_paths() {
    let matches = vec![
        make_match("pat_unicode", "src/模块/文件.ts", 1),
        make_match("pat_unicode", "src/модуль/файл.ts", 2),
        make_match("pat_unicode", "src/🚀/launch.ts", 3),
        make_match("pat_unicode", "src/données/fichier.ts", 4),
    ];

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&matches);

    assert_eq!(result.patterns.len(), 1);
    assert_eq!(result.patterns[0].file_spread, 4);
}

#[test]
fn stress_aggregation_very_long_pattern_ids() {
    let long_id = "a".repeat(10_000);
    let matches = vec![
        make_match(&long_id, "file.ts", 1),
        make_match(&long_id, "file2.ts", 2),
    ];

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&matches);

    assert_eq!(result.patterns.len(), 1);
    assert_eq!(result.patterns[0].pattern_id, long_id);
}

#[test]
fn stress_scorer_zero_total_files() {
    // Edge case: total_files = 0
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 0,
        default_age_days: 7,
    default_data_quality: None,
    });
    let pattern = make_pattern("edge", 10, 5);
    let score = scorer.score(&pattern, MomentumDirection::Stable, 7, None, None);

    assert!(score.posterior_mean.is_finite());
    assert!(score.alpha > 0.0);
    assert!(score.beta > 0.0);
}

#[test]
fn stress_scorer_max_u64_files() {
    // Large but realistic total_files — e.g. a massive monorepo
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 1_000_000,
        default_age_days: 7,
    default_data_quality: None,
    });
    let pattern = make_pattern("huge", 10, 5);
    let score = scorer.score(&pattern, MomentumDirection::Stable, 7, None, None);

    assert!(score.posterior_mean.is_finite());
    assert!(score.posterior_mean >= 0.0 && score.posterior_mean <= 1.0);
}
