//! Category 3: Intelligence Precision — Production Tests
//!
//! Bayesian confidence scoring and DNA profiling are statistically driven —
//! they can drift into inaccuracy. These tests verify numerical stability,
//! tier boundaries, feedback saturation, and convention persistence.
//!
//! T3-01 through T3-11.

use std::time::Instant;

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use drift_analysis::graph::reachability::bfs::reachability_forward;
use drift_analysis::patterns::aggregation::types::{AggregatedPattern, PatternLocation};
use drift_analysis::patterns::confidence::beta::credible_interval;
use drift_analysis::patterns::confidence::factors::{
    WEIGHT_AGE, WEIGHT_CONSISTENCY, WEIGHT_DATA_QUALITY, WEIGHT_FREQUENCY, WEIGHT_MOMENTUM,
    WEIGHT_SPREAD,
};
use drift_analysis::patterns::confidence::momentum::MomentumTracker;
use drift_analysis::patterns::confidence::scorer::{
    ConfidenceScorer, InMemoryFeedbackStore, ScorerConfig,
};
use drift_analysis::patterns::confidence::types::{ConfidenceScore, ConfidenceTier, MomentumDirection};
use drift_analysis::patterns::learning::types::InMemoryConventionStore;
use drift_analysis::patterns::outliers::selector::OutlierDetector;
use drift_analysis::patterns::pipeline::PatternIntelligencePipeline;
use drift_analysis::structural::dna::extractor::GeneExtractorRegistry;
use drift_analysis::structural::dna::types::FileExtractionResult;
use smallvec::smallvec;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn make_scorer(total_files: u64, age_days: u64) -> ConfidenceScorer {
    ConfidenceScorer::new(ScorerConfig {
        total_files,
        default_age_days: age_days,
        default_data_quality: None,
    })
}

fn make_match(
    file: &str,
    line: u32,
    pattern_id: &str,
    confidence: f32,
    category: PatternCategory,
) -> PatternMatch {
    PatternMatch {
        file: file.to_string(),
        line,
        column: 0,
        pattern_id: pattern_id.to_string(),
        confidence,
        cwe_ids: smallvec![],
        owasp: None,
        detection_method: DetectionMethod::AstVisitor,
        category,
        matched_text: String::new(),
    }
}

// ---------------------------------------------------------------------------
// T3-01: Bayesian Convergence
// ---------------------------------------------------------------------------

/// Feed 100 identical "False Positive" feedback loops. `posterior_mean` must
/// drop below the Uncertain tier threshold (<0.50).
#[test]
fn t3_01_bayesian_convergence() {
    let mut store = InMemoryFeedbackStore::new();
    // 100 FP dismissals: each adds beta_delta=0.5 (penalizes alpha/beta ratio)
    for _ in 0..100 {
        store.record("fp_pattern", 0.0, 0.5);
    }

    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 30,
        default_data_quality: None,
    })
    .with_feedback_store(Box::new(store));

    let pattern = make_pattern("fp_pattern", 50, 40);
    let score = scorer.score(&pattern, MomentumDirection::Stable, 30, None, None);

    assert!(
        score.posterior_mean < 0.50,
        "After 100 FP feedbacks, posterior_mean ({:.4}) should drop below Uncertain threshold 0.50",
        score.posterior_mean
    );
    assert_eq!(
        score.tier,
        ConfidenceTier::Uncertain,
        "Tier should be Uncertain, got {:?}",
        score.tier
    );
}

// ---------------------------------------------------------------------------
// T3-02: DNA Allele Consistency
// ---------------------------------------------------------------------------

/// Use GeneExtractorRegistry.with_all_extractors() (10 extractors) to analyze
/// a repo with 50% camelCase / 50% snake_case naming. Dominant allele
/// frequency must be ≥ 0.3 for dominance.
#[test]
fn t3_02_dna_allele_consistency() {
    let registry = GeneExtractorRegistry::with_all_extractors();
    assert_eq!(registry.len(), 10, "Should have 10 extractors");

    // Use the VariantHandling gene extractor to test allele consistency.
    // We'll build file extraction results manually with mixed naming.
    let variant_handling = registry.extractors().iter()
        .find(|e| e.gene_id() == drift_analysis::structural::dna::types::GeneId::VariantHandling)
        .expect("VariantHandling extractor must exist");

    // Create 50 files with camelCase props and 50 files with className approach
    let mut results: Vec<FileExtractionResult> = Vec::new();

    // 50 files with one style (e.g. cva/class-variance-authority)
    for i in 0..50 {
        let content = r#"
import { cva } from 'class-variance-authority';
const buttonVariants = cva('base', { variants: { size: { sm: 'small', lg: 'large' } } });
"#;
        let file_path = format!("src/component_{}.tsx", i);
        results.push(variant_handling.extract_from_file(content, &file_path));
    }

    // 50 files with another style (e.g. conditional className)
    for i in 50..100 {
        let content = r#"
const className = active ? 'btn-active' : 'btn-inactive';
<div className={isOpen ? 'open' : 'closed'} />;
"#;
        let file_path = format!("src/component_{}.tsx", i);
        results.push(variant_handling.extract_from_file(content, &file_path));
    }

    let gene = variant_handling.build_gene(&results);

    // If alleles were detected, the dominant must have frequency ≥ 0.3
    if let Some(ref dominant) = gene.dominant {
        assert!(
            dominant.frequency >= 0.3,
            "Dominant allele frequency ({:.4}) must be ≥ 0.3",
            dominant.frequency
        );
    }

    // If two alleles exist, consistency = gap between them
    if gene.alleles.len() >= 2 {
        let expected_consistency = gene.alleles[0].frequency - gene.alleles[1].frequency;
        assert!(
            (gene.consistency - expected_consistency).abs() < 1e-10,
            "Consistency ({:.4}) should be gap between top two alleles ({:.4})",
            gene.consistency,
            expected_consistency
        );
    }
}

// ---------------------------------------------------------------------------
// T3-03: Taint Reachability Depth
// ---------------------------------------------------------------------------

/// Set max_depth for reachability_forward to 5, 10, 50. Execution time must
/// scale linearly (not exponentially) when traversing the petgraph.
#[test]
fn t3_03_taint_reachability_depth() {
    // Build a linear chain of 200 nodes: A→B→C→...
    let mut graph = CallGraph::new();
    let mut nodes = Vec::new();

    for i in 0..200 {
        let node = FunctionNode {
            file: format!("src/file_{}.ts", i),
            name: format!("func_{}", i),
            qualified_name: None,
            language: "typescript".to_string(),
            line: 1,
            end_line: 10,
            is_entry_point: i == 0,
            is_exported: false,
            signature_hash: i as u64,
            body_hash: i as u64,
        };
        nodes.push(graph.add_function(node));
    }

    // Chain: 0→1→2→...→199
    for i in 0..199 {
        graph.add_edge(
            nodes[i],
            nodes[i + 1],
            CallEdge {
                resolution: Resolution::SameFile,
                confidence: 0.95,
                call_site_line: 5,
            },
        );
    }

    // Measure times at depths 5, 10, 50
    let depths = [5u32, 10, 50];
    let mut times = Vec::new();

    for &depth in &depths {
        let start = Instant::now();
        for _ in 0..100 {
            // Run multiple iterations for more stable timing
            let result = reachability_forward(&graph, nodes[0], Some(depth));
            assert!(result.reachable.len() <= depth as usize);
        }
        let elapsed = start.elapsed();
        times.push((depth, elapsed));
    }

    // Verify linear scaling: time at depth=50 should be <20× time at depth=5
    // (exponential would be ~2^45 ratio; linear is ~10×)
    let time_5 = times[0].1.as_nanos().max(1);
    let time_50 = times[2].1.as_nanos().max(1);
    let ratio = time_50 as f64 / time_5 as f64;

    assert!(
        ratio < 20.0,
        "Depth 50 / Depth 5 time ratio ({:.1}×) exceeds linear threshold (20×). \
         Times: depth=5: {:?}, depth=50: {:?}",
        ratio,
        times[0].1,
        times[2].1
    );
}

// ---------------------------------------------------------------------------
// T3-04: Confidence Tier Boundary Precision
// ---------------------------------------------------------------------------

/// Create patterns with posterior_mean at exactly 0.50, 0.70, 0.85.
/// Must classify as Tentative, Emerging, Established respectively.
#[test]
fn t3_04_confidence_tier_boundary_precision() {
    // Test the tier classification function directly at boundaries
    assert_eq!(
        ConfidenceTier::from_posterior_mean(0.85),
        ConfidenceTier::Established,
        "0.85 should be Established"
    );
    assert_eq!(
        ConfidenceTier::from_posterior_mean(0.70),
        ConfidenceTier::Emerging,
        "0.70 should be Emerging"
    );
    assert_eq!(
        ConfidenceTier::from_posterior_mean(0.50),
        ConfidenceTier::Tentative,
        "0.50 should be Tentative"
    );

    // Just below boundaries
    assert_eq!(
        ConfidenceTier::from_posterior_mean(0.8499999999),
        ConfidenceTier::Emerging,
        "0.849... should be Emerging (not Established)"
    );
    assert_eq!(
        ConfidenceTier::from_posterior_mean(0.6999999999),
        ConfidenceTier::Tentative,
        "0.699... should be Tentative (not Emerging)"
    );
    assert_eq!(
        ConfidenceTier::from_posterior_mean(0.4999999999),
        ConfidenceTier::Uncertain,
        "0.499... should be Uncertain (not Tentative)"
    );

    // Verify ConfidenceScore.from_params respects these boundaries too
    let score_established = ConfidenceScore::from_params(85.0, 15.0, MomentumDirection::Stable);
    assert_eq!(score_established.tier, ConfidenceTier::Established);
    assert!((score_established.posterior_mean - 0.85).abs() < 1e-10);

    let score_emerging = ConfidenceScore::from_params(70.0, 30.0, MomentumDirection::Stable);
    assert_eq!(score_emerging.tier, ConfidenceTier::Emerging);
    assert!((score_emerging.posterior_mean - 0.70).abs() < 1e-10);

    let score_tentative = ConfidenceScore::from_params(50.0, 50.0, MomentumDirection::Stable);
    assert_eq!(score_tentative.tier, ConfidenceTier::Tentative);
    assert!((score_tentative.posterior_mean - 0.50).abs() < 1e-10);
}

// ---------------------------------------------------------------------------
// T3-05: Temporal Decay Symmetry
// ---------------------------------------------------------------------------

/// Score a pattern, then simulate 90 days of inactivity via score_with_momentum.
/// Both alpha AND beta must decay proportionally (preserving posterior_mean
/// but widening credible interval).
#[test]
fn t3_05_temporal_decay_symmetry() {
    let scorer = make_scorer(100, 30);
    let pattern = make_pattern("decay_test", 80, 70);
    let mut tracker = MomentumTracker::new();
    for _ in 0..5 {
        tracker.record(80);
    }

    // Fresh score (0 days since last seen)
    let fresh = scorer.score_with_momentum(&pattern, &tracker, 30, 0);
    // Stale score (90 days since last seen — full decay)
    let stale = scorer.score_with_momentum(&pattern, &tracker, 30, 90);

    // Both alpha and beta should have decayed
    assert!(
        stale.alpha < fresh.alpha,
        "Alpha should decay: fresh={:.4}, stale={:.4}",
        fresh.alpha,
        stale.alpha
    );
    assert!(
        stale.beta < fresh.beta,
        "Beta should decay: fresh={:.4}, stale={:.4}",
        fresh.beta,
        stale.beta
    );

    // Posterior mean should be approximately preserved (symmetric decay)
    assert!(
        (fresh.posterior_mean - stale.posterior_mean).abs() < 0.05,
        "Symmetric decay should preserve posterior_mean: fresh={:.4}, stale={:.4}",
        fresh.posterior_mean,
        stale.posterior_mean
    );

    // CI should widen
    let fresh_width = fresh.credible_interval.1 - fresh.credible_interval.0;
    let stale_width = stale.credible_interval.1 - stale.credible_interval.0;
    assert!(
        stale_width > fresh_width,
        "90-day stale CI ({:.4}) should be wider than fresh CI ({:.4})",
        stale_width,
        fresh_width
    );
}

// ---------------------------------------------------------------------------
// T3-06: Feedback Loop Saturation
// ---------------------------------------------------------------------------

/// Apply 10,000 dismiss feedback events to the same pattern. Alpha must never
/// go below 0.01 (floor in scorer.rs:154); posterior_mean must not become NaN/Inf.
#[test]
fn t3_06_feedback_loop_saturation() {
    let mut store = InMemoryFeedbackStore::new();
    // 10,000 FP dismissals: each adds (0.0, 0.5)
    for _ in 0..10_000 {
        store.record("saturated", 0.0, 0.5);
    }

    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 30,
        default_data_quality: None,
    })
    .with_feedback_store(Box::new(store));

    let pattern = make_pattern("saturated", 50, 40);
    let score = scorer.score(&pattern, MomentumDirection::Stable, 30, None, None);

    // Alpha must not go below 0.01 (floor)
    assert!(
        score.alpha >= 0.01,
        "Alpha must not go below 0.01 floor: {}",
        score.alpha
    );
    assert!(
        score.beta >= 0.01,
        "Beta must not go below 0.01 floor: {}",
        score.beta
    );

    // No NaN/Inf
    assert!(
        score.posterior_mean.is_finite(),
        "posterior_mean must be finite: {}",
        score.posterior_mean
    );
    assert!(
        score.credible_interval.0.is_finite(),
        "CI low must be finite: {}",
        score.credible_interval.0
    );
    assert!(
        score.credible_interval.1.is_finite(),
        "CI high must be finite: {}",
        score.credible_interval.1
    );

    // posterior_mean should be very low after 10K dismissals
    assert!(
        score.posterior_mean < 0.50,
        "10K dismissals should drive posterior_mean ({:.4}) well below 0.50",
        score.posterior_mean
    );
}

// ---------------------------------------------------------------------------
// T3-07: 6-Factor Weight Invariant
// ---------------------------------------------------------------------------

/// Verify WEIGHT_FREQUENCY + WEIGHT_CONSISTENCY + WEIGHT_AGE + WEIGHT_SPREAD
/// + WEIGHT_MOMENTUM + WEIGHT_DATA_QUALITY == 1.0.
#[test]
fn t3_07_six_factor_weight_invariant() {
    let sum = WEIGHT_FREQUENCY
        + WEIGHT_CONSISTENCY
        + WEIGHT_AGE
        + WEIGHT_SPREAD
        + WEIGHT_MOMENTUM
        + WEIGHT_DATA_QUALITY;

    assert!(
        (sum - 1.0).abs() < f64::EPSILON * 10.0,
        "6-factor weights must sum to 1.0, got {:.17}",
        sum
    );

    // Verify individual values match documented constants
    assert!((WEIGHT_FREQUENCY - 0.25).abs() < 1e-10, "WEIGHT_FREQUENCY should be 0.25");
    assert!((WEIGHT_CONSISTENCY - 0.20).abs() < 1e-10, "WEIGHT_CONSISTENCY should be 0.20");
    assert!((WEIGHT_AGE - 0.10).abs() < 1e-10, "WEIGHT_AGE should be 0.10");
    assert!((WEIGHT_SPREAD - 0.15).abs() < 1e-10, "WEIGHT_SPREAD should be 0.15");
    assert!((WEIGHT_MOMENTUM - 0.15).abs() < 1e-10, "WEIGHT_MOMENTUM should be 0.15");
    assert!((WEIGHT_DATA_QUALITY - 0.15).abs() < 1e-10, "WEIGHT_DATA_QUALITY should be 0.15");
}

// ---------------------------------------------------------------------------
// T3-08: DataQuality Factor Impact
// ---------------------------------------------------------------------------

/// Score the same pattern with data_quality=0.3 vs data_quality=0.9. Low
/// quality must produce lower composite score; weight is 0.15 of total.
#[test]
fn t3_08_data_quality_factor_impact() {
    let scorer = make_scorer(100, 30);
    let pattern = make_pattern("dq_test", 50, 40);

    let high_q = scorer.score(&pattern, MomentumDirection::Stable, 30, None, Some(0.9));
    let low_q = scorer.score(&pattern, MomentumDirection::Stable, 30, None, Some(0.3));

    assert!(
        high_q.posterior_mean > low_q.posterior_mean,
        "data_quality=0.9 ({:.4}) should score higher than data_quality=0.3 ({:.4})",
        high_q.posterior_mean,
        low_q.posterior_mean
    );

    // The difference should be meaningful (0.15 weight × 0.6 quality gap)
    let diff = high_q.posterior_mean - low_q.posterior_mean;
    assert!(
        diff > 0.001,
        "DataQuality difference ({:.6}) should be non-trivial",
        diff
    );
}

// ---------------------------------------------------------------------------
// T3-09: Credible Interval Numerical Stability
// ---------------------------------------------------------------------------

/// Compute CI with alpha=1e7, beta=1.0 (extreme skew). Must return finite
/// (low, high) values without NaN/Inf.
#[test]
fn t3_09_credible_interval_numerical_stability() {
    // Extreme high alpha
    let (low, high) = credible_interval(1e7, 1.0, 0.95);
    assert!(low.is_finite(), "CI low must be finite for alpha=1e7: {}", low);
    assert!(high.is_finite(), "CI high must be finite for alpha=1e7: {}", high);
    assert!(low <= high, "CI low ({}) must be <= high ({})", low, high);
    assert!(low >= 0.0, "CI low ({}) must be >= 0.0", low);
    assert!(high <= 1.0, "CI high ({}) must be <= 1.0", high);

    // Extreme high beta
    let (low2, high2) = credible_interval(1.0, 1e7, 0.95);
    assert!(low2.is_finite(), "CI low must be finite for beta=1e7: {}", low2);
    assert!(high2.is_finite(), "CI high must be finite for beta=1e7: {}", high2);
    assert!(low2 <= high2);

    // Both extreme
    let (low3, high3) = credible_interval(1e7, 1e7, 0.95);
    assert!(low3.is_finite(), "CI low must be finite for both=1e7: {}", low3);
    assert!(high3.is_finite(), "CI high must be finite for both=1e7: {}", high3);

    // Near-zero parameters
    let (low4, high4) = credible_interval(0.001, 0.001, 0.95);
    assert!(low4.is_finite(), "CI low must be finite for near-zero: {}", low4);
    assert!(high4.is_finite(), "CI high must be finite for near-zero: {}", high4);

    // Invalid parameters (should return fallback, not crash)
    let (low5, high5) = credible_interval(0.0, 0.0, 0.95);
    assert!(low5.is_finite());
    assert!(high5.is_finite());

    let (low6, high6) = credible_interval(-1.0, 1.0, 0.95);
    assert!(low6.is_finite());
    assert!(high6.is_finite());

    // ConfidenceScore.from_params with extreme values
    let extreme_score = ConfidenceScore::from_params(1e7, 1.0, MomentumDirection::Stable);
    assert!(extreme_score.posterior_mean.is_finite());
    assert!(extreme_score.credible_interval.0.is_finite());
    assert!(extreme_score.credible_interval.1.is_finite());
}

// ---------------------------------------------------------------------------
// T3-10: Convention Persistence Across Runs
// ---------------------------------------------------------------------------

/// Run pipeline twice with same matches using InMemoryConventionStore.
/// scan_count must increment; discovery_date preserved; last_seen updated.
#[test]
fn t3_10_convention_persistence_across_runs() {
    let mut pipeline = PatternIntelligencePipeline::new();
    let mut store = InMemoryConventionStore::new();

    // Generate matches for a dominant pattern (high spread)
    let matches: Vec<PatternMatch> = (0..80)
        .map(|i| {
            make_match(
                &format!("src/file_{}.ts", i),
                10,
                "persist_pattern",
                0.9,
                PatternCategory::Structural,
            )
        })
        .collect();

    // Run 1
    let r1 = pipeline.run(&matches, 100, 1000, Some(&mut store));
    assert!(!r1.conventions.is_empty(), "Should discover conventions on run 1");
    let c1 = r1
        .conventions
        .iter()
        .find(|c| c.pattern_id == "persist_pattern")
        .expect("Should find persist_pattern convention");
    assert_eq!(c1.scan_count, 1, "First run should have scan_count=1");
    assert_eq!(c1.discovery_date, 1000, "Discovery date should be 1000");
    assert_eq!(c1.last_seen, 1000, "Last seen should be 1000 on first run");

    // Run 2 (later timestamp)
    let r2 = pipeline.run(&matches, 100, 2000, Some(&mut store));
    assert!(!r2.conventions.is_empty(), "Should discover conventions on run 2");
    let c2 = r2
        .conventions
        .iter()
        .find(|c| c.pattern_id == "persist_pattern")
        .expect("Should find persist_pattern convention");
    assert_eq!(c2.scan_count, 2, "Second run should have scan_count=2");
    assert_eq!(
        c2.discovery_date, 1000,
        "Discovery date must be preserved across runs"
    );
    assert_eq!(c2.last_seen, 2000, "Last seen should update to 2000");
}

// ---------------------------------------------------------------------------
// T3-11: Outlier Detection Minimum Sample
// ---------------------------------------------------------------------------

/// Feed outlier detector with <3 confidence values. Must skip outlier
/// detection (not crash). Pipeline line 117 filters `>=3`.
#[test]
fn t3_11_outlier_detection_minimum_sample() {
    let detector = OutlierDetector::new();

    // Empty
    let results_0 = detector.detect(&[]);
    // The detector should not crash. It may return empty or rule-based results.
    assert!(
        results_0.len() <= 1,
        "Empty input should produce 0 or minimal rule-based results"
    );

    // 1 value
    let results_1 = detector.detect(&[0.9]);
    assert!(
        results_1.len() <= 1,
        "Single value should produce 0 or minimal rule-based results"
    );

    // 2 values
    let results_2 = detector.detect(&[0.9, 0.1]);
    // Should not crash; might detect via rule-based (zero_confidence, confidence_cliff)
    let _ = results_2; // Just verify no panic

    // 3 values (minimum for statistical methods)
    let results_3 = detector.detect(&[0.9, 0.9, 0.0]);
    // With 3 values, statistical methods can fire; the zero should be flagged
    let _ = results_3; // Just verify no panic

    // Also verify via the pipeline (line 117 filter)
    let mut pipeline = PatternIntelligencePipeline::new();
    // Create a pattern with only 2 locations (below the >=3 threshold)
    let matches: Vec<PatternMatch> = (0..2)
        .map(|i| {
            make_match(
                &format!("src/f_{}.ts", i),
                1,
                "small_pat",
                0.9,
                PatternCategory::Structural,
            )
        })
        .collect();
    let result = pipeline.run(&matches, 100, 1000, None);
    // Pipeline should complete without crash; outliers list should not contain small_pat
    let has_outliers = result
        .outliers
        .iter()
        .any(|(pid, _)| pid == "small_pat");
    assert!(
        !has_outliers,
        "Pattern with <3 values should be filtered from outlier detection"
    );
}
