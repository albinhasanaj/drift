#![allow(unused_imports, unused_variables)]
//! Phase 3 — Determinism Tests
//!
//! Verifies that identical inputs always produce identical outputs.
//! Non-determinism in hash iteration order is a classic footgun with
//! FxHashMap — downstream consumers (storage, NAPI) would see phantom diffs.

use drift_analysis::patterns::aggregation::pipeline::AggregationPipeline;
use drift_analysis::patterns::aggregation::types::{AggregatedPattern, PatternLocation};
use drift_analysis::patterns::confidence::scorer::{ConfidenceScorer, ScorerConfig};
use drift_analysis::patterns::confidence::types::MomentumDirection;
use drift_analysis::patterns::learning::discovery::ConventionDiscoverer;
use drift_analysis::patterns::outliers::selector::OutlierDetector;

use drift_analysis::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
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

fn build_test_matches() -> Vec<PatternMatch> {
    let mut matches = Vec::new();
    for p in 0..20 {
        for f in 0..50 {
            matches.push(make_match(
                &format!("pat_{}", p),
                &format!("src/mod_{}/file_{}.ts", p % 5, f),
                f as u32,
            ));
        }
    }
    matches
}

// ═══════════════════════════════════════════════════════════════════════════
// AGGREGATION DETERMINISM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_aggregation_sorted_output() {
    let matches = build_test_matches();
    let pipeline = AggregationPipeline::with_defaults();

    // Run 10 times, collect sorted pattern IDs each time
    let mut all_runs: Vec<Vec<String>> = Vec::new();
    for _ in 0..10 {
        let result = pipeline.run(&matches);
        let mut ids: Vec<String> = result.patterns.iter().map(|p| p.pattern_id.clone()).collect();
        ids.sort();
        all_runs.push(ids);
    }

    // Every run must produce the same sorted set
    for (i, run) in all_runs.iter().enumerate().skip(1) {
        assert_eq!(
            &all_runs[0], run,
            "Aggregation run 0 vs run {} produced different pattern sets",
            i
        );
    }
}

#[test]
fn determinism_aggregation_location_counts() {
    let matches = build_test_matches();
    let pipeline = AggregationPipeline::with_defaults();

    let mut all_counts: Vec<Vec<(String, u32)>> = Vec::new();
    for _ in 0..10 {
        let result = pipeline.run(&matches);
        let mut counts: Vec<(String, u32)> = result
            .patterns
            .iter()
            .map(|p| (p.pattern_id.clone(), p.location_count))
            .collect();
        counts.sort_by(|a, b| a.0.cmp(&b.0));
        all_counts.push(counts);
    }

    for (i, run) in all_counts.iter().enumerate().skip(1) {
        assert_eq!(
            &all_counts[0], run,
            "Location counts differ between run 0 and run {}",
            i
        );
    }
}

#[test]
fn determinism_aggregation_file_spread() {
    let matches = build_test_matches();
    let pipeline = AggregationPipeline::with_defaults();

    let mut all_spreads: Vec<Vec<(String, u32)>> = Vec::new();
    for _ in 0..10 {
        let result = pipeline.run(&matches);
        let mut spreads: Vec<(String, u32)> = result
            .patterns
            .iter()
            .map(|p| (p.pattern_id.clone(), p.file_spread))
            .collect();
        spreads.sort_by(|a, b| a.0.cmp(&b.0));
        all_spreads.push(spreads);
    }

    for (i, run) in all_spreads.iter().enumerate().skip(1) {
        assert_eq!(
            &all_spreads[0], run,
            "File spreads differ between run 0 and run {}",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIDENCE SCORING DETERMINISM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_confidence_scores_identical() {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 14,
    default_data_quality: None,
    });

    let patterns: Vec<AggregatedPattern> = (0..50)
        .map(|i| make_pattern(&format!("pat_{}", i), (i + 5) as u32, (i % 20 + 2) as u32))
        .collect();

    let mut all_scores: Vec<Vec<(String, f64)>> = Vec::new();
    for _ in 0..10 {
        let scores = scorer.score_batch(&patterns, None);
        let mut sorted: Vec<(String, f64)> = scores
            .into_iter()
            .map(|(id, s)| (id, s.posterior_mean))
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        all_scores.push(sorted);
    }

    for (i, run) in all_scores.iter().enumerate().skip(1) {
        for (j, (id, mean)) in run.iter().enumerate() {
            let (ref_id, ref_mean) = &all_scores[0][j];
            assert_eq!(id, ref_id, "ID mismatch at index {} between run 0 and {}", j, i);
            assert!(
                (mean - ref_mean).abs() < 1e-15,
                "Score for {} differs: {} vs {} (run 0 vs {})",
                id, ref_mean, mean, i
            );
        }
    }
}

#[test]
fn determinism_confidence_tier_assignment() {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 200,
        default_age_days: 30,
    default_data_quality: None,
    });

    let patterns: Vec<AggregatedPattern> = (0..100)
        .map(|i| make_pattern(&format!("p_{}", i), (i * 2 + 1) as u32, (i % 30 + 1) as u32))
        .collect();

    let mut all_tiers: Vec<Vec<(String, String)>> = Vec::new();
    for _ in 0..10 {
        let scores = scorer.score_batch(&patterns, None);
        let mut tiers: Vec<(String, String)> = scores
            .into_iter()
            .map(|(id, s)| (id, s.tier.name().to_string()))
            .collect();
        tiers.sort_by(|a, b| a.0.cmp(&b.0));
        all_tiers.push(tiers);
    }

    for (i, run) in all_tiers.iter().enumerate().skip(1) {
        assert_eq!(
            &all_tiers[0], run,
            "Tier assignments differ between run 0 and run {}",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OUTLIER DETECTION DETERMINISM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_outlier_detection_same_indices() {
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = vec![0.9; 100];
    values[10] = 0.01;
    values[50] = 0.02;
    values[90] = 99.0;

    let mut all_indices: Vec<Vec<usize>> = Vec::new();
    for _ in 0..10 {
        let results = detector.detect(&values);
        let mut indices: Vec<usize> = results.iter().map(|r| r.index).collect();
        indices.sort();
        all_indices.push(indices);
    }

    for (i, run) in all_indices.iter().enumerate().skip(1) {
        assert_eq!(
            &all_indices[0], run,
            "Outlier indices differ between run 0 and run {}",
            i
        );
    }
}

#[test]
fn determinism_outlier_deviation_scores() {
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = (0..50).map(|i| 10.0 + (i as f64) * 0.1).collect();
    values.push(999.0);

    let mut all_scores: Vec<Vec<(usize, f64)>> = Vec::new();
    for _ in 0..10 {
        let results = detector.detect(&values);
        let mut scores: Vec<(usize, f64)> = results
            .iter()
            .map(|r| (r.index, r.deviation_score.value()))
            .collect();
        scores.sort_by_key(|s| s.0);
        all_scores.push(scores);
    }

    for (i, run) in all_scores.iter().enumerate().skip(1) {
        for (j, (idx, score)) in run.iter().enumerate() {
            if j < all_scores[0].len() {
                let (ref_idx, ref_score) = &all_scores[0][j];
                assert_eq!(idx, ref_idx);
                assert!(
                    (score - ref_score).abs() < 1e-15,
                    "Deviation score at index {} differs: {} vs {}",
                    idx, ref_score, score
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVENTION DISCOVERY DETERMINISM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_convention_discovery() {
    let discoverer = ConventionDiscoverer::new();
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 14,
    default_data_quality: None,
    });

    let patterns: Vec<AggregatedPattern> = (0..30)
        .map(|i| make_pattern(&format!("pat_{}", i), (i * 3 + 10) as u32, (i % 15 + 3) as u32))
        .collect();

    let scores = scorer.score_batch(&patterns, None);

    let mut all_conventions: Vec<Vec<(String, String)>> = Vec::new();
    for _ in 0..10 {
        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        let mut conv_data: Vec<(String, String)> = conventions
            .iter()
            .map(|c| (c.pattern_id.clone(), c.category.name().to_string()))
            .collect();
        conv_data.sort_by(|a, b| a.0.cmp(&b.0));
        all_conventions.push(conv_data);
    }

    for (i, run) in all_conventions.iter().enumerate().skip(1) {
        assert_eq!(
            &all_conventions[0], run,
            "Convention discovery differs between run 0 and run {}",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FULL PIPELINE DETERMINISM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_full_pipeline_end_to_end() {
    let matches = build_test_matches();
    let pipeline = AggregationPipeline::with_defaults();
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 100,
        default_age_days: 14,
    default_data_quality: None,
    });
    let detector = OutlierDetector::new();
    let discoverer = ConventionDiscoverer::new();

    // Capture a "fingerprint" of the full pipeline output
    let mut fingerprints: Vec<String> = Vec::new();

    for _ in 0..5 {
        let agg = pipeline.run(&matches);

        let mut pattern_ids: Vec<String> = agg.patterns.iter().map(|p| p.pattern_id.clone()).collect();
        pattern_ids.sort();

        let scores = scorer.score_batch(&agg.patterns, None);
        let mut score_vals: Vec<(String, f64)> = scores
            .iter()
            .map(|(id, s)| (id.clone(), s.posterior_mean))
            .collect();
        score_vals.sort_by(|a, b| a.0.cmp(&b.0));

        let conf_values: Vec<f64> = scores.iter().map(|(_, s)| s.posterior_mean).collect();
        let outliers = detector.detect(&conf_values);
        let mut outlier_indices: Vec<usize> = outliers.iter().map(|o| o.index).collect();
        outlier_indices.sort();

        let conventions = discoverer.discover(&agg.patterns, &scores, 100, 1000);
        let mut conv_ids: Vec<String> = conventions.iter().map(|c| c.pattern_id.clone()).collect();
        conv_ids.sort();

        let fingerprint = format!(
            "pats:{:?}|scores:{:?}|outliers:{:?}|convs:{:?}",
            pattern_ids, score_vals, outlier_indices, conv_ids
        );
        fingerprints.push(fingerprint);
    }

    for (i, fp) in fingerprints.iter().enumerate().skip(1) {
        assert_eq!(
            &fingerprints[0], fp,
            "Full pipeline fingerprint differs between run 0 and run {}",
            i
        );
    }
}
