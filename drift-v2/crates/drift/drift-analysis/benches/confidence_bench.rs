//! T3-INT-05: Confidence scoring benchmark (1K, 10K, 100K patterns).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use drift_analysis::engine::types::PatternCategory;
use drift_analysis::patterns::aggregation::types::{AggregatedPattern, PatternLocation};
use drift_analysis::patterns::confidence::scorer::{ConfidenceScorer, ScorerConfig};

fn make_patterns(n: usize) -> Vec<AggregatedPattern> {
    (0..n)
        .map(|i| {
            let locations = ((i % 50) + 5) as u32;
            let files = ((i % 20) + 2) as u32;
            let locs: Vec<PatternLocation> = (0..locations)
                .map(|j| PatternLocation {
                    file: format!("file_{}.ts", j % files),
                    line: j + 1,
                    column: 0,
                    confidence: 0.7 + ((j % 30) as f32) * 0.01,
                    is_outlier: false,
                    matched_text: None,
                })
                .collect();
            AggregatedPattern {
                pattern_id: format!("pattern_{}", i),
                category: PatternCategory::Structural,
                location_count: locations,
                outlier_count: 0,
                file_spread: files,
                hierarchy: None,
                locations: locs,
                aliases: Vec::new(),
                merged_from: Vec::new(),
                confidence_mean: 0.85,
                confidence_stddev: 0.05,
                confidence_values: vec![0.85; locations as usize],
                is_dirty: false,
                location_hash: 0,
            }
        })
        .collect()
}

fn bench_confidence_scoring(c: &mut Criterion) {
    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files: 1000,
        default_age_days: 14,
        default_data_quality: None,
    });

    let patterns_1k = make_patterns(1_000);
    let patterns_10k = make_patterns(10_000);

    c.bench_function("confidence_1k_patterns", |b| {
        b.iter(|| {
            let scores = scorer.score_batch(black_box(&patterns_1k), None);
            black_box(scores);
        })
    });

    c.bench_function("confidence_10k_patterns", |b| {
        b.iter(|| {
            let scores = scorer.score_batch(black_box(&patterns_10k), None);
            black_box(scores);
        })
    });
}

criterion_group!(benches, bench_confidence_scoring);
criterion_main!(benches);
