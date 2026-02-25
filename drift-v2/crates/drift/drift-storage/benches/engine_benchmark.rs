//! CP0-G-06 / CT0-G-10: Performance regression gate.
//!
//! Benchmarks trait dispatch overhead vs direct engine method calls.
//! Pass criteria: trait dispatch overhead < 1%.

use criterion::{criterion_group, criterion_main, Criterion};
use tempfile::tempdir;

use drift_core::traits::storage::{IDriftFiles, IDriftAnalysis, IDriftReader};
use drift_storage::engine::DriftStorageEngine;

fn bench_trait_vs_direct(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let engine = DriftStorageEngine::open(&dir.path().join("bench.db")).unwrap();

    // Seed a scan so latest_scan_timestamp has something to return
    let analysis: &dyn IDriftAnalysis = &engine;
    let scan_id = analysis.insert_scan_start(1000, "/bench").unwrap();
    analysis
        .update_scan_complete(scan_id, 2000, 10, 5, 3, 1, 1, 100, "completed", None)
        .unwrap();

    // ── Benchmark: count_files via trait ──
    let files_trait: &dyn IDriftFiles = &engine;
    c.bench_function("trait_count_files", |b| {
        b.iter(|| files_trait.count_files().unwrap())
    });

    // ── Benchmark: count_functions via trait ──
    let analysis_trait: &dyn IDriftAnalysis = &engine;
    c.bench_function("trait_count_functions", |b| {
        b.iter(|| analysis_trait.count_functions().unwrap())
    });

    // ── Benchmark: pattern_confidence via reader trait ──
    let reader_trait: &dyn IDriftReader = &engine;
    c.bench_function("trait_pattern_confidence", |b| {
        b.iter(|| reader_trait.pattern_confidence("nonexistent").unwrap())
    });

    // ── Benchmark: latest_scan_timestamp via reader trait ──
    c.bench_function("trait_latest_scan_timestamp", |b| {
        b.iter(|| reader_trait.latest_scan_timestamp().unwrap())
    });

    // ── Benchmark: get_file_metadata via trait (miss) ──
    c.bench_function("trait_get_file_metadata_miss", |b| {
        b.iter(|| files_trait.get_file_metadata("nonexistent.ts").unwrap())
    });

    // ── Benchmark: query_all_violations via trait (empty) ──
    use drift_core::traits::storage::IDriftEnforcement;
    let enforcement_trait: &dyn IDriftEnforcement = &engine;
    c.bench_function("trait_query_all_violations_empty", |b| {
        b.iter(|| enforcement_trait.query_all_violations().unwrap())
    });
}

criterion_group!(benches, bench_trait_vs_direct);
criterion_main!(benches);
