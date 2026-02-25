//! Scanner benchmarks — T1-INT-03.
//!
//! Benchmarks: cold scan (10K files) and incremental scan (10 changed files).
//! Run with: cargo bench -p drift-analysis --bench scanner_bench

use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use drift_analysis::scanner::Scanner;
use drift_analysis::scanner::types::CachedFileMetadata;
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::types::collections::FxHashMap;
use tempfile::TempDir;

struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

/// Create a temp directory with N TypeScript files.
fn create_test_files(count: usize) -> TempDir {
    let dir = TempDir::new().unwrap();
    for i in 0..count {
        let subdir = dir.path().join(format!("dir_{:03}", i / 100));
        std::fs::create_dir_all(&subdir).ok();
        let content = format!(
            "export function fn_{i}(x: number): number {{ return x * {i}; }}\n"
        );
        std::fs::write(subdir.join(format!("f_{i:05}.ts")), &content).unwrap();
    }
    dir
}

fn scanner_cold_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_cold");
    group.sample_size(10);

    for size in [1000, 5000, 10000] {
        let dir = create_test_files(size);
        let config = ScanConfig::default();
        let cached = FxHashMap::default();

        group.bench_with_input(
            BenchmarkId::new("cold_scan", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let scanner = Scanner::new(config.clone());
                    scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();
                });
            },
        );
    }
    group.finish();
}

fn scanner_incremental_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_incremental");
    group.sample_size(10);

    let dir = create_test_files(10000);
    let config = ScanConfig::default();

    // First scan to build cached metadata
    let scanner = Scanner::new(config.clone());
    let cached_empty = FxHashMap::default();
    let diff = scanner.scan(dir.path(), &cached_empty, &NoOpHandler).unwrap();

    // Build cached metadata from first scan
    let mut cached: FxHashMap<PathBuf, CachedFileMetadata> = FxHashMap::default();
    for (path, entry) in &diff.entries {
        cached.insert(
            path.clone(),
            CachedFileMetadata {
                path: path.clone(),
                content_hash: entry.content_hash,
                mtime_secs: entry.mtime_secs,
                mtime_nanos: entry.mtime_nanos,
                file_size: entry.file_size,
                language: entry.language,
            },
        );
    }

    // Modify 10 files
    for i in 0..10 {
        let subdir = dir.path().join(format!("dir_{:03}", i / 100));
        let content = format!(
            "export function fn_{i}_modified(x: number): number {{ return x + {i}; }}\n"
        );
        std::fs::write(subdir.join(format!("f_{i:05}.ts")), &content).unwrap();
    }

    group.bench_function("incremental_10_changed", |b| {
        b.iter(|| {
            let scanner = Scanner::new(config.clone());
            scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, scanner_cold_scan, scanner_incremental_scan);
criterion_main!(benches);
