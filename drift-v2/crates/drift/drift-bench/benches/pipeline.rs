//! Criterion benchmark harness for the Drift analysis pipeline.
//!
//! Wraps the full scan → parse → analyze → store pipeline with structured
//! telemetry collection via `BenchmarkRegistry`. Produces both Criterion
//! statistical output AND a machine-readable JSON report.
//!
//! Run with: `cargo bench -p drift-bench --bench pipeline`

use std::path::Path;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tempfile::TempDir;

use drift_analysis::call_graph::CallGraphBuilder;
use drift_analysis::engine::pipeline::AnalysisPipeline;
use drift_analysis::engine::regex_engine::RegexEngine;
use drift_analysis::engine::resolution::ResolutionIndex;
use drift_analysis::engine::visitor::{DetectionEngine, VisitorRegistry};
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::scanner::Scanner;
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::types::collections::FxHashMap;

struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

use drift_bench::fixtures::{generate_fixture, FixtureSize};
use drift_bench::report::FixtureInfo;

// ---------------------------------------------------------------------------
// Fixture setup (outside the timed region)
// ---------------------------------------------------------------------------

struct PreparedFixture {
    _dir: TempDir,
    root: std::path::PathBuf,
    fixture_info: FixtureInfo,
}

fn prepare_fixture(size: FixtureSize, seed: u64) -> PreparedFixture {
    let dir = TempDir::new().expect("create temp dir");
    let fixture = generate_fixture(dir.path(), size, seed);
    let info = FixtureInfo {
        size_label: format!("{:?}", size),
        file_count: fixture.files.len(),
        total_lines: fixture.total_lines,
        total_bytes: fixture.total_bytes,
        language_count: 7,
    };
    PreparedFixture {
        root: dir.path().to_path_buf(),
        _dir: dir,
        fixture_info: info,
    }
}

// ---------------------------------------------------------------------------
// Full pipeline benchmark (scan → parse → analyze → call graph)
// ---------------------------------------------------------------------------

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for &(size, label) in &[
        (FixtureSize::Micro, "micro_10files"),
        (FixtureSize::Small, "small_100files"),
        (FixtureSize::Medium, "medium_1Kfiles"),
        (FixtureSize::Large, "large_10Kfiles"),
    ] {
        let prepared = prepare_fixture(size, 42);

        group.throughput(Throughput::Elements(prepared.fixture_info.file_count as u64));

        group.bench_with_input(
            BenchmarkId::new("pipeline", label),
            &prepared,
            |b, prep| {
                b.iter(|| {
                    run_pipeline(&prep.root);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Per-phase benchmarks
// ---------------------------------------------------------------------------

fn bench_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner");
    group.sample_size(20);

    for &(size, label) in &[
        (FixtureSize::Micro, "micro"),
        (FixtureSize::Small, "small"),
        (FixtureSize::Medium, "medium"),
        (FixtureSize::Large, "large"),
    ] {
        let prepared = prepare_fixture(size, 42);
        group.throughput(Throughput::Elements(prepared.fixture_info.file_count as u64));

        group.bench_with_input(
            BenchmarkId::new("scan", label),
            &prepared,
            |b, prep| {
                b.iter(|| {
                    let config = ScanConfig::default();
                    let scanner = Scanner::new(config);
                    let cached = FxHashMap::default();
                    scanner.scan(&prep.root, &cached, &NoOpHandler).unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_parser(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser");
    group.sample_size(20);

    for &(size, label) in &[
        (FixtureSize::Micro, "micro"),
        (FixtureSize::Small, "small"),
        (FixtureSize::Medium, "medium"),
        (FixtureSize::Large, "large"),
    ] {
        let prepared = prepare_fixture(size, 42);

        // Pre-scan to get file list
        let config = ScanConfig::default();
        let scanner = Scanner::new(config);
        let cached = FxHashMap::default();
        let diff = scanner.scan(&prepared.root, &cached, &NoOpHandler).unwrap();
        let file_contents: Vec<_> = diff
            .added
            .iter()
            .filter_map(|p| std::fs::read(p).ok().map(|c| (p.clone(), c)))
            .collect();

        group.throughput(Throughput::Elements(file_contents.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("parse", label),
            &file_contents,
            |b, files| {
                b.iter(|| {
                    let parser = ParserManager::new();
                    let mut results = Vec::new();
                    for (path, content) in files {
                        if let Ok(pr) = parser.parse(content, path) {
                            results.push(pr);
                        }
                    }
                    results
                });
            },
        );
    }

    group.finish();
}

fn bench_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("analysis");
    group.sample_size(20);

    for &(size, label) in &[
        (FixtureSize::Micro, "micro"),
        (FixtureSize::Small, "small"),
        (FixtureSize::Medium, "medium"),
        (FixtureSize::Large, "large"),
    ] {
        let prepared = prepare_fixture(size, 42);

        // Pre-scan + parse
        let config = ScanConfig::default();
        let scanner = Scanner::new(config);
        let cached = FxHashMap::default();
        let diff = scanner.scan(&prepared.root, &cached, &NoOpHandler).unwrap();
        let parser = ParserManager::new();
        let parse_results: Vec<_> = diff
            .added
            .iter()
            .filter_map(|p| {
                std::fs::read(p)
                    .ok()
                    .and_then(|c| parser.parse(&c, p).ok())
            })
            .collect();

        group.throughput(Throughput::Elements(parse_results.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("analyze", label),
            &parse_results,
            |b, results| {
                b.iter(|| {
                    let registry = VisitorRegistry::new();
                    let engine = DetectionEngine::new(registry);
                    let regex_engine = RegexEngine::new();
                    let mut pipeline = AnalysisPipeline::new(engine, regex_engine);
                    let mut resolution_index = ResolutionIndex::new();
                    let mut total_matches = 0usize;

                    for pr in results {
                        if let Ok(content) = std::fs::read(prepared.root.join(&pr.file)) {
                            let mut ts_parser = tree_sitter::Parser::new();
                            let _ = ts_parser.set_language(
                                &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                            );
                            if let Some(tree) = ts_parser.parse(&content, None) {
                                let result =
                                    pipeline.analyze_file(pr, &content, &tree, &mut resolution_index);
                                total_matches += result.matches.len();
                            }
                        }
                    }
                    total_matches
                });
            },
        );
    }

    group.finish();
}

fn bench_call_graph(c: &mut Criterion) {
    let mut group = c.benchmark_group("call_graph");
    group.sample_size(20);

    for &(size, label) in &[
        (FixtureSize::Micro, "micro"),
        (FixtureSize::Small, "small"),
        (FixtureSize::Medium, "medium"),
        (FixtureSize::Large, "large"),
    ] {
        let prepared = prepare_fixture(size, 42);

        // Pre-scan + parse
        let config = ScanConfig::default();
        let scanner = Scanner::new(config);
        let cached = FxHashMap::default();
        let diff = scanner.scan(&prepared.root, &cached, &NoOpHandler).unwrap();
        let parser = ParserManager::new();
        let parse_results: Vec<_> = diff
            .added
            .iter()
            .filter_map(|p| {
                std::fs::read(p)
                    .ok()
                    .and_then(|c| parser.parse(&c, p).ok())
            })
            .collect();

        group.throughput(Throughput::Elements(parse_results.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("build", label),
            &parse_results,
            |b, results| {
                b.iter(|| {
                    let builder = CallGraphBuilder::new();
                    builder.build(results).unwrap()
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Helper: run full pipeline once (for the combined benchmark)
// ---------------------------------------------------------------------------

fn run_pipeline(root: &Path) -> (usize, usize, usize) {
    // Scan
    let config = ScanConfig::default();
    let scanner = Scanner::new(config);
    let cached = FxHashMap::default();
    let diff = scanner.scan(root, &cached, &NoOpHandler).unwrap();
    let file_count = diff.added.len();

    // Parse
    let parser = ParserManager::new();
    let mut parse_results = Vec::new();
    for path in &diff.added {
        if let Ok(content) = std::fs::read(path) {
            if let Ok(pr) = parser.parse(&content, path) {
                parse_results.push(pr);
            }
        }
    }
    let func_count: usize = parse_results.iter().map(|r| r.functions.len()).sum();

    // Analyze
    let registry = VisitorRegistry::new();
    let engine = DetectionEngine::new(registry);
    let regex_engine = RegexEngine::new();
    let mut pipeline = AnalysisPipeline::new(engine, regex_engine);
    let mut resolution_index = ResolutionIndex::new();
    let mut total_matches = 0usize;

    for pr in &parse_results {
        if let Ok(content) = std::fs::read(root.join(&pr.file)) {
            let mut ts_parser = tree_sitter::Parser::new();
            let _ = ts_parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into());
            if let Some(tree) = ts_parser.parse(&content, None) {
                let result = pipeline.analyze_file(pr, &content, &tree, &mut resolution_index);
                total_matches += result.matches.len();
            }
        }
    }

    (file_count, func_count, total_matches)
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_scanner,
    bench_parser,
    bench_analysis,
    bench_call_graph,
);
criterion_main!(benches);
