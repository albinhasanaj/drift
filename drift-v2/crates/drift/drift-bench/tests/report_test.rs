#![allow(unused_variables, unused_assignments)]
//! Tests for the benchmark report system: telemetry collection, KPI computation,
//! JSON serialization, regression detection, and full pipeline report generation.

use std::time::Duration;

use drift_bench::report::{
    BenchmarkRegistry, BenchmarkReport, EnvironmentInfo, FixtureInfo, PhaseMetric,
    RegressionVerdict,
};

// ---------------------------------------------------------------------------
// PhaseMetric
// ---------------------------------------------------------------------------

#[test]
fn phase_metric_computes_derived_fields() {
    let m = PhaseMetric::new("scanner", Duration::from_millis(200), 100, 500_000);
    assert_eq!(m.duration_us, 200_000);
    assert!((m.items_per_second - 500.0).abs() < 1.0);
    assert!((m.bytes_per_second - 2_500_000.0).abs() < 1000.0);
    assert!((m.us_per_item - 2000.0).abs() < 1.0);
}

#[test]
fn phase_metric_zero_items() {
    let m = PhaseMetric::new("empty", Duration::from_millis(10), 0, 0);
    assert_eq!(m.us_per_item, 0.0);
    assert_eq!(m.items_processed, 0);
}

#[test]
fn phase_metric_sub_metrics() {
    let m = PhaseMetric::new("parser", Duration::from_millis(50), 10, 5000)
        .with_sub("functions_per_second", 200.0)
        .with_sub("lines_parsed", 10000.0);
    assert_eq!(m.sub_metrics.len(), 2);
    assert_eq!(m.sub_metrics["functions_per_second"], 200.0);
    assert_eq!(m.sub_metrics["lines_parsed"], 10000.0);
}

// ---------------------------------------------------------------------------
// EnvironmentInfo
// ---------------------------------------------------------------------------

#[test]
fn environment_capture() {
    let env = EnvironmentInfo::capture();
    assert!(!env.os.is_empty());
    assert!(!env.arch.is_empty());
    assert!(env.cpu_count >= 1);
    // In debug test mode
    assert_eq!(env.profile, "debug");
}

// ---------------------------------------------------------------------------
// BenchmarkRegistry lifecycle
// ---------------------------------------------------------------------------

#[test]
fn registry_start_end_phase() {
    let mut reg = BenchmarkRegistry::new();
    reg.start_phase("scanner");
    std::thread::sleep(Duration::from_millis(5));
    let metric = reg.end_phase(50, 10000);
    assert!(metric.is_some());
    let m = metric.unwrap();
    assert_eq!(m.name, "scanner");
    assert!(m.duration_us >= 4000); // at least 4ms
    assert_eq!(m.items_processed, 50);
}

#[test]
fn registry_record_phase_directly() {
    let mut reg = BenchmarkRegistry::new();
    reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(10), 100, 50000));
    reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(50), 100, 50000));
    reg.record_phase(PhaseMetric::new("analysis", Duration::from_millis(30), 200, 50000));
    assert_eq!(reg.phases().len(), 3);
    assert!(reg.phase("parser").is_some());
    assert!(reg.phase("nonexistent").is_none());
}

#[test]
fn registry_end_phase_without_start_returns_none() {
    let mut reg = BenchmarkRegistry::new();
    assert!(reg.end_phase(10, 100).is_none());
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

fn make_sample_registry() -> BenchmarkRegistry {
    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "small".to_string(),
        file_count: 100,
        total_lines: 10_000,
        total_bytes: 400_000,
        language_count: 7,
    });
    reg.set_commit_sha("abc123def456");

    reg.record_phase(
        PhaseMetric::new("scanner", Duration::from_millis(50), 100, 400_000)
            .with_sub("languages_detected", 7.0),
    );
    reg.record_phase(
        PhaseMetric::new("parser", Duration::from_millis(200), 100, 400_000)
            .with_sub("functions_per_second", 2500.0)
            .with_sub("lines_parsed", 50_000.0),
    );
    reg.record_phase(
        PhaseMetric::new("analysis", Duration::from_millis(150), 350, 400_000)
            .with_sub("patterns_per_ms", 2.3),
    );
    reg.record_phase(PhaseMetric::new(
        "call_graph",
        Duration::from_millis(80),
        500,
        0,
    ));
    reg.record_phase(PhaseMetric::new(
        "storage",
        Duration::from_millis(100),
        1200,
        0,
    ));

    reg
}

#[test]
fn report_has_all_phases() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    assert_eq!(report.phases.len(), 5);
    assert_eq!(report.phases[0].name, "scanner");
    assert_eq!(report.phases[4].name, "storage");
}

#[test]
fn report_kpis_computed() {
    let reg = make_sample_registry();
    let report = reg.build_report();

    // files_per_second from scanner phase
    assert!(report.kpis.files_per_second > 0.0);
    // patterns_per_ms from analysis sub_metric
    assert!((report.kpis.patterns_per_ms - 2.3).abs() < 0.01);
    // rows_per_second from storage phase
    assert!(report.kpis.rows_per_second > 0.0);
    // total duration
    assert!(report.kpis.total_duration_us > 0);
}

#[test]
fn report_phase_ratios() {
    let reg = make_sample_registry();
    let report = reg.build_report();

    // parser/scanner ratio should be ~4.0 (200ms / 50ms)
    let ratio = report.kpis.phase_ratios.get("parser/scanner");
    assert!(ratio.is_some());
    assert!((ratio.unwrap() - 4.0).abs() < 0.1);
}

#[test]
fn report_fixture_info() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    assert_eq!(report.fixture.file_count, 100);
    assert_eq!(report.fixture.total_lines, 10_000);
    assert_eq!(report.fixture.language_count, 7);
}

#[test]
fn report_commit_sha() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    assert_eq!(report.commit_sha, Some("abc123def456".to_string()));
}

#[test]
fn report_environment() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    assert!(!report.environment.os.is_empty());
    assert!(report.environment.cpu_count >= 1);
}

#[test]
fn report_timestamp_format() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    // Should be ISO-8601-ish: YYYY-MM-DDTHH:MM:SSZ
    assert!(report.timestamp.contains('T'));
    assert!(report.timestamp.ends_with('Z'));
    assert!(report.timestamp.len() >= 19);
}

// ---------------------------------------------------------------------------
// JSON serialization
// ---------------------------------------------------------------------------

#[test]
fn report_json_roundtrip() {
    let reg = make_sample_registry();
    let report = reg.build_report();

    let json = report.to_json();
    assert!(json.contains("scanner"));
    assert!(json.contains("parser"));
    assert!(json.contains("files_per_second"));

    let parsed: BenchmarkReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.phases.len(), 5);
    assert_eq!(parsed.fixture.file_count, 100);
    assert_eq!(parsed.commit_sha, Some("abc123def456".to_string()));
}

#[test]
fn report_json_compact() {
    let reg = make_sample_registry();
    let report = reg.build_report();

    let compact = report.to_json_compact();
    let pretty = report.to_json();
    assert!(compact.len() < pretty.len());
    // Both should parse
    let _: BenchmarkReport = serde_json::from_str(&compact).unwrap();
}

#[test]
fn report_file_roundtrip() {
    let reg = make_sample_registry();
    let report = reg.build_report();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("benchmark_results.json");
    report.write_to_file(&path).unwrap();

    let loaded = BenchmarkReport::load_from_file(&path).unwrap();
    assert_eq!(loaded.phases.len(), 5);
    assert_eq!(loaded.fixture.file_count, 100);
}

// ---------------------------------------------------------------------------
// Regression detection
// ---------------------------------------------------------------------------

#[test]
fn regression_within_threshold_passes() {
    let mut current = BenchmarkRegistry::new();
    current.record_phase(PhaseMetric::new("scanner", Duration::from_millis(105), 100, 0));

    let mut baseline_reg = BenchmarkRegistry::new();
    baseline_reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 100, 0));
    let baseline = baseline_reg.build_report();

    let verdicts = current.compare_to_baseline(&baseline, 10.0);
    assert_eq!(verdicts.len(), 1);
    assert!(!verdicts[0].regressed, "5% increase should be within 10% threshold");
}

#[test]
fn regression_exceeds_threshold_fails() {
    let mut current = BenchmarkRegistry::new();
    current.record_phase(PhaseMetric::new("scanner", Duration::from_millis(120), 100, 0));

    let mut baseline_reg = BenchmarkRegistry::new();
    baseline_reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 100, 0));
    let baseline = baseline_reg.build_report();

    let verdicts = current.compare_to_baseline(&baseline, 10.0);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].regressed, "20% increase should exceed 10% threshold");
}

#[test]
fn regression_faster_is_ok() {
    let mut current = BenchmarkRegistry::new();
    current.record_phase(PhaseMetric::new("scanner", Duration::from_millis(80), 100, 0));

    let mut baseline_reg = BenchmarkRegistry::new();
    baseline_reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 100, 0));
    let baseline = baseline_reg.build_report();

    let verdicts = current.compare_to_baseline(&baseline, 10.0);
    assert!(!verdicts[0].regressed, "Faster should never be a regression");
    assert!(verdicts[0].change_pct < 0.0, "Change should be negative (improvement)");
}

#[test]
fn regression_multi_phase() {
    let mut current = BenchmarkRegistry::new();
    current.record_phase(PhaseMetric::new("scanner", Duration::from_millis(115), 100, 0));
    current.record_phase(PhaseMetric::new("parser", Duration::from_millis(200), 100, 0));
    current.record_phase(PhaseMetric::new("analysis", Duration::from_millis(90), 100, 0));

    let mut baseline_reg = BenchmarkRegistry::new();
    baseline_reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 100, 0));
    baseline_reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(195), 100, 0));
    baseline_reg.record_phase(PhaseMetric::new("analysis", Duration::from_millis(100), 100, 0));
    let baseline = baseline_reg.build_report();

    let verdicts = current.compare_to_baseline(&baseline, 10.0);
    assert_eq!(verdicts.len(), 3);
    assert!(verdicts[0].regressed, "scanner +15% should regress");
    assert!(!verdicts[1].regressed, "parser +2.6% should be OK");
    assert!(!verdicts[2].regressed, "analysis -10% (faster) should be OK");
}

#[test]
fn regression_missing_baseline_phase_skipped() {
    let mut current = BenchmarkRegistry::new();
    current.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 100, 0));
    current.record_phase(PhaseMetric::new("new_phase", Duration::from_millis(50), 100, 0));

    let mut baseline_reg = BenchmarkRegistry::new();
    baseline_reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 100, 0));
    let baseline = baseline_reg.build_report();

    let verdicts = current.compare_to_baseline(&baseline, 10.0);
    // new_phase has no baseline → should be skipped
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].phase, "scanner");
}

// ---------------------------------------------------------------------------
// Report summary (human-readable)
// ---------------------------------------------------------------------------

#[test]
fn report_summary_contains_key_info() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    let summary = report.summary();

    assert!(summary.contains("DRIFT BENCHMARK REPORT"));
    assert!(summary.contains("scanner"));
    assert!(summary.contains("parser"));
    assert!(summary.contains("analysis"));
    assert!(summary.contains("storage"));
    assert!(summary.contains("files/s"));
    assert!(summary.contains("LOC/s"));
    assert!(summary.contains("patterns/ms"));
}

#[test]
fn report_summary_with_regressions() {
    let reg = make_sample_registry();
    let mut report = reg.build_report();
    report.regressions.push(RegressionVerdict {
        phase: "scanner".to_string(),
        current_us: 120_000,
        baseline_us: 100_000,
        change_pct: 20.0,
        threshold_pct: 10.0,
        regressed: true,
    });

    let summary = report.summary();
    assert!(summary.contains("REGRESSED"));
    assert!(summary.contains("scanner"));
}

#[test]
fn report_has_regressions_flag() {
    let reg = make_sample_registry();
    let report = reg.build_report();
    assert!(!report.has_regressions());

    let mut report_with_reg = report.clone();
    report_with_reg.regressions.push(RegressionVerdict {
        phase: "test".to_string(),
        current_us: 200,
        baseline_us: 100,
        change_pct: 100.0,
        threshold_pct: 10.0,
        regressed: true,
    });
    assert!(report_with_reg.has_regressions());
}

// ---------------------------------------------------------------------------
// Full pipeline report generation (integration)
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_report_generation() {
    use drift_analysis::parsers::manager::ParserManager;
    use drift_analysis::scanner::Scanner;
    use drift_core::config::ScanConfig;
    use drift_core::events::handler::DriftEventHandler;
    use drift_core::types::collections::FxHashMap;

    struct NoOpHandler;
    impl DriftEventHandler for NoOpHandler {}

    let dir = tempfile::tempdir().unwrap();
    let fixture = drift_bench::fixtures::generate_fixture(dir.path(), drift_bench::fixtures::FixtureSize::Micro, 42);

    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "Micro".to_string(),
        file_count: fixture.files.len(),
        total_lines: fixture.total_lines,
        total_bytes: fixture.total_bytes,
        language_count: 7,
    });

    // Phase 1: Scan
    reg.start_phase("scanner");
    let config = ScanConfig::default();
    let scanner = Scanner::new(config);
    let cached = FxHashMap::default();
    let diff = scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();
    let scan_metric = reg.end_phase(diff.added.len() as u64, fixture.total_bytes as u64);
    assert!(scan_metric.is_some());

    // Phase 2: Parse
    reg.start_phase("parser");
    let parser = ParserManager::new();
    let mut parse_results = Vec::new();
    let mut total_functions = 0u64;
    for path in &diff.added {
        if let Ok(content) = std::fs::read(path) {
            if let Ok(pr) = parser.parse(&content, path) {
                total_functions += pr.functions.len() as u64;
                parse_results.push(pr);
            }
        }
    }
    let parse_metric = reg.end_phase(parse_results.len() as u64, fixture.total_bytes as u64);
    assert!(parse_metric.is_some());

    // Build report
    let report = reg.build_report();

    // Validate report structure
    assert_eq!(report.phases.len(), 2);
    assert!(report.kpis.files_per_second > 0.0);
    assert!(report.kpis.total_duration_us > 0);
    assert_eq!(report.fixture.file_count, fixture.files.len());

    // JSON output
    let json = report.to_json();
    let parsed: BenchmarkReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.phases.len(), 2);

    // Summary output
    let summary = report.summary();
    eprintln!("{}", summary);
    assert!(summary.contains("DRIFT BENCHMARK REPORT"));

    // Write to file and reload
    let report_path = dir.path().join("benchmark_results.json");
    report.write_to_file(&report_path).unwrap();
    let loaded = BenchmarkReport::load_from_file(&report_path).unwrap();
    assert_eq!(loaded.phases.len(), 2);

    eprintln!("[BenchReport] Full pipeline report generation test passed");
}
