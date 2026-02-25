//! Enterprise-grade benchmark tests: scalability analysis, memory profiling,
//! performance budgets, trend ledger, and full pipeline report with all KPIs.

use std::time::Duration;

use drift_bench::report::{
    analyze_scalability, BenchmarkRegistry, BenchmarkReport, BudgetVerdict, FixtureInfo,
    MemoryDelta, MemorySnapshot, PerformanceBudget, PhaseBudget, PhaseMetric, ScalabilityResult,
    TrendLedger,
};

// ===========================================================================
// Scalability analysis
// ===========================================================================

#[test]
fn scalability_linear_detected() {
    // Perfect linear: 10 files → 100µs, 100 files → 1000µs, 1000 files → 10000µs
    let result = analyze_scalability("scanner", &[
        (10, 100),
        (100, 1000),
        (1000, 10000),
    ]);
    eprintln!("[Scalability] scanner: exponent={:.3}, R²={:.3}, linear={}",
        result.scaling_exponent, result.r_squared, result.is_linear);
    assert!(result.is_linear, "Perfect linear data should be detected as linear");
    assert!((result.scaling_exponent - 1.0).abs() < 0.1, "Exponent should be ~1.0");
    assert!(result.r_squared > 0.99, "R² should be near-perfect for exact linear data");
}

#[test]
fn scalability_quadratic_detected() {
    // Quadratic: 10 → 100, 100 → 10000, 1000 → 1000000
    let result = analyze_scalability("bad_phase", &[
        (10, 100),
        (100, 10000),
        (1000, 1000000),
    ]);
    eprintln!("[Scalability] bad_phase: exponent={:.3}, R²={:.3}, linear={}",
        result.scaling_exponent, result.r_squared, result.is_linear);
    assert!(!result.is_linear, "Quadratic data should NOT be detected as linear");
    assert!((result.scaling_exponent - 2.0).abs() < 0.1, "Exponent should be ~2.0");
}

#[test]
fn scalability_sublinear_detected() {
    // Sublinear (e.g. cache effects): 10 → 100, 100 → 500, 1000 → 2500
    let result = analyze_scalability("cached_phase", &[
        (10, 100),
        (100, 500),
        (1000, 2500),
    ]);
    eprintln!("[Scalability] cached_phase: exponent={:.3}, R²={:.3}, linear={}",
        result.scaling_exponent, result.r_squared, result.is_linear);
    assert!(result.is_linear, "Sublinear should be classified as linear (exponent < 1.3)");
    assert!(result.scaling_exponent < 1.0, "Sublinear exponent should be < 1.0");
}

#[test]
fn scalability_throughput_efficiency() {
    // If throughput stays constant across sizes, efficiency ≈ 1.0
    let result = analyze_scalability("parser", &[
        (10, 100),     // 100K items/s
        (100, 1000),   // 100K items/s
        (1000, 10000), // 100K items/s
    ]);
    assert!((result.throughput_efficiency - 1.0).abs() < 0.01,
        "Constant throughput should have efficiency ~1.0, got {}", result.throughput_efficiency);
}

#[test]
fn scalability_single_point() {
    let result = analyze_scalability("single", &[(100, 5000)]);
    assert_eq!(result.points.len(), 1);
    // With only one point, defaults should be reasonable
    assert!(result.scaling_exponent.is_finite());
}

#[test]
fn scalability_json_roundtrip() {
    let result = analyze_scalability("test", &[
        (10, 100),
        (100, 1000),
    ]);
    let json = serde_json::to_string(&result).unwrap();
    let parsed: ScalabilityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.phase, "test");
    assert_eq!(parsed.points.len(), 2);
}

// ===========================================================================
// Performance budgets
// ===========================================================================

#[test]
fn budget_enterprise_defaults_exist() {
    let budget = PerformanceBudget::enterprise_defaults();
    assert_eq!(budget.budgets.len(), 5, "Should have budgets for 5 phases");
    let phases: Vec<_> = budget.budgets.iter().map(|b| b.phase.as_str()).collect();
    assert!(phases.contains(&"scanner"));
    assert!(phases.contains(&"parser"));
    assert!(phases.contains(&"analysis"));
    assert!(phases.contains(&"call_graph"));
    assert!(phases.contains(&"storage"));
}

#[test]
fn budget_check_passes_within_limits() {
    let budget = PerformanceBudget::new().add(PhaseBudget {
        phase: "scanner".to_string(),
        max_us_per_item: Some(500.0),
        max_total_us: Some(1_000_000),
        max_memory_delta_bytes: None,
        max_scaling_exponent: None,
    });

    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "test".to_string(),
        file_count: 100,
        total_lines: 5000,
        total_bytes: 200000,
        language_count: 3,
    });
    // 100 files in 30ms = 300µs/file → within 500µs budget
    reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(30), 100, 200000));
    let report = reg.build_report();

    let verdicts = budget.check(&report);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].passed, "Should pass: 300µs/file < 500µs budget");
    assert!(verdicts[0].violations.is_empty());
}

#[test]
fn budget_check_fails_over_limit() {
    let budget = PerformanceBudget::new().add(PhaseBudget {
        phase: "scanner".to_string(),
        max_us_per_item: Some(200.0),
        max_total_us: Some(10_000),
        max_memory_delta_bytes: None,
        max_scaling_exponent: None,
    });

    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "test".to_string(),
        file_count: 100,
        total_lines: 5000,
        total_bytes: 200000,
        language_count: 3,
    });
    // 100 files in 50ms = 500µs/file → exceeds 200µs budget
    // total 50000µs → exceeds 10000µs budget
    reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(50), 100, 200000));
    let report = reg.build_report();

    let verdicts = budget.check(&report);
    assert_eq!(verdicts.len(), 1);
    assert!(!verdicts[0].passed, "Should fail: 500µs/file > 200µs budget");
    assert_eq!(verdicts[0].violations.len(), 2, "Should have 2 violations (per-item + total)");
}

#[test]
fn budget_check_scalability() {
    let budget = PerformanceBudget::new()
        .add(PhaseBudget {
            phase: "scanner".to_string(),
            max_us_per_item: None,
            max_total_us: None,
            max_memory_delta_bytes: None,
            max_scaling_exponent: Some(1.3),
        })
        .add(PhaseBudget {
            phase: "bad_phase".to_string(),
            max_us_per_item: None,
            max_total_us: None,
            max_memory_delta_bytes: None,
            max_scaling_exponent: Some(1.3),
        });

    let linear = analyze_scalability("scanner", &[(10, 100), (100, 1000), (1000, 10000)]);
    let quadratic = analyze_scalability("bad_phase", &[(10, 100), (100, 10000), (1000, 1000000)]);

    let verdicts = budget.check_scalability(&[linear, quadratic]);
    assert_eq!(verdicts.len(), 2);
    assert!(verdicts[0].passed, "Linear scanner should pass");
    assert!(!verdicts[1].passed, "Quadratic bad_phase should fail");
    assert!(verdicts[1].violations[0].contains("scaling_exponent"));
}

#[test]
fn budget_missing_phase_skipped() {
    let budget = PerformanceBudget::new().add(PhaseBudget {
        phase: "nonexistent".to_string(),
        max_us_per_item: Some(100.0),
        max_total_us: None,
        max_memory_delta_bytes: None,
        max_scaling_exponent: None,
    });

    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "test".to_string(),
        file_count: 10,
        total_lines: 500,
        total_bytes: 20000,
        language_count: 1,
    });
    reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(10), 10, 20000));
    let report = reg.build_report();

    let verdicts = budget.check(&report);
    assert!(verdicts.is_empty(), "Missing phase should produce no verdict");
}

// ===========================================================================
// Memory profiling
// ===========================================================================

#[test]
fn memory_snapshot_captures() {
    let snap = MemorySnapshot::capture();
    // On macOS/Linux, RSS should be > 0 for a running process
    eprintln!("[Memory] RSS: {:.1}MB, VMS: {:.1}MB",
        snap.rss_mb(), snap.vms_bytes as f64 / (1024.0 * 1024.0));
    assert!(snap.rss_bytes > 0, "RSS should be > 0 on macOS/Linux");
}

#[test]
fn memory_snapshot_rss_mb() {
    let snap = MemorySnapshot { rss_bytes: 104_857_600, vms_bytes: 0 };
    assert!((snap.rss_mb() - 100.0).abs() < 0.01);
}

#[test]
fn memory_delta_tracking() {
    let mut reg = BenchmarkRegistry::new();
    let (_instant, before) = reg.start_phase_with_memory("test_phase");

    // Allocate some memory to create a measurable delta
    let _data: Vec<u8> = vec![0u8; 1024 * 1024]; // 1MB

    let result = reg.end_phase_with_memory(1, 1024 * 1024, &before);
    assert!(result.is_some());
    let (metric, delta) = result.unwrap();
    assert_eq!(metric.name, "test_phase");
    eprintln!("[Memory] Delta: {:.2}MB (before: {:.1}MB, after: {:.1}MB)",
        delta.delta_rss_mb,
        delta.before_rss_bytes as f64 / (1024.0 * 1024.0),
        delta.after_rss_bytes as f64 / (1024.0 * 1024.0));

    // Memory sub-metrics should be recorded on the phase
    assert!(metric.sub_metrics.contains_key("memory_before_rss_mb"));
    assert!(metric.sub_metrics.contains_key("memory_after_rss_mb"));
    assert!(metric.sub_metrics.contains_key("memory_delta_mb"));
}

// ===========================================================================
// Trend ledger
// ===========================================================================

fn make_report_with_scanner(duration_ms: u64, commit: &str) -> BenchmarkReport {
    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "test".to_string(),
        file_count: 100,
        total_lines: 5000,
        total_bytes: 200000,
        language_count: 3,
    });
    reg.set_commit_sha(commit);
    reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(duration_ms), 100, 200000));
    reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(duration_ms * 3), 100, 200000));
    reg.build_report()
}

#[test]
fn trend_ledger_append_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("bench_history.jsonl");
    let ledger = TrendLedger::new(&ledger_path);

    let r1 = make_report_with_scanner(50, "aaa111");
    let r2 = make_report_with_scanner(55, "bbb222");
    let r3 = make_report_with_scanner(48, "ccc333");

    ledger.append(&r1).unwrap();
    ledger.append(&r2).unwrap();
    ledger.append(&r3).unwrap();

    let all = ledger.read_all().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].commit_sha, Some("aaa111".to_string()));
    assert_eq!(all[2].commit_sha, Some("ccc333".to_string()));
}

#[test]
fn trend_ledger_last_n() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(dir.path().join("history.jsonl"));

    for i in 0..10 {
        let r = make_report_with_scanner(50 + i, &format!("sha_{}", i));
        ledger.append(&r).unwrap();
    }

    let last3 = ledger.last_n(3).unwrap();
    assert_eq!(last3.len(), 3);
    assert_eq!(last3[0].commit_sha, Some("sha_7".to_string()));
    assert_eq!(last3[2].commit_sha, Some("sha_9".to_string()));
}

#[test]
fn trend_ledger_phase_trend() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(dir.path().join("history.jsonl"));

    for i in 0..5 {
        let r = make_report_with_scanner(50 + i * 10, &format!("sha_{}", i));
        ledger.append(&r).unwrap();
    }

    let trend = ledger.phase_trend("scanner").unwrap();
    assert_eq!(trend.len(), 5);
    // Durations should increase: 50ms, 60ms, 70ms, 80ms, 90ms
    assert!(trend[0].1 < trend[4].1);
}

#[test]
fn trend_ledger_sustained_regression_detected() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(dir.path().join("history.jsonl"));

    // 4 fast runs, then 4 slow runs (>5% regression)
    for _ in 0..4 {
        ledger.append(&make_report_with_scanner(100, "fast")).unwrap();
    }
    for _ in 0..4 {
        ledger.append(&make_report_with_scanner(120, "slow")).unwrap(); // +20%
    }

    let regression = ledger.detect_sustained_regression("scanner", 4).unwrap();
    assert!(regression.is_some(), "Should detect sustained regression");
    let pct = regression.unwrap();
    eprintln!("[Trend] Sustained regression: {:.1}%", pct);
    assert!(pct > 15.0, "Should detect ~20% regression");
}

#[test]
fn trend_ledger_no_regression_when_stable() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(dir.path().join("history.jsonl"));

    for _ in 0..8 {
        ledger.append(&make_report_with_scanner(100, "stable")).unwrap();
    }

    let regression = ledger.detect_sustained_regression("scanner", 4).unwrap();
    assert!(regression.is_none(), "Stable runs should not trigger regression");
}

#[test]
fn trend_ledger_insufficient_data() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(dir.path().join("history.jsonl"));

    ledger.append(&make_report_with_scanner(100, "only_one")).unwrap();

    let regression = ledger.detect_sustained_regression("scanner", 4).unwrap();
    assert!(regression.is_none(), "Insufficient data should return None");
}

#[test]
fn trend_ledger_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(dir.path().join("empty.jsonl"));
    std::fs::write(dir.path().join("empty.jsonl"), "").unwrap();

    let all = ledger.read_all().unwrap();
    assert!(all.is_empty());
}

#[test]
fn trend_ledger_malformed_lines_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.jsonl");
    let ledger = TrendLedger::new(&path);

    ledger.append(&make_report_with_scanner(100, "good1")).unwrap();
    // Inject a malformed line
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(f, "{{not valid json}}").unwrap();
    ledger.append(&make_report_with_scanner(110, "good2")).unwrap();

    let all = ledger.read_all().unwrap();
    assert_eq!(all.len(), 2, "Should skip malformed line and read 2 valid reports");
}

// ===========================================================================
// Enterprise summary rendering
// ===========================================================================

#[test]
fn enterprise_summary_renders_all_sections() {
    let mut reg = BenchmarkRegistry::new();
    reg.set_fixture(FixtureInfo {
        size_label: "Small".to_string(),
        file_count: 100,
        total_lines: 10000,
        total_bytes: 400000,
        language_count: 7,
    });
    reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(50), 100, 400000));
    reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(200), 100, 400000));
    reg.record_phase(PhaseMetric::new("analysis", Duration::from_millis(150), 350, 400000));
    let report = reg.build_report();

    let scalability = vec![
        analyze_scalability("scanner", &[(10, 500), (100, 5000), (1000, 50000)]),
        analyze_scalability("parser", &[(10, 2000), (100, 20000), (1000, 200000)]),
    ];

    let budgets = vec![
        BudgetVerdict { phase: "scanner".to_string(), passed: true, violations: vec![] },
        BudgetVerdict { phase: "parser".to_string(), passed: true, violations: vec![] },
        BudgetVerdict {
            phase: "analysis".to_string(),
            passed: false,
            violations: vec!["us_per_item: 428.6 > 400.0 budget".to_string()],
        },
    ];

    let memory = vec![
        MemoryDelta {
            phase: "scanner".to_string(),
            before_rss_bytes: 50 * 1024 * 1024,
            after_rss_bytes: 55 * 1024 * 1024,
            delta_rss_bytes: 5 * 1024 * 1024,
            delta_rss_mb: 5.0,
        },
        MemoryDelta {
            phase: "parser".to_string(),
            before_rss_bytes: 55 * 1024 * 1024,
            after_rss_bytes: 120 * 1024 * 1024,
            delta_rss_bytes: 65 * 1024 * 1024,
            delta_rss_mb: 65.0,
        },
    ];

    let summary = report.enterprise_summary(&scalability, &budgets, &memory);
    eprintln!("{}", summary);

    assert!(summary.contains("DRIFT BENCHMARK REPORT"));
    assert!(summary.contains("MEMORY PROFILE"));
    assert!(summary.contains("SCALABILITY ANALYSIS"));
    assert!(summary.contains("PERFORMANCE BUDGETS"));
    assert!(summary.contains("LINEAR"));
    assert!(summary.contains("PASS"));
    assert!(summary.contains("FAIL"));
    assert!(summary.contains("+5.0MB"));
    assert!(summary.contains("+65.0MB"));
}

// ===========================================================================
// Full pipeline enterprise benchmark (integration)
// ===========================================================================

#[test]
fn enterprise_full_pipeline_benchmark() {
    use drift_analysis::parsers::manager::ParserManager;
    use drift_analysis::scanner::Scanner;
    use drift_core::config::ScanConfig;
    use drift_core::events::handler::DriftEventHandler;
    use drift_core::types::collections::FxHashMap;

    struct NoOpHandler;
    impl DriftEventHandler for NoOpHandler {}

    let mut scalability_points: Vec<(u64, u64)> = Vec::new();
    let mut memory_deltas: Vec<MemoryDelta> = Vec::new();

    // Run across two fixture sizes for scalability analysis
    for &(size, seed) in &[
        (drift_bench::fixtures::FixtureSize::Micro, 42u64),
        (drift_bench::fixtures::FixtureSize::Small, 42u64),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = drift_bench::fixtures::generate_fixture(dir.path(), size, seed);

        let mut reg = BenchmarkRegistry::new();
        reg.set_fixture(FixtureInfo {
            size_label: format!("{:?}", size),
            file_count: fixture.files.len(),
            total_lines: fixture.total_lines,
            total_bytes: fixture.total_bytes,
            language_count: 7,
        });

        // Scanner with memory tracking
        let (_instant, mem_before) = reg.start_phase_with_memory("scanner");
        let config = ScanConfig::default();
        let scanner = Scanner::new(config);
        let cached = FxHashMap::default();
        let diff = scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();
        let result = reg.end_phase_with_memory(
            diff.added.len() as u64,
            fixture.total_bytes as u64,
            &mem_before,
        );
        if let Some((_metric, delta)) = result {
            memory_deltas.push(delta);
        }

        // Parser with memory tracking
        let (_instant, mem_before) = reg.start_phase_with_memory("parser");
        let parser = ParserManager::new();
        let mut parse_results = Vec::new();
        for path in &diff.added {
            if let Ok(content) = std::fs::read(path) {
                if let Ok(pr) = parser.parse(&content, path) {
                    parse_results.push(pr);
                }
            }
        }
        let result = reg.end_phase_with_memory(
            parse_results.len() as u64,
            fixture.total_bytes as u64,
            &mem_before,
        );
        if let Some((_metric, delta)) = result {
            memory_deltas.push(delta);
        }

        let report = reg.build_report();

        // Collect scalability data point for scanner
        if let Some(scanner_phase) = report.phases.iter().find(|p| p.name == "scanner") {
            scalability_points.push((fixture.files.len() as u64, scanner_phase.duration_us));
        }

        eprintln!("[Enterprise] {:?}: {} files, scanner={:.1}ms, parser={:.1}ms",
            size,
            fixture.files.len(),
            report.phases[0].duration_us as f64 / 1000.0,
            report.phases[1].duration_us as f64 / 1000.0,
        );
    }

    // Scalability analysis
    let scalability = vec![
        analyze_scalability("scanner", &scalability_points),
    ];
    eprintln!("[Enterprise] Scanner scaling: O(n^{:.2}), R²={:.3}, linear={}",
        scalability[0].scaling_exponent, scalability[0].r_squared, scalability[0].is_linear);

    // Budget check
    let budget = PerformanceBudget::enterprise_defaults();
    let last_dir = tempfile::tempdir().unwrap();
    let last_fixture = drift_bench::fixtures::generate_fixture(
        last_dir.path(), drift_bench::fixtures::FixtureSize::Micro, 42,
    );
    let mut last_reg = BenchmarkRegistry::new();
    last_reg.set_fixture(FixtureInfo {
        size_label: "Micro".to_string(),
        file_count: last_fixture.files.len(),
        total_lines: last_fixture.total_lines,
        total_bytes: last_fixture.total_bytes,
        language_count: 7,
    });
    last_reg.start_phase("scanner");
    let config = ScanConfig::default();
    let scanner = Scanner::new(config);
    let cached = FxHashMap::default();
    let diff = scanner.scan(last_dir.path(), &cached, &NoOpHandler).unwrap();
    last_reg.end_phase(diff.added.len() as u64, last_fixture.total_bytes as u64);
    last_reg.start_phase("parser");
    let parser = ParserManager::new();
    for path in &diff.added {
        if let Ok(content) = std::fs::read(path) {
            let _ = parser.parse(&content, path);
        }
    }
    last_reg.end_phase(diff.added.len() as u64, last_fixture.total_bytes as u64);
    let final_report = last_reg.build_report();
    let budget_verdicts = budget.check(&final_report);
    let scalability_verdicts = budget.check_scalability(&scalability);

    // All budget + scalability verdicts
    let all_verdicts: Vec<_> = budget_verdicts.iter()
        .chain(scalability_verdicts.iter())
        .cloned()
        .collect();

    // Enterprise summary
    let summary = final_report.enterprise_summary(&scalability, &all_verdicts, &memory_deltas);
    eprintln!("{}", summary);

    // Trend ledger
    let ledger_dir = tempfile::tempdir().unwrap();
    let ledger = TrendLedger::new(ledger_dir.path().join("bench_history.jsonl"));
    ledger.append(&final_report).unwrap();
    let loaded = ledger.read_all().unwrap();
    assert_eq!(loaded.len(), 1);

    // JSON report
    let json = final_report.to_json();
    let parsed: BenchmarkReport = serde_json::from_str(&json).unwrap();
    assert!(parsed.phases.len() >= 2);

    // Assertions
    for v in &budget_verdicts {
        assert!(v.passed, "Phase {} should pass enterprise budget: {:?}", v.phase, v.violations);
    }

    eprintln!("[Enterprise] All enterprise benchmark checks passed");
}
