//! Tests for drift-bench: fixtures, regression detection, benchmark levels.

use std::fs;

use drift_bench::fixtures::{generate_fixture, FixtureSize, SimpleRng};
use drift_bench::{BenchLevel, BenchResult};

#[test]
fn fixture_micro_creates_10_files() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = generate_fixture(tmp.path(), FixtureSize::Micro, 42);

    assert_eq!(fixture.files.len(), 10);
    assert!(fixture.total_lines > 0);
    assert!(fixture.total_bytes > 0);

    for f in &fixture.files {
        assert!(f.path.exists(), "File should exist: {:?}", f.path);
        let content = fs::read_to_string(&f.path).unwrap();
        assert!(!content.is_empty());
    }
}

#[test]
fn fixture_small_creates_100_files() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = generate_fixture(tmp.path(), FixtureSize::Small, 1);
    assert_eq!(fixture.files.len(), 100);
}

#[test]
fn fixture_deterministic_same_seed() {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let f1 = generate_fixture(tmp1.path(), FixtureSize::Micro, 42);
    let f2 = generate_fixture(tmp2.path(), FixtureSize::Micro, 42);

    assert_eq!(f1.files.len(), f2.files.len());
    assert_eq!(f1.total_lines, f2.total_lines);
    assert_eq!(f1.total_bytes, f2.total_bytes);

    for (a, b) in f1.files.iter().zip(f2.files.iter()) {
        let ca = fs::read_to_string(&a.path).unwrap();
        let cb = fs::read_to_string(&b.path).unwrap();
        assert_eq!(ca, cb, "Same seed should produce identical files");
    }
}

#[test]
fn fixture_different_seeds_differ() {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let f1 = generate_fixture(tmp1.path(), FixtureSize::Micro, 42);
    let f2 = generate_fixture(tmp2.path(), FixtureSize::Micro, 99);

    let c1 = fs::read_to_string(&f1.files[0].path).unwrap();
    let c2 = fs::read_to_string(&f2.files[0].path).unwrap();
    assert_ne!(c1, c2);
}

#[test]
fn regression_detection_within_threshold() {
    let baseline = BenchResult {
        name: "scan_10k".to_string(),
        level: BenchLevel::Regression,
        duration_ms: 100.0,
        iterations: 10,
        throughput: None,
    };

    // 5% slower — within 10% threshold → no regression
    let ok = BenchResult {
        duration_ms: 105.0,
        ..baseline.clone()
    };
    assert!(!ok.regresses_vs(&baseline));
}

#[test]
fn regression_detection_exceeds_threshold() {
    let baseline = BenchResult {
        name: "scan_10k".to_string(),
        level: BenchLevel::Regression,
        duration_ms: 100.0,
        iterations: 10,
        throughput: None,
    };

    // 15% slower — exceeds 10% threshold → regression
    let bad = BenchResult {
        duration_ms: 115.0,
        ..baseline.clone()
    };
    assert!(bad.regresses_vs(&baseline));
}

#[test]
fn regression_faster_is_ok() {
    let baseline = BenchResult {
        name: "scan_10k".to_string(),
        level: BenchLevel::Regression,
        duration_ms: 100.0,
        iterations: 10,
        throughput: None,
    };

    let faster = BenchResult {
        duration_ms: 80.0,
        ..baseline.clone()
    };
    assert!(!faster.regresses_vs(&baseline));
}

#[test]
fn regression_zero_baseline_no_panic() {
    let baseline = BenchResult {
        name: "test".to_string(),
        level: BenchLevel::Micro,
        duration_ms: 0.0,
        iterations: 0,
        throughput: None,
    };

    let current = BenchResult {
        duration_ms: 100.0,
        ..baseline.clone()
    };
    // Should not panic or regress on zero baseline
    assert!(!current.regresses_vs(&baseline));
}

#[test]
fn bench_level_properties() {
    assert_eq!(BenchLevel::Micro.as_str(), "micro");
    assert_eq!(BenchLevel::Component.as_str(), "component");
    assert_eq!(BenchLevel::System.as_str(), "system");
    assert_eq!(BenchLevel::Regression.as_str(), "regression");

    assert!(!BenchLevel::Micro.blocks_ci());
    assert!(!BenchLevel::Component.blocks_ci());
    assert!(!BenchLevel::System.blocks_ci());
    assert!(BenchLevel::Regression.blocks_ci());

    // Regression has tightest threshold
    assert!(BenchLevel::Regression.regression_threshold() < BenchLevel::Micro.regression_threshold());
}

#[test]
fn rng_deterministic() {
    let mut r1 = SimpleRng::new(42);
    let mut r2 = SimpleRng::new(42);
    for _ in 0..100 {
        assert_eq!(r1.next_u64(), r2.next_u64());
    }
}

#[test]
fn rng_zero_seed_handled() {
    // Seed 0 should not produce all zeros
    let mut rng = SimpleRng::new(0);
    let val = rng.next_u64();
    assert_ne!(val, 0);
}
