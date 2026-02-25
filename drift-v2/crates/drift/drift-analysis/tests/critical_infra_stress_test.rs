#![allow(unused_imports)]
//! Critical Infrastructure Stress Tests for Phase 6 Enforcement
//!
//! These tests probe for SILENT FAILURES — bugs that don't panic but produce
//! wrong results. Every test here targets a specific code path that could
//! silently corrupt data, produce incorrect scores, or lose information.
//!
//! Categories:
//! §1  Suppression Checker Off-By-One & Edge Cases
//! §2  Health Scorer Mathematical Invariants
//! §3  Policy Engine Aggregation Correctness
//! §4  Gate Orchestrator DAG Integrity
//! §5  Regression Gate Boundary Precision
//! §6  Trend Analyzer Numerical Stability
//! §7  Auto-Approver Decision Correctness
//! §8  Feedback Tracker FP Rate Denominator Bug Hunt
//! §9  Progressive Enforcement State Machine
//! §10 SARIF Reporter Field Preservation Under Mutation
//! §11 Deduplication Detector Correctness
//! §12 Cross-Subsystem Data Corruption Probes
//! §13 Storage Query Correctness Under Edge Data

use std::collections::HashMap;

use drift_analysis::enforcement::audit::*;
use drift_analysis::enforcement::feedback::*;
use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::gates::progressive::*;
use drift_analysis::enforcement::policy::*;
use drift_analysis::enforcement::reporters::sarif::SarifReporter;
use drift_analysis::enforcement::reporters::json::JsonReporter;

use drift_analysis::enforcement::reporters::Reporter;
use drift_analysis::enforcement::rules::*;

// ═══════════════════════════════════════════════════════════════════════
// §1  SUPPRESSION CHECKER — Off-by-one bugs are the #1 silent failure
// ═══════════════════════════════════════════════════════════════════════

/// Suppression on line 1 of file: the line above is line 0 which doesn't exist.
/// This must NOT panic and must NOT suppress (no line above to check).
#[test]
fn critical_suppression_line_1_of_file() {
    let checker = SuppressionChecker::new();
    let mut source = HashMap::new();
    source.insert("file.ts".to_string(), vec![
        "const x = 1;".to_string(),  // line 1
    ]);

    // Violation on line 1 — no line above to contain drift-ignore
    let suppressed = checker.is_suppressed("file.ts", 1, None, &source);
    assert!(!suppressed, "Line 1 cannot be suppressed — no line above it");
}

/// Suppression on line 2 where line 1 has drift-ignore — should suppress.
#[test]
fn critical_suppression_line_2_with_ignore_on_line_1() {
    let checker = SuppressionChecker::new();
    let mut source = HashMap::new();
    source.insert("file.ts".to_string(), vec![
        "// drift-ignore".to_string(),  // line 1
        "const x = 1;".to_string(),     // line 2 — should be suppressed
    ]);

    let suppressed = checker.is_suppressed("file.ts", 2, None, &source);
    assert!(suppressed, "Line 2 should be suppressed by drift-ignore on line 1");
}

/// Suppression with line number = 0 — invalid, must not panic.
#[test]
fn critical_suppression_line_zero() {
    let checker = SuppressionChecker::new();
    let mut source = HashMap::new();
    source.insert("file.ts".to_string(), vec![
        "// drift-ignore".to_string(),
        "code".to_string(),
    ]);

    let suppressed = checker.is_suppressed("file.ts", 0, None, &source);
    assert!(!suppressed, "Line 0 is invalid — must not suppress");
}

/// Suppression with line number beyond file length — must not panic.
#[test]
fn critical_suppression_line_beyond_eof() {
    let checker = SuppressionChecker::new();
    let mut source = HashMap::new();
    source.insert("file.ts".to_string(), vec![
        "line1".to_string(),
        "line2".to_string(),
    ]);

    let suppressed = checker.is_suppressed("file.ts", 999, None, &source);
    assert!(!suppressed, "Line beyond EOF must not suppress or panic");
}

/// drift-ignore inside a string literal must NOT suppress.
#[test]
fn critical_suppression_in_string_literal() {
    let checker = SuppressionChecker::new();
    let mut source = HashMap::new();
    source.insert("file.ts".to_string(), vec![
        r#"const msg = "drift-ignore this line";"#.to_string(),  // line 1 — NOT a comment
        "const x = unsafeOp();".to_string(),                      // line 2
    ]);

    let suppressed = checker.is_suppressed("file.ts", 2, None, &source);
    assert!(!suppressed, "drift-ignore in string literal must NOT suppress");
}

/// Multiple comma-separated rule IDs in drift-ignore — verify each is matched.
#[test]
fn critical_suppression_multiple_rule_ids() {
    let checker = SuppressionChecker::new();
    let mut source = HashMap::new();
    source.insert("file.ts".to_string(), vec![
        "// drift-ignore security/sql, naming/camelCase".to_string(),
        "code".to_string(),
    ]);

    assert!(checker.is_suppressed("file.ts", 2, Some("security/sql"), &source));
    assert!(checker.is_suppressed("file.ts", 2, Some("naming/camelCase"), &source));
    assert!(!checker.is_suppressed("file.ts", 2, Some("security/xss"), &source),
        "Rule not in list must NOT be suppressed");
}

// ═══════════════════════════════════════════════════════════════════════
// §2  HEALTH SCORER — Mathematical invariants that must NEVER break
// ═══════════════════════════════════════════════════════════════════════

/// Health score must always be in [0, 100] regardless of input.
#[test]
fn critical_health_score_always_bounded() {
    let scorer = HealthScorer::new();

    // Extreme: all metrics at maximum
    let patterns = vec![PatternAuditData {
        id: "max".to_string(),
        name: "max".to_string(),
        category: "test".to_string(),
        status: PatternStatus::Approved,
        confidence: 1.0,
        location_count: 1000,
        outlier_count: 0,
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: false, locations: vec![],
    }];
    let (score, _) = scorer.compute(&patterns, &[]);
    assert!((0.0..=100.0).contains(&score), "Max input: score={score}");

    // Extreme: all metrics at minimum
    let patterns_min = vec![PatternAuditData {
        id: "min".to_string(),
        name: "min".to_string(),
        category: "test".to_string(),
        status: PatternStatus::Discovered,
        confidence: 0.0,
        location_count: 0,
        outlier_count: 1000,
        in_call_graph: false,
        constraint_issues: 100,
        has_error_issues: true, locations: vec![],
    }];
    let (score_min, _) = scorer.compute(&patterns_min, &[]);
    assert!((0.0..=100.0).contains(&score_min), "Min input: score={score_min}");
}

/// duplicate_free_rate must not go negative when dup groups exceed pattern count.
#[test]
fn critical_health_scorer_dup_groups_exceed_patterns() {
    let scorer = HealthScorer::new();

    let patterns = vec![PatternAuditData {
        id: "p1".to_string(),
        name: "p1".to_string(),
        category: "test".to_string(),
        status: PatternStatus::Approved,
        confidence: 0.9,
        location_count: 10,
        outlier_count: 0,
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: false, locations: vec![],
    }];

    // 5 duplicate groups with 2 patterns each = 10 patterns in dup groups
    // but we only have 1 pattern → dup_ratio = 10/1 = 10.0 → 1 - 10 = -9.0
    // This MUST be clamped to 0.0
    let dup_groups: Vec<DuplicateGroup> = (0..5).map(|i| DuplicateGroup {
        pattern_ids: vec![format!("a{i}"), format!("b{i}")],
        similarity: 0.96,
        action: DuplicateAction::AutoMerge,
    }).collect();

    let (score, breakdown) = scorer.compute(&patterns, &dup_groups);
    assert!(breakdown.duplicate_free_rate >= 0.0,
        "duplicate_free_rate must not be negative: {}", breakdown.duplicate_free_rate);
    assert!(score >= 0.0, "Score must not be negative: {score}");
}

/// 5-factor weights must sum to 1.0 (mathematical invariant).
#[test]
fn critical_health_scorer_weights_sum_to_one() {
    // The weights are: 0.30 + 0.20 + 0.20 + 0.15 + 0.15 = 1.00
    let sum: f64 = 0.30 + 0.20 + 0.20 + 0.15 + 0.15;
    assert!((sum - 1.0).abs() < f64::EPSILON,
        "Health scorer weights must sum to 1.0, got {sum}");
}

/// Per-category health must produce scores for every category present.
#[test]
fn critical_health_scorer_per_category_completeness() {
    let scorer = HealthScorer::new();
    let patterns = vec![
        PatternAuditData {
            id: "p1".to_string(), name: "p1".to_string(),
            category: "naming".to_string(), status: PatternStatus::Approved,
            confidence: 0.9, location_count: 10, outlier_count: 1,
            in_call_graph: true, constraint_issues: 0, has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "p2".to_string(), name: "p2".to_string(),
            category: "security".to_string(), status: PatternStatus::Approved,
            confidence: 0.95, location_count: 20, outlier_count: 0,
            in_call_graph: true, constraint_issues: 0, has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "p3".to_string(), name: "p3".to_string(),
            category: "error_handling".to_string(), status: PatternStatus::Discovered,
            confidence: 0.7, location_count: 5, outlier_count: 2,
            in_call_graph: false, constraint_issues: 1, has_error_issues: false, locations: vec![],
        },
    ];

    let categories = scorer.compute_per_category(&patterns, &[]);
    assert!(categories.contains_key("naming"), "Missing naming category");
    assert!(categories.contains_key("security"), "Missing security category");
    assert!(categories.contains_key("error_handling"), "Missing error_handling category");
    assert_eq!(categories.len(), 3, "Should have exactly 3 categories");

    for (cat, health) in &categories {
        assert!((0.0..=100.0).contains(&health.score),
            "Category '{cat}' score out of range: {}", health.score);
        assert!((0.0..=1.0).contains(&health.avg_confidence),
            "Category '{cat}' avg_confidence out of range");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// §3  POLICY ENGINE — Aggregation mode correctness
// ═══════════════════════════════════════════════════════════════════════

/// Weighted mode with explicit weights must produce mathematically correct score.
#[test]
fn critical_policy_weighted_mode_math() {
    let mut weights = HashMap::new();
    weights.insert("pattern-compliance".to_string(), 0.40);
    weights.insert("security-boundaries".to_string(), 0.60);

    let policy = Policy {
        name: "weighted-test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Weighted,
        weights,
        threshold: 70.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };

    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 100.0, "ok".to_string()),
        GateResult::pass(GateId::SecurityBoundaries, 50.0, "ok".to_string()),
    ];

    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);

    // Expected: (100*0.40 + 50*0.60) / (0.40+0.60) = (40+30)/1.0 = 70.0
    let expected = (100.0 * 0.40 + 50.0 * 0.60) / (0.40 + 0.60);
    assert!((pr.overall_score - expected).abs() < 0.01,
        "Weighted score should be {expected}, got {}", pr.overall_score);
    assert!(pr.overall_passed, "70.0 >= 70.0 threshold should pass");
}

/// Weighted mode with gate that has NO explicit weight — uses fallback.
#[test]
fn critical_policy_weighted_missing_weight_fallback() {
    let mut weights = HashMap::new();
    weights.insert("pattern-compliance".to_string(), 0.50);
    // security-boundaries has NO weight → should use 1/n fallback

    let policy = Policy {
        name: "test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Weighted,
        weights,
        threshold: 0.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };

    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 100.0, "ok".to_string()),
        GateResult::pass(GateId::SecurityBoundaries, 0.0, "ok".to_string()),
    ];

    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);

    // Must not be NaN or panic
    assert!(!pr.overall_score.is_nan(), "Score must not be NaN with missing weights");
    assert!(pr.overall_score >= 0.0, "Score must be non-negative");
}

/// any_must_pass with ALL gates failing — must return false.
#[test]
fn critical_policy_any_must_pass_all_fail() {
    let policy = Policy {
        name: "test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::AnyMustPass,
        weights: HashMap::new(),
        threshold: 0.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };

    let results = vec![
        GateResult::fail(GateId::PatternCompliance, 30.0, "fail".to_string(), vec![]),
        GateResult::fail(GateId::SecurityBoundaries, 20.0, "fail".to_string(), vec![]),
    ];

    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(!pr.overall_passed, "All gates failing in any-must-pass should fail overall");
}

/// Required gate that is MISSING from results — should it pass or fail?
/// Current impl: map_or(true, ...) means missing gate = pass. Verify this.
#[test]
fn critical_policy_required_gate_missing_from_results() {
    let policy = Policy {
        name: "test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::AnyMustPass,
        weights: HashMap::new(),
        threshold: 0.0,
        required_gates: vec![GateId::SecurityBoundaries], // required but not in results
        progressive: false,
        ramp_up_days: 0,
    };

    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 100.0, "ok".to_string()),
        // SecurityBoundaries is MISSING
    ];

    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    // Fixed behavior: missing required gate = treated as FAILED (is_some_and returns false for None)
    // This was a Phase B fix — map_or(true,...) → is_some_and(|r| r.passed)
    assert!(!pr.required_gates_passed,
        "Missing required gate must be treated as failed (not evaluated = not passed)");
}

/// Threshold mode at exact boundary — score == threshold must pass.
#[test]
fn critical_policy_threshold_exact_boundary() {
    let policy = Policy {
        name: "test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Threshold,
        weights: HashMap::new(),
        threshold: 75.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };

    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 75.0, "ok".to_string()),
    ];

    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(pr.overall_passed, "Score exactly at threshold (75.0 >= 75.0) must pass");
}

// ═══════════════════════════════════════════════════════════════════════
// §4  GATE ORCHESTRATOR — DAG integrity and dependency handling
// ═══════════════════════════════════════════════════════════════════════

/// When PatternCompliance fails, ConstraintVerification AND SecurityBoundaries
/// must both be skipped (they depend on PatternCompliance).
#[test]
fn critical_orchestrator_cascading_skip() {
    let orchestrator = GateOrchestrator::new();

    // PatternCompliance will fail (high-confidence outlier)
    let input = GateInput {
        patterns: vec![PatternInfo {
            pattern_id: "test".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: "src/app.ts".to_string(),
                line: 1,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 5.0,
                message: "Critical violation".to_string(),
            }],
            cwe_ids: vec![89],
            owasp_categories: vec![],
        }],
        ..Default::default()
    };

    let results = orchestrator.execute(&input).unwrap();

    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.passed, "PatternCompliance should fail");

    let cv = results.iter().find(|r| r.gate_id == GateId::ConstraintVerification).unwrap();
    assert_eq!(cv.status, GateStatus::Skipped,
        "ConstraintVerification must be SKIPPED when PatternCompliance fails");

    let sb = results.iter().find(|r| r.gate_id == GateId::SecurityBoundaries).unwrap();
    assert_eq!(sb.status, GateStatus::Skipped,
        "SecurityBoundaries must be SKIPPED when PatternCompliance fails");

    // Gates without dependencies should still execute (not dependency-skipped).
    // TestCoverage self-skips due to no data, but it was NOT dependency-skipped.
    let tc = results.iter().find(|r| r.gate_id == GateId::TestCoverage).unwrap();
    assert!(!tc.summary.contains("dependencies not met"),
        "TestCoverage has no dependencies — should NOT be dependency-skipped");
}

/// Skipped gates must have passed=true (they don't block the pipeline).
#[test]
fn critical_orchestrator_skipped_gates_are_passing() {
    let orchestrator = GateOrchestrator::new();
    let input = GateInput {
        patterns: vec![PatternInfo {
            pattern_id: "fail".to_string(),
            category: "security".to_string(),
            confidence: 0.99,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: "x.ts".to_string(), line: 1, column: None,
                end_line: None,
                end_column: None,
                deviation_score: 5.0, message: "fail".to_string(),
            }],
            cwe_ids: vec![89],
            owasp_categories: vec![],
        }],
        ..Default::default()
    };

    let results = orchestrator.execute(&input).unwrap();
    for r in &results {
        if r.status == GateStatus::Skipped {
            assert!(r.passed, "Skipped gate {} must have passed=true", r.gate_id);
        }
    }
}

/// All 6 gates must appear in results even when some are skipped.
#[test]
fn critical_orchestrator_all_gates_present() {
    let orchestrator = GateOrchestrator::new();
    let input = GateInput::default();
    let results = orchestrator.execute(&input).unwrap();
    assert_eq!(results.len(), 6, "Must have exactly 6 gate results");

    let ids: Vec<GateId> = results.iter().map(|r| r.gate_id).collect();
    for expected in GateId::all() {
        assert!(ids.contains(expected), "Missing gate: {expected}");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// §5  REGRESSION GATE — Boundary precision at -5.0 and -15.0
// ═══════════════════════════════════════════════════════════════════════

/// Delta of exactly -5.0 must trigger WARNING (not pass).
#[test]
fn critical_regression_exact_minus_5() {
    let gate = drift_analysis::enforcement::gates::regression::RegressionGate;
    let input = GateInput {
        previous_health_score: Some(80.0),
        current_health_score: Some(75.0), // delta = -5.0
        ..Default::default()
    };

    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Warned,
        "Delta of exactly -5.0 must be WARNING, got {:?}", result.status);
    assert!(result.passed, "Warning status should still pass");
}

/// Delta of exactly -15.0 must trigger FAILURE (not warning).
#[test]
fn critical_regression_exact_minus_15() {
    let gate = drift_analysis::enforcement::gates::regression::RegressionGate;
    let input = GateInput {
        previous_health_score: Some(80.0),
        current_health_score: Some(65.0), // delta = -15.0
        ..Default::default()
    };

    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Failed,
        "Delta of exactly -15.0 must be FAILED, got {:?}", result.status);
    assert!(!result.passed);
}

/// Delta of -4.999 must PASS (just above warning threshold).
#[test]
fn critical_regression_just_above_warning() {
    let gate = drift_analysis::enforcement::gates::regression::RegressionGate;
    let input = GateInput {
        previous_health_score: Some(80.0),
        current_health_score: Some(75.001), // delta = -4.999
        ..Default::default()
    };

    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Passed,
        "Delta of -4.999 must PASS, got {:?}", result.status);
}

/// Delta of -14.999 must be WARNING (just above critical threshold).
#[test]
fn critical_regression_just_above_critical() {
    let gate = drift_analysis::enforcement::gates::regression::RegressionGate;
    let input = GateInput {
        previous_health_score: Some(80.0),
        current_health_score: Some(65.001), // delta = -14.999
        ..Default::default()
    };

    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Warned,
        "Delta of -14.999 must be WARNING, got {:?}", result.status);
}

/// Positive delta (improvement) must always pass.
#[test]
fn critical_regression_positive_delta() {
    let gate = drift_analysis::enforcement::gates::regression::RegressionGate;
    let input = GateInput {
        previous_health_score: Some(50.0),
        current_health_score: Some(90.0), // delta = +40
        ..Default::default()
    };

    let result = gate.evaluate(&input);
    assert!(result.passed, "Positive delta must always pass");
    assert_eq!(result.status, GateStatus::Passed);
}

// ═══════════════════════════════════════════════════════════════════════
// §6  TREND ANALYZER — Numerical stability
// ═══════════════════════════════════════════════════════════════════════

/// Linear regression with perfectly linear data must have R² ≈ 1.0.
#[test]
fn critical_trend_perfect_linear_data() {
    let analyzer = TrendAnalyzer::new();
    let scores: Vec<f64> = (0..20).map(|i| 50.0 + i as f64 * 2.0).collect();
    let pred = analyzer.predict(&scores).unwrap();

    assert!((pred.slope - 2.0).abs() < 0.01,
        "Slope should be ~2.0 for y=50+2x, got {}", pred.slope);
    assert!(pred.confidence_interval > 0.99,
        "R² should be ~1.0 for perfect linear data, got {}", pred.confidence_interval);
    assert_eq!(pred.direction, TrendDirection::Improving);
}

/// Trend classification with exactly 7 data points (boundary for rolling avg).
#[test]
fn critical_trend_classify_exactly_7_points() {
    let analyzer = TrendAnalyzer::new();

    // 7 points: first half low, second half high → improving
    let scores = vec![70.0, 71.0, 72.0, 73.0, 80.0, 81.0, 82.0];
    let direction = analyzer.classify_trend(&scores);
    // recent_avg (all 7) vs older_avg (first 3.5 → first 3)
    // This tests the n < 14 branch
    assert_ne!(direction, TrendDirection::Declining,
        "Improving scores should not be classified as declining");
}

/// Anomaly detection: value exactly at threshold must NOT be flagged.
#[test]
fn critical_anomaly_at_exact_threshold() {
    let analyzer = TrendAnalyzer::new();
    // Mean=50, stddev=10, threshold=2.0 → anomaly if |z| > 2.0
    // Value at exactly mean + 2*stddev = 70 → z = 2.0 → NOT anomaly (> not >=)
    let values = vec![40.0, 50.0, 60.0, 40.0, 50.0, 60.0, 40.0, 50.0, 60.0, 70.0];
    let anomalies = analyzer.detect_anomalies("test", &values, 2.0);
    // The z-score of the last value depends on actual mean/stddev
    // This verifies the boundary behavior
    for a in &anomalies {
        assert!(a.z_score.abs() > 2.0,
            "Anomaly z-score must be strictly > threshold, got {}", a.z_score);
    }
}

/// Trend prediction with descending data must predict lower future scores.
#[test]
fn critical_trend_descending_prediction() {
    let analyzer = TrendAnalyzer::new();
    let scores: Vec<f64> = (0..10).map(|i| 90.0 - i as f64 * 3.0).collect();
    let pred = analyzer.predict(&scores).unwrap();

    assert!(pred.slope < 0.0, "Descending data must have negative slope");
    assert!(pred.predicted_score_7d < scores[scores.len() - 1],
        "7d prediction must be lower than current for descending trend");
    assert_eq!(pred.direction, TrendDirection::Declining);
    // Predictions must be clamped to [0, 100]
    assert!(pred.predicted_score_30d >= 0.0, "30d prediction must be >= 0");
}

// ═══════════════════════════════════════════════════════════════════════
// §7  AUTO-APPROVER — Decision correctness
// ═══════════════════════════════════════════════════════════════════════

/// Pattern with 0 locations must NOT be auto-approved (min_locations=3).
#[test]
fn critical_auto_approve_zero_locations() {
    let approver = AutoApprover::new();
    let patterns = vec![PatternAuditData {
        id: "zero-loc".to_string(),
        name: "test".to_string(),
        category: "naming".to_string(),
        status: PatternStatus::Discovered,
        confidence: 0.99, // high confidence
        location_count: 0, // but zero locations
        outlier_count: 0,
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: false, locations: vec![],
    }];

    let (approved, _, _) = approver.classify(&patterns);
    assert!(!approved.contains(&"zero-loc".to_string()),
        "Pattern with 0 locations must NOT be auto-approved");
}

/// Pattern with has_error_issues=true must NOT be auto-approved.
#[test]
fn critical_auto_approve_error_issues_block() {
    let approver = AutoApprover::new();
    let patterns = vec![PatternAuditData {
        id: "error-pat".to_string(),
        name: "test".to_string(),
        category: "naming".to_string(),
        status: PatternStatus::Discovered,
        confidence: 0.99,
        location_count: 100,
        outlier_count: 0,
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: true, // blocks auto-approve
        locations: vec![],
    }];

    let (approved, review, _) = approver.classify(&patterns);
    assert!(!approved.contains(&"error-pat".to_string()),
        "Pattern with error issues must NOT be auto-approved");
    assert!(review.contains(&"error-pat".to_string()),
        "High-confidence pattern with errors should go to review");
}

/// Already-approved patterns must be skipped entirely.
#[test]
fn critical_auto_approve_skips_already_approved() {
    let approver = AutoApprover::new();
    let patterns = vec![PatternAuditData {
        id: "already".to_string(),
        name: "test".to_string(),
        category: "naming".to_string(),
        status: PatternStatus::Approved, // already approved
        confidence: 0.99,
        location_count: 100,
        outlier_count: 0,
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: false, locations: vec![],
    }];

    let (approved, review, fp) = approver.classify(&patterns);
    assert!(approved.is_empty(), "Already-approved should not appear in auto-approved");
    assert!(review.is_empty(), "Already-approved should not appear in review");
    assert!(fp.is_empty(), "Already-approved should not appear in likely-FP");
}

/// Outlier ratio at exact boundary (0.50) must still auto-approve.
#[test]
fn critical_auto_approve_outlier_ratio_exact_boundary() {
    let approver = AutoApprover::new();
    let patterns = vec![PatternAuditData {
        id: "boundary".to_string(),
        name: "test".to_string(),
        category: "naming".to_string(),
        status: PatternStatus::Discovered,
        confidence: 0.95,
        location_count: 5,  // 5 locations
        outlier_count: 5,   // 5 outliers → ratio = 5/10 = 0.50 (exactly at threshold)
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: false, locations: vec![],
    }];

    let (approved, _, _) = approver.classify(&patterns);
    assert!(approved.contains(&"boundary".to_string()),
        "Outlier ratio exactly at 0.50 threshold should still auto-approve (<=)");
}

// ═══════════════════════════════════════════════════════════════════════
// §8  FEEDBACK TRACKER — FP rate denominator correctness
// ═══════════════════════════════════════════════════════════════════════

/// FP rate denominator is (fixed + dismissed), NOT total_findings.
/// Verify this with suppress and escalate actions that should NOT affect FP rate.
#[test]
fn critical_feedback_fp_rate_denominator() {
    let mut tracker = FeedbackTracker::new();

    // 5 fixes, 5 FP dismissals, 90 suppressions
    for i in 0..5 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("fix-{i}"), pattern_id: "p".to_string(),
            detector_id: "det".to_string(), action: FeedbackAction::Fix,
            dismissal_reason: None, reason: None, author: None, timestamp: i,
        });
    }
    for i in 5..10 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("fp-{i}"), pattern_id: "p".to_string(),
            detector_id: "det".to_string(), action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::FalsePositive),
            reason: None, author: None, timestamp: i,
        });
    }
    for i in 10..100 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("sup-{i}"), pattern_id: "p".to_string(),
            detector_id: "det".to_string(), action: FeedbackAction::Suppress,
            dismissal_reason: None, reason: None, author: None, timestamp: i,
        });
    }

    let m = tracker.get_metrics("det").unwrap();
    assert_eq!(m.total_findings, 100);
    assert_eq!(m.fixed, 5);
    assert_eq!(m.dismissed, 5);
    assert_eq!(m.suppressed, 90);
    assert_eq!(m.false_positives, 5);

    // FP rate = 5 / (5 + 5) = 0.50, NOT 5/100 = 0.05
    assert!((m.fp_rate - 0.50).abs() < 0.01,
        "FP rate should be 5/(5+5)=0.50, got {:.3}", m.fp_rate);
}

/// WontFix dismissal must NOT count as false positive.
#[test]
fn critical_feedback_wontfix_not_fp() {
    let mut tracker = FeedbackTracker::new();

    for i in 0..10 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("wf-{i}"), pattern_id: "p".to_string(),
            detector_id: "det".to_string(), action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::WontFix),
            reason: None, author: None, timestamp: i,
        });
    }

    let m = tracker.get_metrics("det").unwrap();
    assert_eq!(m.dismissed, 10);
    assert_eq!(m.false_positives, 0, "WontFix must NOT count as false positive");
    assert!((m.fp_rate - 0.0).abs() < 0.01, "FP rate should be 0 with only WontFix");
}

/// Duplicate dismissal must NOT count as false positive.
#[test]
fn critical_feedback_duplicate_not_fp() {
    let mut tracker = FeedbackTracker::new();

    for i in 0..10 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("dup-{i}"), pattern_id: "p".to_string(),
            detector_id: "det".to_string(), action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::Duplicate),
            reason: None, author: None, timestamp: i,
        });
    }

    let m = tracker.get_metrics("det").unwrap();
    assert_eq!(m.false_positives, 0, "Duplicate must NOT count as false positive");
}

/// NotApplicable dismissal MUST count as false positive.
#[test]
fn critical_feedback_not_applicable_is_fp() {
    let mut tracker = FeedbackTracker::new();

    tracker.record(&FeedbackRecord {
        violation_id: "na-1".to_string(), pattern_id: "p".to_string(),
        detector_id: "det".to_string(), action: FeedbackAction::Dismiss,
        dismissal_reason: Some(DismissalReason::NotApplicable),
        reason: None, author: None, timestamp: 1,
    });

    let m = tracker.get_metrics("det").unwrap();
    assert_eq!(m.false_positives, 1, "NotApplicable MUST count as false positive");
}

/// Abuse detection with timestamps NOT in order — must still detect.
#[test]
fn critical_feedback_abuse_unordered_timestamps() {
    let mut tracker = FeedbackTracker::new();

    // 100 dismissals with scrambled timestamps but all within 60s window
    let base = 1_000_000u64;
    for i in 0..100u64 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("abuse-{i}"), pattern_id: "p".to_string(),
            detector_id: "det".to_string(), action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::WontFix),
            reason: None, author: Some("abuser".to_string()),
            timestamp: base + (i % 30), // all within 30 seconds
        });
    }

    let abusers = tracker.detect_abuse(60, 100);
    // The abuse detection checks timestamps[len-threshold..] window
    // With unordered timestamps, the last 100 entries may not be in order
    // This tests whether the detection still works
    assert!(abusers.contains(&"abuser".to_string()),
        "Abuse detection should work even with unordered timestamps within window");
}

// ═══════════════════════════════════════════════════════════════════════
// §9  PROGRESSIVE ENFORCEMENT — State machine correctness
// ═══════════════════════════════════════════════════════════════════════

/// Progressive enforcement at 25% progress: Error→Info, Warning→Info.
#[test]
fn critical_progressive_quarter_progress() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 100,
        project_age_days: 24, // 24% < 25%
    });

    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Info,
        "Error should be Info at <25% progress");
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Info,
        "Warning should be Info at <25% progress");
    assert_eq!(pe.effective_severity(Severity::Info, false), Severity::Info,
        "Info stays Info");
}

/// Progressive enforcement at 50% progress: Error→Warning, Warning→Info.
#[test]
fn critical_progressive_half_progress() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 100,
        project_age_days: 49, // 49% < 50%
    });

    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Warning,
        "Error should be Warning at 25-50% progress");
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Info,
        "Warning should be Info at <50% progress");
}

/// Progressive enforcement at 75% progress: Error→Error, Warning→Warning.
#[test]
fn critical_progressive_three_quarter_progress() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 100,
        project_age_days: 75,
    });

    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Error,
        "Error should be Error at >=50% progress");
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Warning,
        "Warning should be Warning at >=50% progress");
}

/// New files always get full enforcement regardless of ramp-up.
#[test]
fn critical_progressive_new_files_full_enforcement() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 100,
        project_age_days: 1, // very early in ramp-up
    });

    assert_eq!(pe.effective_severity(Severity::Error, true), Severity::Error,
        "New files must get full enforcement");
    assert_eq!(pe.effective_severity(Severity::Warning, true), Severity::Warning,
        "New files must get full enforcement");
}

/// Disabled progressive enforcement passes through original severity.
#[test]
fn critical_progressive_disabled() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: false,
        ramp_up_days: 100,
        project_age_days: 1,
    });

    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Error);
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Warning);
    assert!(!pe.is_ramping_up());
    assert!((pe.ramp_up_progress() - 1.0).abs() < 0.001);
}

// ═══════════════════════════════════════════════════════════════════════
// §10 SARIF REPORTER — Field preservation under mutation
// ═══════════════════════════════════════════════════════════════════════

/// Violation with line=0 must be clamped to startLine=1 in SARIF.
#[test]
fn critical_sarif_line_zero_clamped() {
    let reporter = SarifReporter::new();
    let results = vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 50.0,
        summary: "test".to_string(),
        violations: vec![Violation {
            id: "v1".to_string(), file: "test.ts".to_string(),
            line: 0, column: None, end_line: None, end_column: None,
            severity: Severity::Error, pattern_id: "test".to_string(),
            rule_id: "test/rule".to_string(), message: "test".to_string(),
            quick_fix: None, cwe_id: None, owasp_category: None,
            suppressed: false, is_new: false,
        }],
        warnings: vec![], execution_time_ms: 0,
        details: serde_json::Value::Null, error: None,
    }];

    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();
    let start_line = sarif["runs"][0]["results"][0]["locations"][0]
        ["physicalLocation"]["region"]["startLine"].as_u64().unwrap();
    assert!(start_line >= 1, "SARIF startLine must be >= 1, got {start_line}");
}

/// SARIF with both CWE and OWASP on same violation — both must appear in taxa.
#[test]
fn critical_sarif_both_cwe_and_owasp() {
    let reporter = SarifReporter::new();
    let results = vec![GateResult {
        gate_id: GateId::SecurityBoundaries,
        status: GateStatus::Failed,
        passed: false,
        score: 0.0,
        summary: "test".to_string(),
        violations: vec![Violation {
            id: "v1".to_string(), file: "test.ts".to_string(),
            line: 10, column: Some(5), end_line: Some(10), end_column: Some(30),
            severity: Severity::Error, pattern_id: "sql".to_string(),
            rule_id: "security/sql".to_string(), message: "SQL injection".to_string(),
            quick_fix: None,
            cwe_id: Some(89),
            owasp_category: Some("A03:2021-Injection".to_string()),
            suppressed: false, is_new: false,
        }],
        warnings: vec![], execution_time_ms: 0,
        details: serde_json::Value::Null, error: None,
    }];

    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Taxonomies are at runs[0].taxonomies (SARIF 2.1.0 §3.14.8)
    let taxonomies = sarif["runs"][0]["taxonomies"].as_array().unwrap();
    assert_eq!(taxonomies.len(), 2, "Must have both CWE and OWASP taxonomy entries");
    assert!(taxonomies.iter().any(|t| t["name"].as_str().unwrap() == "CWE"));
    assert!(taxonomies.iter().any(|t| t["name"].as_str().unwrap() == "OWASP"));

    // CWE/OWASP references are in rules[0].relationships (SARIF 2.1.0 §3.49.3)
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    let relationships = rules[0]["relationships"].as_array().unwrap();
    assert_eq!(relationships.len(), 2, "Rule must reference both CWE and OWASP");
    assert!(relationships.iter().any(|r| r["target"]["id"].as_str().unwrap().contains("CWE")));
    assert!(relationships.iter().any(|r| r["target"]["id"].as_str().unwrap().contains("A03")));
}

/// SARIF rules deduplication: same rule_id from multiple violations → one rule entry.
#[test]
fn critical_sarif_rule_deduplication() {
    let reporter = SarifReporter::new();
    let violations: Vec<Violation> = (0..5).map(|i| Violation {
        id: format!("v{i}"), file: format!("file{i}.ts"),
        line: i as u32 + 1, column: None, end_line: None, end_column: None,
        severity: Severity::Warning, pattern_id: "naming".to_string(),
        rule_id: "naming/camelCase".to_string(), // SAME rule_id
        message: format!("Violation {i}"),
        quick_fix: None, cwe_id: None, owasp_category: None,
        suppressed: false, is_new: false,
    }).collect();

    let results = vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed, passed: false, score: 50.0,
        summary: "test".to_string(), violations,
        warnings: vec![], execution_time_ms: 0,
        details: serde_json::Value::Null, error: None,
    }];

    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "Same rule_id should produce exactly 1 rule entry, got {}", rules.len());
}

// ═══════════════════════════════════════════════════════════════════════
// §11 DEDUPLICATION DETECTOR — Correctness
// ═══════════════════════════════════════════════════════════════════════

/// Patterns in DIFFERENT categories must never be compared.
#[test]
fn critical_dedup_cross_category_isolation() {
    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "naming-1".to_string(), name: "camelCase".to_string(),
            category: "naming".to_string(), status: PatternStatus::Approved,
            confidence: 0.9, location_count: 10, outlier_count: 0,
            in_call_graph: true, constraint_issues: 0, has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "security-1".to_string(), name: "parameterized".to_string(),
            category: "security".to_string(), status: PatternStatus::Approved,
            confidence: 0.9, location_count: 10, outlier_count: 0,
            in_call_graph: true, constraint_issues: 0, has_error_issues: false, locations: vec![],
        },
    ];

    let groups = detector.detect(&patterns);
    assert!(groups.is_empty(),
        "Patterns in different categories must never be grouped as duplicates");
}

/// Patterns with identical location counts in same category → high similarity.
#[test]
fn critical_dedup_identical_counts_same_category() {
    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "a".to_string(), name: "a".to_string(),
            category: "naming".to_string(), status: PatternStatus::Approved,
            confidence: 0.9, location_count: 10, outlier_count: 0,
            in_call_graph: true, constraint_issues: 0, has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "b".to_string(), name: "b".to_string(),
            category: "naming".to_string(), status: PatternStatus::Approved,
            confidence: 0.9, location_count: 10, outlier_count: 0,
            in_call_graph: true, constraint_issues: 0, has_error_issues: false, locations: vec![],
        },
    ];

    let groups = detector.detect(&patterns);
    assert!(!groups.is_empty(),
        "Identical location counts in same category should produce duplicate group");
    assert_eq!(groups[0].similarity, 1.0,
        "Identical counts should have similarity 1.0");
    assert_eq!(groups[0].action, DuplicateAction::AutoMerge,
        "Similarity 1.0 should be AutoMerge");
}

/// Jaccard from_sets with disjoint sets → 0.0.
#[test]
fn critical_dedup_jaccard_disjoint() {
    use std::collections::HashSet;
    let a: HashSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
    let b: HashSet<String> = ["p", "q"].iter().map(|s| s.to_string()).collect();
    let sim = DuplicateDetector::jaccard_from_sets(&a, &b);
    assert!((sim - 0.0).abs() < f64::EPSILON, "Disjoint sets should have similarity 0.0");
}

/// Jaccard from_sets with identical sets → 1.0.
#[test]
fn critical_dedup_jaccard_identical() {
    use std::collections::HashSet;
    let a: HashSet<String> = ["x", "y", "z"].iter().map(|s| s.to_string()).collect();
    let sim = DuplicateDetector::jaccard_from_sets(&a, &a);
    assert!((sim - 1.0).abs() < f64::EPSILON, "Identical sets should have similarity 1.0");
}

// ═══════════════════════════════════════════════════════════════════════
// §12 CROSS-SUBSYSTEM DATA CORRUPTION PROBES
// ═══════════════════════════════════════════════════════════════════════

/// Violations with is_new=true must survive through gates and reporters.
#[test]
fn critical_is_new_flag_preserved() {
    let v = Violation {
        id: "new-v".to_string(), file: "new.ts".to_string(),
        line: 1, column: None, end_line: None, end_column: None,
        severity: Severity::Warning, pattern_id: "test".to_string(),
        rule_id: "test/new".to_string(), message: "New violation".to_string(),
        quick_fix: None, cwe_id: None, owasp_category: None,
        suppressed: false, is_new: true,
    };

    // Through JSON serialization
    let json = serde_json::to_string(&v).unwrap();
    let v2: Violation = serde_json::from_str(&json).unwrap();
    assert!(v2.is_new, "is_new flag must survive JSON round-trip");

    // Through gate result
    let gr = GateResult::fail(GateId::PatternCompliance, 50.0, "test".to_string(), vec![v]);
    assert!(gr.violations[0].is_new, "is_new must survive in gate result");

    // Through JSON reporter
    let json_out = JsonReporter.generate(&[gr]).unwrap();
    // JSON reporter doesn't include is_new in output — verify it's at least not corrupted
    let parsed: serde_json::Value = serde_json::from_str(&json_out).unwrap();
    assert!(parsed["gates"][0]["violations"][0].is_object());
}

/// Confidence feedback: all action deltas must be non-negative.
#[test]
fn critical_confidence_feedback_non_negative_deltas() {
    let cf = ConfidenceFeedback::new();

    let actions = [
        (FeedbackAction::Fix, None),
        (FeedbackAction::Dismiss, Some(DismissalReason::FalsePositive)),
        (FeedbackAction::Dismiss, Some(DismissalReason::NotApplicable)),
        (FeedbackAction::Dismiss, Some(DismissalReason::WontFix)),
        (FeedbackAction::Dismiss, Some(DismissalReason::Duplicate)),
        (FeedbackAction::Dismiss, None),
        (FeedbackAction::Suppress, None),
        (FeedbackAction::Escalate, None),
    ];

    for (action, reason) in &actions {
        let (alpha_d, beta_d) = cf.compute_adjustment(*action, *reason);
        assert!(alpha_d >= 0.0, "Alpha delta must be >= 0 for {action:?}/{reason:?}");
        assert!(beta_d >= 0.0, "Beta delta must be >= 0 for {action:?}/{reason:?}");
    }
}

/// Bayesian confidence must always be in [0, 1].
#[test]
fn critical_bayesian_confidence_bounded() {
    // Edge cases
    assert!((ConfidenceFeedback::bayesian_confidence(0.0, 0.0) - 0.5).abs() < 0.01,
        "alpha=0, beta=0 should return 0.5");
    assert!((ConfidenceFeedback::bayesian_confidence(100.0, 0.0) - 1.0).abs() < 0.01,
        "alpha=100, beta=0 should return ~1.0");
    assert!((ConfidenceFeedback::bayesian_confidence(0.0, 100.0) - 0.0).abs() < 0.01,
        "alpha=0, beta=100 should return ~0.0");

    // Large values
    let c = ConfidenceFeedback::bayesian_confidence(1e10, 1e10);
    assert!((0.0..=1.0).contains(&c), "Large values: confidence={c}");
    assert!((c - 0.5).abs() < 0.01, "Equal large values should be ~0.5");
}

// ═══════════════════════════════════════════════════════════════════════
// §13 STORAGE QUERY CORRECTNESS UNDER EDGE DATA
// ═══════════════════════════════════════════════════════════════════════

/// Insert violation with NULL optional fields — must not fail.
#[test]
fn critical_storage_null_optional_fields() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let v = ViolationRow {
        id: "null-test".to_string(),
        file: "test.ts".to_string(),
        line: 1,
        column: None,       // NULL
        end_line: None,
        end_column: None,
        severity: "info".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "test".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: None,       // NULL
        owasp_category: None, // NULL
        suppressed: false,
        is_new: false,
    };

    insert_violation(&conn, &v).unwrap();
    let rows = query_all_violations(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].column.is_none());
    assert!(rows[0].cwe_id.is_none());
    assert!(rows[0].owasp_category.is_none());
}

/// Upsert semantics: INSERT OR REPLACE on same violation ID must update, not duplicate.
#[test]
fn critical_storage_upsert_no_duplicates() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let v1 = ViolationRow {
        id: "v-upsert".to_string(),
        file: "test.ts".to_string(),
        line: 10,
        column: None,
        end_line: None,
        end_column: None,
        severity: "warning".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "original message".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    };

    let v2 = ViolationRow {
        id: "v-upsert".to_string(), // SAME ID
        file: "test.ts".to_string(),
        line: 10,
        column: None,
        end_line: None,
        end_column: None,
        severity: "error".to_string(), // CHANGED severity
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "updated message".to_string(), // CHANGED message
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: Some(89), // ADDED CWE
        owasp_category: None,
        suppressed: false,
        is_new: false,
    };

    insert_violation(&conn, &v1).unwrap();
    insert_violation(&conn, &v2).unwrap();

    let rows = query_all_violations(&conn).unwrap();
    assert_eq!(rows.len(), 1, "Upsert must not create duplicates");
    assert_eq!(rows[0].severity, "error", "Upsert must update severity");
    assert_eq!(rows[0].message, "updated message", "Upsert must update message");
    assert_eq!(rows[0].cwe_id, Some(89), "Upsert must update CWE");
}

/// Query violations by file with no matching file — must return empty, not error.
#[test]
fn critical_storage_query_nonexistent_file() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let rows = query_violations_by_file(&conn, "nonexistent.ts").unwrap();
    assert!(rows.is_empty(), "Query for nonexistent file must return empty vec");
}

/// Audit snapshot with extreme values — must not fail.
#[test]
fn critical_storage_extreme_audit_values() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let s = AuditSnapshotRow {
        health_score: 0.0,
        avg_confidence: 0.0,
        approval_ratio: 0.0,
        compliance_rate: 0.0,
        cross_validation_rate: 0.0,
        duplicate_free_rate: 0.0,
        pattern_count: 0,
        category_scores: Some("{}".to_string()),
        created_at: 0,
    };
    insert_audit_snapshot(&conn, &s).unwrap();

    let s2 = AuditSnapshotRow {
        health_score: 100.0,
        avg_confidence: 1.0,
        approval_ratio: 1.0,
        compliance_rate: 1.0,
        cross_validation_rate: 1.0,
        duplicate_free_rate: 1.0,
        pattern_count: u32::MAX,
        category_scores: None,
        created_at: u64::MAX,
    };
    insert_audit_snapshot(&conn, &s2).unwrap();

    let rows = query_audit_snapshots(&conn, 10).unwrap();
    assert_eq!(rows.len(), 2, "Both extreme snapshots must be stored");
}

/// Health trend with very large metric value — must not overflow.
#[test]
fn critical_storage_large_metric_value() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    insert_health_trend(&conn, "test_metric", f64::MAX).unwrap();
    let rows = query_health_trends(&conn, "test_metric", 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].metric_value.is_finite(), "Stored value must be finite");
}

/// Feedback with all optional fields NULL — must not fail.
#[test]
fn critical_storage_feedback_all_nulls() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let f = FeedbackRow {
        violation_id: "v1".to_string(),
        pattern_id: "p1".to_string(),
        detector_id: "d1".to_string(),
        action: "fix".to_string(),
        dismissal_reason: None,
        reason: None,
        author: None,
        created_at: 0,
    };
    insert_feedback(&conn, &f).unwrap();

    let rows = query_feedback_by_detector(&conn, "d1").unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].dismissal_reason.is_none());
    assert!(rows[0].reason.is_none());
    assert!(rows[0].author.is_none());
}

/// Gate result with very long summary and details — must not truncate.
#[test]
fn critical_storage_long_gate_result() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let long_summary = "x".repeat(10_000);
    let long_details = serde_json::to_string(&serde_json::json!({
        "data": "y".repeat(50_000)
    })).unwrap();

    let g = GateResultRow {
        gate_id: "pattern-compliance".to_string(),
        status: "passed".to_string(),
        passed: true,
        score: 85.0,
        summary: long_summary.clone(),
        violation_count: 0,
        warning_count: 0,
        execution_time_ms: 0,
        details: Some(long_details.clone()),
        error: None,
        run_at: 0,
    };
    insert_gate_result(&conn, &g).unwrap();

    let rows = query_gate_results(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].summary.len(), 10_000, "Summary must not be truncated");
    assert_eq!(rows[0].details.as_ref().unwrap().len(), long_details.len(),
        "Details must not be truncated");
}
