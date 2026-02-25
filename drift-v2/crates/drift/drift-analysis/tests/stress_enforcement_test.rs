#![allow(clippy::field_reassign_with_default, clippy::manual_range_contains, clippy::len_zero, clippy::cloned_ref_to_slice_refs, unused_variables)]
//! Production-readiness stress tests for Phase 6 Enforcement.
//!
//! These tests are DIFFERENT from the P6 functional tests. They target:
//! - Adversarial / malicious inputs (Unicode, path traversal, huge strings)
//! - Boundary conditions (NaN, Infinity, u32::MAX, empty everything)
//! - Upstream→downstream data flow integrity (rules→gates→policy→audit→feedback→storage)
//! - Serialization round-trip fidelity (serde_json for every public type)
//! - Cross-subsystem contract violations (mismatched IDs, orphan references)
//! - Concurrent-safety patterns (no shared mutable state leaks)
//! - Regression traps (exact boundary values that previously failed)

use std::collections::HashMap;

use drift_analysis::enforcement::audit::*;
use drift_analysis::enforcement::feedback::*;
use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::policy::*;
use drift_analysis::enforcement::reporters::sarif::SarifReporter;
use drift_analysis::enforcement::reporters::json::JsonReporter;
use drift_analysis::enforcement::reporters::console::ConsoleReporter;
use drift_analysis::enforcement::reporters::Reporter;
use drift_analysis::enforcement::rules::*;

// ═══════════════════════════════════════════════════════════════════════
// §1  ADVERSARIAL INPUTS — Unicode, path traversal, injection, huge data
// ═══════════════════════════════════════════════════════════════════════

/// Unicode filenames, CJK messages, emoji in pattern IDs — nothing should panic.
#[test]
fn stress_unicode_everywhere() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "命名規則-🦀".to_string(),
            category: "naming".to_string(),
            confidence: 0.85,
            locations: vec![PatternLocation {
                file: "src/コンポーネント/ユーザー.ts".to_string(),
                line: 42,
                column: Some(1),
            }],
            outliers: vec![OutlierLocation {
                file: "src/コンポーネント/ヘルパー.ts".to_string(),
                line: 10,
                column: None,
                end_line: None,
                end_column: None,
                                deviation_score: 2.5,
                message: "変数名がキャメルケースではありません 🐍→🐫".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].file.contains("ヘルパー"));
    assert!(violations[0].message.contains('🐫'));

    // SARIF must produce valid JSON even with Unicode
    let gate_result = GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 50.0,
        summary: "Unicode test".to_string(),
        violations: violations.clone(),
        warnings: vec![],
        execution_time_ms: 0,
        details: serde_json::Value::Null,
        error: None,
    };
    let sarif = SarifReporter::new().generate(&[gate_result]).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(parsed["version"], "2.1.0");

    // JSON reporter too
    let gate_result2 = GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 50.0,
        summary: "Unicode test".to_string(),
        violations,
        warnings: vec![],
        execution_time_ms: 0,
        details: serde_json::Value::Null,
        error: None,
    };
    let json_out = JsonReporter.generate(&[gate_result2]).unwrap();
    let _: serde_json::Value = serde_json::from_str(&json_out).unwrap();
}

/// Path traversal in filenames — should not cause panics or weird behavior.
#[test]
fn stress_path_traversal_filenames() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "traversal-test".to_string(),
            category: "security".to_string(),
            confidence: 0.9,
            locations: vec![],
            outliers: vec![
                OutlierLocation {
                    file: "../../../etc/passwd".to_string(),
                    line: 1,
                    column: None,
                    end_line: None,
                    end_column: None,
                                        deviation_score: 5.0,
                    message: "Path traversal attempt".to_string(),
                },
                OutlierLocation {
                    file: "src/app.ts\0hidden".to_string(), // null byte
                    line: 1,
                    column: None,
                    end_line: None,
                    end_column: None,
                                        deviation_score: 5.0,
                    message: "Null byte injection".to_string(),
                },
                OutlierLocation {
                    file: "".to_string(), // empty filename
                    line: 0,
                    column: None,
                    end_line: None,
                    end_column: None,
                                        deviation_score: 1.0,
                    message: "Empty file".to_string(),
                },
            ],
            cwe_ids: vec![22], // CWE-22 Path Traversal
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 3, "All outliers should produce violations");
    // Verify no panic, violations are well-formed
    for v in &violations {
        assert!(!v.id.is_empty());
        assert!(!v.rule_id.is_empty());
    }
}

/// Extremely long strings — should not OOM or panic.
#[test]
fn stress_huge_strings() {
    let huge_msg = "x".repeat(100_000);
    let huge_file = format!("src/{}.ts", "a".repeat(10_000));

    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "huge".to_string(),
            category: "naming".to_string(),
            confidence: 0.8,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: huge_file.clone(),
                line: 1,
                column: None,
                end_line: None,
                end_column: None,
                                deviation_score: 2.0,
                message: huge_msg.clone(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].message.len(), 100_000);
}

// ═══════════════════════════════════════════════════════════════════════
// §2  BOUNDARY CONDITIONS — NaN, Infinity, zero, MAX, negative values
// ═══════════════════════════════════════════════════════════════════════

/// Health scorer must never produce NaN or Infinity, even with adversarial inputs.
#[test]
fn stress_health_scorer_nan_infinity_guard() {
    let scorer = HealthScorer::new();

    // All-zero pattern data
    let patterns = vec![PatternAuditData {
        id: "zero".to_string(),
        name: "zero".to_string(),
        category: "test".to_string(),
        status: PatternStatus::Discovered,
        confidence: 0.0,
        location_count: 0,
        outlier_count: 0,
        in_call_graph: false,
        constraint_issues: 0,
        has_error_issues: false, locations: vec![],
    }];

    let (score, breakdown) = scorer.compute(&patterns, &[]);
    assert!(!score.is_nan(), "Score must not be NaN with zero data");
    assert!(!score.is_infinite(), "Score must not be Infinite");
    assert!(score >= 0.0 && score <= 100.0);
    assert!(!breakdown.raw_score.is_nan());
    assert!(!breakdown.compliance_rate.is_nan());
}

/// Confidence values at exact boundaries: 0.0, 0.5, 1.0.
#[test]
fn stress_confidence_exact_boundaries() {
    let scorer = HealthScorer::new();

    for conf in [0.0, 0.5, 1.0] {
        let patterns = vec![PatternAuditData {
            id: format!("conf-{conf}"),
            name: "test".to_string(),
            category: "test".to_string(),
            status: PatternStatus::Approved,
            confidence: conf,
            location_count: 10,
            outlier_count: 0,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        }];

        let (score, _) = scorer.compute(&patterns, &[]);
        assert!(!score.is_nan(), "NaN at confidence={conf}");
        assert!(score >= 0.0 && score <= 100.0, "Out of range at confidence={conf}: {score}");
    }
}

/// Trend prediction with constant values (zero variance) — must not divide by zero.
#[test]
fn stress_trend_prediction_constant_values() {
    let analyzer = TrendAnalyzer::new();

    // All identical values → slope should be ~0, no NaN
    let scores = vec![80.0; 10];
    let prediction = analyzer.predict(&scores);
    assert!(prediction.is_some());
    let pred = prediction.unwrap();
    assert!(!pred.slope.is_nan());
    assert!(!pred.predicted_score_7d.is_nan());
    assert!(!pred.predicted_score_30d.is_nan());
    assert!(pred.slope.abs() < 0.001, "Constant data should have ~0 slope");
    assert_eq!(pred.direction, TrendDirection::Stable);
}

/// Trend prediction with only 1-4 data points — must return None, not panic.
#[test]
fn stress_trend_prediction_insufficient_data() {
    let analyzer = TrendAnalyzer::new();

    for n in 0..5 {
        let scores: Vec<f64> = (0..n).map(|i| 80.0 + i as f64).collect();
        let prediction = analyzer.predict(&scores);
        assert!(prediction.is_none(), "Should return None for {n} data points");
    }
}

/// Anomaly detection with zero standard deviation — must not divide by zero.
#[test]
fn stress_anomaly_detection_zero_stddev() {
    let analyzer = TrendAnalyzer::new();
    let values = vec![50.0; 10]; // All identical → stddev = 0
    let anomalies = analyzer.detect_anomalies("test", &values, 2.0);
    assert!(anomalies.is_empty(), "No anomalies when all values identical");
}

/// Degradation detector with identical snapshots — no alerts.
#[test]
fn stress_degradation_identical_snapshots() {
    let detector = DegradationDetector::new();
    let snapshot = AuditSnapshot {
        health_score: 85.0,
        avg_confidence: 0.90,
        approval_ratio: 0.80,
        compliance_rate: 0.90,
        cross_validation_rate: 0.70,
        duplicate_free_rate: 1.0,
        pattern_count: 50,
        category_scores: HashMap::new(),
        timestamp: 1000,
        root_path: None,
        total_files: None,
    };

    let alerts = detector.detect(&snapshot, &snapshot);
    assert!(alerts.is_empty(), "Identical snapshots should produce no alerts");
}

/// Degradation detector with improving scores — no alerts.
#[test]
fn stress_degradation_improving_scores() {
    let detector = DegradationDetector::new();
    let previous = AuditSnapshot {
        health_score: 70.0,
        avg_confidence: 0.80,
        approval_ratio: 0.60,
        compliance_rate: 0.80,
        cross_validation_rate: 0.50,
        duplicate_free_rate: 0.90,
        pattern_count: 30,
        category_scores: HashMap::new(),
        timestamp: 1000,
        root_path: None,
        total_files: None,
    };
    let current = AuditSnapshot {
        health_score: 90.0,
        avg_confidence: 0.95,
        ..previous.clone()
    };

    let alerts = detector.detect(&current, &previous);
    assert!(alerts.is_empty(), "Improving scores should produce no alerts");
}

/// Policy engine with empty gate results — should not panic.
#[test]
fn stress_policy_empty_results() {
    for mode in [
        AggregationMode::AllMustPass,
        AggregationMode::AnyMustPass,
        AggregationMode::Weighted,
        AggregationMode::Threshold,
    ] {
        let policy = Policy {
            name: "test".to_string(),
            preset: PolicyPreset::Custom,
            aggregation_mode: mode,
            weights: HashMap::new(),
            threshold: 80.0,
            required_gates: vec![],
            progressive: false,
            ramp_up_days: 0,
        };
        let engine = PolicyEngine::new(policy);
        let result = engine.evaluate(&[]);
        assert!(!result.overall_score.is_nan(), "NaN score with empty results in {mode:?}");
    }
}

/// Progressive enforcement with zero ramp-up days — should not divide by zero.
#[test]
fn stress_progressive_zero_ramp_up() {
    use drift_analysis::enforcement::gates::progressive::*;

    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 0,
        project_age_days: 0,
    });

    // Should not panic, should treat as full enforcement
    let sev = pe.effective_severity(Severity::Error, false);
    assert_eq!(sev, Severity::Error, "Zero ramp-up should mean full enforcement");
    assert!(!pe.is_ramping_up());
    assert!((pe.ramp_up_progress() - 1.0).abs() < 0.001);
}

/// Gate orchestrator with no gates — should return empty, not error.
#[test]
fn stress_orchestrator_no_gates() {
    let orchestrator = GateOrchestrator::with_gates(vec![]);
    let input = GateInput::default();
    let results = orchestrator.execute(&input).unwrap();
    assert!(results.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// §3  UPSTREAM→DOWNSTREAM DATA FLOW INTEGRITY
//     Rules → Gates → Policy → Audit → Feedback → Storage round-trip
// ═══════════════════════════════════════════════════════════════════════

/// Violations produced by rules engine must be consumable by gates, reporters,
/// and storage without any field mismatch or silent data loss.
#[test]
fn stress_rules_to_gates_to_reporters_data_flow() {
    // Step 1: Rules engine produces violations with ALL fields populated
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "sql-param".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: vec![PatternLocation {
                file: "src/db.ts".to_string(),
                line: 5,
                column: Some(1),
            }],
            outliers: vec![OutlierLocation {
                file: "src/api.ts".to_string(),
                line: 42,
                column: Some(10),
                end_line: None,
                end_column: None,
                                deviation_score: 4.5,
                message: "String concat in SQL".to_string(),
            }],
            cwe_ids: vec![89],
            owasp_categories: vec!["A03:2021-Injection".to_string()],
        }],
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };
    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 1);
    let v = &violations[0];

    // Verify ALL fields are populated correctly
    assert!(!v.id.is_empty(), "ID must be populated");
    assert_eq!(v.file, "src/api.ts");
    assert_eq!(v.line, 42);
    assert_eq!(v.column, Some(10));
    assert_eq!(v.severity, Severity::Error, "CWE-89 must be Error");
    assert_eq!(v.cwe_id, Some(89));
    assert_eq!(v.owasp_category.as_deref(), Some("A03:2021-Injection"));
    assert!(!v.suppressed);
    assert!(v.quick_fix.is_some(), "Security violations should get quick fix");

    // Step 2: Feed into gate — violation must survive intact
    let gate_result = GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 50.0,
        summary: "test".to_string(),
        violations: violations.clone(),
        warnings: vec![],
        execution_time_ms: 10,
        details: serde_json::Value::Null,
        error: None,
    };

    // Step 3: SARIF reporter must preserve CWE and OWASP references
    let sarif_out = SarifReporter::new().generate(&[gate_result.clone()]).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&sarif_out).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "security/sql-param");
    assert_eq!(results[0]["level"], "error");
    // CWE/OWASP references now in result.properties (SARIF 2.1.0 compliant)
    assert_eq!(results[0]["properties"]["cweId"], "CWE-89", "CWE-89 must be in properties");
    assert_eq!(results[0]["properties"]["owaspCategory"], "A03:2021-Injection", "OWASP must be in properties");
    // And on rules via relationships
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    let rule = rules.iter().find(|r| r["id"] == "security/sql-param").unwrap();
    let rels = rule["relationships"].as_array().unwrap();
    assert!(rels.iter().any(|r| r["target"]["toolComponent"]["name"] == "CWE"), "Rule must have CWE relationship");

    // Step 4: JSON reporter must preserve all fields
    let json_out = JsonReporter.generate(&[gate_result.clone()]).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_out).unwrap();
    let jv = &json["gates"][0]["violations"][0];
    assert_eq!(jv["file"], "src/api.ts");
    assert_eq!(jv["line"], 42);
    assert_eq!(jv["severity"], "error");
    assert_eq!(jv["cwe_id"], 89);
    assert_eq!(jv["owasp_category"], "A03:2021-Injection");

    // Step 5: Console reporter must include file:line format
    let console_out = ConsoleReporter::new(false).generate(&[gate_result]).unwrap();
    assert!(console_out.contains("src/api.ts"), "Console must show filename");
    assert!(console_out.contains("42"), "Console must show line number");
}

/// Gate results flow into policy engine — verify score aggregation is mathematically correct.
#[test]
fn stress_gates_to_policy_score_integrity() {
    // Create gate results with known scores
    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 90.0, "ok".to_string()),
        GateResult::pass(GateId::ConstraintVerification, 80.0, "ok".to_string()),
        GateResult::fail(GateId::SecurityBoundaries, 60.0, "fail".to_string(), vec![]),
        GateResult::pass(GateId::TestCoverage, 85.0, "ok".to_string()),
        GateResult::pass(GateId::ErrorHandling, 95.0, "ok".to_string()),
        GateResult::pass(GateId::Regression, 100.0, "ok".to_string()),
    ];

    // Threshold mode: average = (90+80+60+85+95+100)/6 = 85.0
    let policy = Policy {
        name: "test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Threshold,
        weights: HashMap::new(),
        threshold: 85.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    let expected_avg = (90.0 + 80.0 + 60.0 + 85.0 + 95.0 + 100.0) / 6.0;
    assert!(
        (pr.overall_score - expected_avg).abs() < 0.01,
        "Score {:.2} should be {:.2}",
        pr.overall_score,
        expected_avg
    );
    assert!(pr.overall_passed, "85.0 >= 85.0 should pass");
    assert_eq!(pr.gates_passed, 5);
    assert_eq!(pr.gates_failed, 1);

    // All-must-pass: one failure → overall fail
    let policy2 = Policy {
        name: "strict".to_string(),
        preset: PolicyPreset::Strict,
        aggregation_mode: AggregationMode::AllMustPass,
        weights: HashMap::new(),
        threshold: 0.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine2 = PolicyEngine::new(policy2);
    let pr2 = engine2.evaluate(&results);
    assert!(!pr2.overall_passed, "All-must-pass should fail with one failing gate");
}

/// Required gates override aggregation mode — even if score passes, required gate failure blocks.
#[test]
fn stress_required_gates_override() {
    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 100.0, "ok".to_string()),
        GateResult::fail(GateId::SecurityBoundaries, 0.0, "fail".to_string(), vec![]),
        GateResult::pass(GateId::TestCoverage, 100.0, "ok".to_string()),
    ];

    // Any-must-pass with required security gate
    let policy = Policy {
        name: "test".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::AnyMustPass,
        weights: HashMap::new(),
        threshold: 0.0,
        required_gates: vec![GateId::SecurityBoundaries],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(
        !pr.overall_passed,
        "Required gate failure must block even in any-must-pass mode"
    );
    assert!(!pr.required_gates_passed);
}

/// Feedback tracker metrics flow correctly into auto-disable decisions.
#[test]
fn stress_feedback_to_auto_disable_flow() {
    let mut tracker = FeedbackTracker::new();

    // Simulate realistic detector lifecycle:
    // detector-a: 100 findings, 5 FP → 5% FP rate → healthy
    // detector-b: 100 findings, 25 FP → 25% FP rate → should alert
    // detector-c: 100 findings, 25 FP, sustained 35 days → should disable

    for i in 0..95 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("va-{i}"),
            pattern_id: "pat-a".to_string(),
            detector_id: "detector-a".to_string(),
            action: FeedbackAction::Fix,
            dismissal_reason: None,
            reason: None,
            author: None,
            timestamp: i,
        });
    }
    for i in 95..100 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("va-{i}"),
            pattern_id: "pat-a".to_string(),
            detector_id: "detector-a".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::FalsePositive),
            reason: None,
            author: None,
            timestamp: i,
        });
    }

    for i in 0..75 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("vb-{i}"),
            pattern_id: "pat-b".to_string(),
            detector_id: "detector-b".to_string(),
            action: FeedbackAction::Fix,
            dismissal_reason: None,
            reason: None,
            author: None,
            timestamp: i,
        });
    }
    for i in 75..100 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("vb-{i}"),
            pattern_id: "pat-b".to_string(),
            detector_id: "detector-b".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::FalsePositive),
            reason: None,
            author: None,
            timestamp: i,
        });
    }

    // detector-c: same as b but with sustained days
    for i in 0..75 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("vc-{i}"),
            pattern_id: "pat-c".to_string(),
            detector_id: "detector-c".to_string(),
            action: FeedbackAction::Fix,
            dismissal_reason: None,
            reason: None,
            author: None,
            timestamp: i,
        });
    }
    for i in 75..100 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("vc-{i}"),
            pattern_id: "pat-c".to_string(),
            detector_id: "detector-c".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::FalsePositive),
            reason: None,
            author: None,
            timestamp: i,
        });
    }
    tracker.update_sustained_days("detector-c", 35);

    // Verify FP rates
    let ma = tracker.get_metrics("detector-a").unwrap();
    assert!((ma.fp_rate - 0.05).abs() < 0.01, "detector-a FP rate should be ~5%");

    let mb = tracker.get_metrics("detector-b").unwrap();
    assert!((mb.fp_rate - 0.25).abs() < 0.01, "detector-b FP rate should be ~25%");

    // Alerts: b and c should alert (>10% FP)
    let alerts = tracker.check_alerts();
    assert!(alerts.contains(&"detector-b".to_string()));
    assert!(alerts.contains(&"detector-c".to_string()));
    assert!(!alerts.contains(&"detector-a".to_string()));

    // Auto-disable: only c (sustained 35 days)
    let disabled = tracker.check_auto_disable();
    assert!(disabled.contains(&"detector-c".to_string()));
    assert!(!disabled.contains(&"detector-b".to_string()), "detector-b has no sustained days");
    assert!(!disabled.contains(&"detector-a".to_string()));
}

// ═══════════════════════════════════════════════════════════════════════
// §4  SERIALIZATION ROUND-TRIP FIDELITY
// ═══════════════════════════════════════════════════════════════════════

/// Every public type must survive JSON round-trip without data loss.
#[test]
fn stress_serde_round_trip_all_types() {
    // Violation
    let v = Violation {
        id: "v-1".to_string(),
        file: "src/app.ts".to_string(),
        line: 42,
        column: Some(10),
        end_line: Some(42),
        end_column: Some(50),
        severity: Severity::Error,
        pattern_id: "sql".to_string(),
        rule_id: "security/sql".to_string(),
        message: "SQL injection".to_string(),
        quick_fix: Some(QuickFix {
            strategy: QuickFixStrategy::WrapInTryCatch,
            description: "Use parameterized query".to_string(),
            replacement: Some("db.query($1, [input])".to_string()),
        }),
        cwe_id: Some(89),
        owasp_category: Some("A03:2021".to_string()),
        suppressed: false,
        is_new: true,
    };
    let json = serde_json::to_string(&v).unwrap();
    let v2: Violation = serde_json::from_str(&json).unwrap();
    assert_eq!(v.id, v2.id);
    assert_eq!(v.severity, v2.severity);
    assert_eq!(v.cwe_id, v2.cwe_id);
    assert_eq!(v.quick_fix.as_ref().unwrap().strategy, v2.quick_fix.as_ref().unwrap().strategy);

    // GateResult
    let gr = GateResult::fail(GateId::SecurityBoundaries, 60.0, "fail".to_string(), vec![v.clone()]);
    let json = serde_json::to_string(&gr).unwrap();
    let gr2: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(gr.gate_id, gr2.gate_id);
    assert_eq!(gr.passed, gr2.passed);
    assert_eq!(gr.violations.len(), gr2.violations.len());

    // PolicyResult
    let pr = PolicyResult {
        policy_name: "strict".to_string(),
        aggregation_mode: AggregationMode::AllMustPass,
        overall_passed: false,
        overall_score: 60.0,
        gate_count: 6,
        gates_passed: 5,
        gates_failed: 1,
        required_gates_passed: true,
        details: "test".to_string(),
    };
    let json = serde_json::to_string(&pr).unwrap();
    let pr2: PolicyResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pr.overall_passed, pr2.overall_passed);
    assert_eq!(pr.aggregation_mode, pr2.aggregation_mode);

    // FeedbackMetrics
    let fm = FeedbackMetrics {
        detector_id: "det-1".to_string(),
        total_findings: 100,
        fixed: 80,
        dismissed: 15,
        suppressed: 3,
        escalated: 2,
        false_positives: 10,
        fp_rate: 0.125,
        action_rate: 1.0,
        days_above_threshold: 5,
    };
    let json = serde_json::to_string(&fm).unwrap();
    let fm2: FeedbackMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(fm.total_findings, fm2.total_findings);
    assert!((fm.fp_rate - fm2.fp_rate).abs() < 0.001);

    // AuditSnapshot
    let snap = AuditSnapshot {
        health_score: 82.5,
        avg_confidence: 0.88,
        approval_ratio: 0.75,
        compliance_rate: 0.90,
        cross_validation_rate: 0.70,
        duplicate_free_rate: 1.0,
        pattern_count: 50,
        category_scores: {
            let mut m = HashMap::new();
            m.insert("naming".to_string(), 85.0);
            m.insert("security".to_string(), 78.0);
            m
        },
        timestamp: 1706000000,
        root_path: None,
        total_files: None,
    };
    let json = serde_json::to_string(&snap).unwrap();
    let snap2: AuditSnapshot = serde_json::from_str(&json).unwrap();
    assert!((snap.health_score - snap2.health_score).abs() < 0.001);
    assert_eq!(snap.category_scores.len(), snap2.category_scores.len());
}

/// Severity enum serde must use lowercase strings, not integers.
#[test]
fn stress_severity_serde_format() {
    let json = serde_json::to_string(&Severity::Error).unwrap();
    assert_eq!(json, "\"error\"", "Severity must serialize as lowercase string");

    let json = serde_json::to_string(&Severity::Warning).unwrap();
    assert_eq!(json, "\"warning\"");

    let json = serde_json::to_string(&Severity::Info).unwrap();
    assert_eq!(json, "\"info\"");

    let json = serde_json::to_string(&Severity::Hint).unwrap();
    assert_eq!(json, "\"hint\"");

    // Deserialize back
    let s: Severity = serde_json::from_str("\"error\"").unwrap();
    assert_eq!(s, Severity::Error);
}

/// GateId serde must use kebab-case strings.
#[test]
fn stress_gate_id_serde_format() {
    let json = serde_json::to_string(&GateId::PatternCompliance).unwrap();
    assert_eq!(json, "\"pattern-compliance\"");

    let json = serde_json::to_string(&GateId::SecurityBoundaries).unwrap();
    assert_eq!(json, "\"security-boundaries\"");

    // Round-trip
    let id: GateId = serde_json::from_str("\"test-coverage\"").unwrap();
    assert_eq!(id, GateId::TestCoverage);
}

// ═══════════════════════════════════════════════════════════════════════
// §5  CROSS-SUBSYSTEM CONTRACT VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

/// Suppressed violations must be excluded from SARIF output.
#[test]
fn stress_suppressed_violations_excluded_from_sarif() {
    let gate_result = GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 50.0,
        summary: "test".to_string(),
        violations: vec![
            Violation {
                id: "v-active".to_string(),
                file: "src/a.ts".to_string(),
                line: 10,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Error,
                pattern_id: "test".to_string(),
                rule_id: "test/active".to_string(),
                message: "Active violation".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false,
            },
            Violation {
                id: "v-suppressed".to_string(),
                file: "src/b.ts".to_string(),
                line: 20,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Error,
                pattern_id: "test".to_string(),
                rule_id: "test/suppressed".to_string(),
                message: "Suppressed violation".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: true,
                is_new: false,
            },
        ],
        warnings: vec![],
        execution_time_ms: 0,
        details: serde_json::Value::Null,
        error: None,
    };

    let sarif_out = SarifReporter::new().generate(&[gate_result]).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&sarif_out).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "Suppressed violations must be excluded from SARIF");
    assert_eq!(results[0]["ruleId"], "test/active");
}

/// Severity ordering: Error > Warning > Info > Hint (for dedup and sorting).
#[test]
fn stress_severity_ordering() {
    assert!(Severity::Error < Severity::Warning, "Error should sort before Warning");
    assert!(Severity::Warning < Severity::Info);
    assert!(Severity::Info < Severity::Hint);

    // Penalty ordering
    assert!(Severity::Error.penalty() > Severity::Warning.penalty());
    assert!(Severity::Warning.penalty() > Severity::Info.penalty());
    assert!(Severity::Info.penalty() > Severity::Hint.penalty());
}

/// Gate dependency chain: constraint_verification depends on pattern_compliance,
/// security_boundaries depends on pattern_compliance. If pattern_compliance fails,
/// both dependents must be skipped.
#[test]
fn stress_cascading_dependency_skip() {
    // Create input that will make pattern compliance fail (many high-confidence outliers)
    let input = GateInput {
        patterns: vec![PatternInfo {
            pattern_id: "critical".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: vec![],
            outliers: (0..50)
                .map(|i| OutlierLocation {
                    file: format!("src/f{i}.ts"),
                    line: i as u32,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 5.0,
                    message: "Critical".to_string(),
                })
                .collect(),
            cwe_ids: vec![89],
            owasp_categories: vec![],
        }],
        constraints: vec![ConstraintInput {
            id: "no-circular".to_string(),
            description: "No circular deps".to_string(),
            passed: false, // Would fail on its own
            violations: vec![ConstraintViolationInput {
                file: "src/a.ts".to_string(),
                line: Some(1),
                message: "Circular dep".to_string(),
            }],
        }],
        error_gaps: vec![ErrorGapInput {
            file: "src/handler.ts".to_string(),
            line: 10,
            gap_type: "empty_catch".to_string(),
            message: "Empty catch block".to_string(),
        }],
        ..Default::default()
    };

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    // Pattern compliance should fail
    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.passed);

    // Both dependents should be skipped
    let cv = results.iter().find(|r| r.gate_id == GateId::ConstraintVerification).unwrap();
    assert_eq!(cv.status, GateStatus::Skipped, "Constraint verification should be skipped");

    let sb = results.iter().find(|r| r.gate_id == GateId::SecurityBoundaries).unwrap();
    assert_eq!(sb.status, GateStatus::Skipped, "Security boundaries should be skipped");

    // Non-dependent gates should still execute (provide error_gaps so ErrorHandling
    // has data and doesn't skip for missing input)
    let eh = results.iter().find(|r| r.gate_id == GateId::ErrorHandling).unwrap();
    assert_ne!(eh.status, GateStatus::Skipped, "Error handling has no deps, should execute");
}

/// Auto-approve must never approve patterns with error issues.
#[test]
fn stress_auto_approve_rejects_error_patterns() {
    let approver = AutoApprover::new();
    let patterns = vec![PatternAuditData {
        id: "has-errors".to_string(),
        name: "error-pattern".to_string(),
        category: "naming".to_string(),
        status: PatternStatus::Discovered,
        confidence: 0.99, // Very high confidence
        location_count: 100,
        outlier_count: 1,
        in_call_graph: true,
        constraint_issues: 0,
        has_error_issues: true, // But has error issues!
        locations: vec![],
    }];

    let (auto_approved, needs_review, _) = approver.classify(&patterns);
    assert!(
        !auto_approved.contains(&"has-errors".to_string()),
        "Patterns with error issues must never be auto-approved"
    );
    assert!(needs_review.contains(&"has-errors".to_string()));
}

/// Duplicate detector must not compare patterns across different categories.
#[test]
fn stress_dedup_cross_category_isolation() {
    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "naming-1".to_string(),
            name: "camelCase".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Approved,
            confidence: 0.9,
            location_count: 50,
            outlier_count: 5,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "security-1".to_string(),
            name: "sql-param".to_string(),
            category: "security".to_string(), // Different category!
            status: PatternStatus::Approved,
            confidence: 0.9,
            location_count: 50, // Same counts
            outlier_count: 5,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
    ];

    let groups = detector.detect(&patterns);
    assert!(
        groups.is_empty(),
        "Patterns in different categories must not be compared for duplicates"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// §6  STORAGE ROUND-TRIP — upstream analysis → storage → downstream query
// ═══════════════════════════════════════════════════════════════════════

/// Full storage round-trip: insert all enforcement data, query it back,
/// verify materialized views, then verify data integrity.
#[test]
fn stress_storage_full_round_trip() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;
    use drift_storage::materialized::status::*;
    use drift_storage::materialized::security::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    // Insert 100 violations with mixed severities and CWE IDs
    for i in 0..100u32 {
        let severity = match i % 4 {
            0 => "error",
            1 => "warning",
            2 => "info",
            _ => "hint",
        };
        let cwe_id = if i % 3 == 0 { Some(89) } else { None };

        insert_violation(
            &conn,
            &ViolationRow {
                id: format!("v-{i:04}"),
                file: format!("src/file{}.ts", i / 10),
                line: i,
                column: Some(i % 80 + 1),
                end_line: None,
                end_column: None,
                severity: severity.to_string(),
                pattern_id: format!("pat-{}", i % 5),
                rule_id: format!("rule/{}", i % 10),
                message: format!("Violation {i}"),
                quick_fix_strategy: None,
                quick_fix_description: None,
                cwe_id,
                owasp_category: if cwe_id.is_some() {
                    Some("A03:2021".to_string())
                } else {
                    None
                },
                suppressed: i % 20 == 0, // 5% suppressed
                is_new: false,
            },
        )
        .unwrap();
    }

    // Insert gate results
    for gate_id in ["pattern-compliance", "constraint-verification", "security-boundaries",
                     "test-coverage", "error-handling", "regression"] {
        insert_gate_result(
            &conn,
            &GateResultRow {
                gate_id: gate_id.to_string(),
                status: "passed".to_string(),
                passed: true,
                score: 85.0,
                summary: format!("{gate_id}: 85%"),
                violation_count: 10,
                warning_count: 0,
                execution_time_ms: 15,
                details: None,
                error: None,
                run_at: 0,
            },
        )
        .unwrap();
    }

    // Insert audit snapshot
    insert_audit_snapshot(
        &conn,
        &AuditSnapshotRow {
            health_score: 82.5,
            avg_confidence: 0.88,
            approval_ratio: 0.75,
            compliance_rate: 0.90,
            cross_validation_rate: 0.70,
            duplicate_free_rate: 1.0,
            pattern_count: 25,
            category_scores: Some(r#"{"naming":85,"security":78}"#.to_string()),
            created_at: 0,
        },
    )
    .unwrap();

    // Insert health trends
    for i in 0..30 {
        insert_health_trend(&conn, "health_score", 80.0 + (i as f64 * 0.1)).unwrap();
    }

    // Insert feedback
    for i in 0..20 {
        insert_feedback(
            &conn,
            &FeedbackRow {
                violation_id: format!("v-{i:04}"),
                pattern_id: format!("pat-{}", i % 5),
                detector_id: format!("det-{}", i % 3),
                action: if i % 3 == 0 { "fix" } else { "dismiss" }.to_string(),
                dismissal_reason: if i % 3 != 0 {
                    Some("false_positive".to_string())
                } else {
                    None
                },
                reason: None,
                author: Some("dev@test.com".to_string()),
                created_at: 0,
            },
        )
        .unwrap();
    }

    // Query back and verify
    let all_violations = query_all_violations(&conn).unwrap();
    assert_eq!(all_violations.len(), 100, "Should have 100 violations");

    let file_violations = query_violations_by_file(&conn, "src/file0.ts").unwrap();
    assert_eq!(file_violations.len(), 10, "file0.ts should have 10 violations (0-9)");

    let gates = query_gate_results(&conn).unwrap();
    assert_eq!(gates.len(), 6, "Should have 6 gate results");

    let snapshots = query_audit_snapshots(&conn, 10).unwrap();
    assert_eq!(snapshots.len(), 1);

    let trends = query_health_trends(&conn, "health_score", 100).unwrap();
    assert_eq!(trends.len(), 30);

    let feedback = query_feedback_by_detector(&conn, "det-0").unwrap();
    assert!(!feedback.is_empty());

    // Materialized views
    let status = refresh_status(&conn).unwrap();
    // 100 violations, 5 suppressed → 95 unsuppressed
    assert_eq!(status.violation_count, 95, "Status view should exclude suppressed");
    assert_eq!(status.gate_pass_count, 6);
    assert_eq!(status.gate_fail_count, 0);

    let security = refresh_security(&conn).unwrap();
    // CWE violations: i%3==0 → 34 total, minus suppressed ones
    // Suppressed: i%20==0 AND i%3==0 → i=0,60 → 2 suppressed security violations
    // error+CWE: i%4==0 AND i%3==0 → i=0,12,24,36,48,60,72,84,96 → 9 total
    // minus suppressed (i%20==0): i=0,60 → 7 critical
    assert!(security.total_security_violations > 0, "Should have security violations");
    assert!(security.critical_count > 0, "Should have critical security violations");
}

/// Verify INSERT OR REPLACE semantics — updating a violation doesn't create duplicates.
#[test]
fn stress_storage_upsert_no_duplicates() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let v = ViolationRow {
        id: "v-upsert".to_string(),
        file: "src/app.ts".to_string(),
        line: 10,
        column: None,
        end_line: None,
        end_column: None,
        severity: "error".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "Original message".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: Some(89),
        owasp_category: None,
        suppressed: false,
        is_new: false,
    };

    // Insert twice with same ID
    insert_violation(&conn, &v).unwrap();
    let v2 = ViolationRow {
        message: "Updated message".to_string(),
        ..v
    };
    insert_violation(&conn, &v2).unwrap();

    let all = query_all_violations(&conn).unwrap();
    assert_eq!(all.len(), 1, "INSERT OR REPLACE should not create duplicates");
    assert_eq!(all[0].message, "Updated message", "Should have updated message");
}

// ═══════════════════════════════════════════════════════════════════════
// §7  SUPPRESSION EDGE CASES
// ═══════════════════════════════════════════════════════════════════════

/// Suppression on line 1 (first line of file) — edge case for line-1 check.
#[test]
fn stress_suppression_first_line() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/app.ts".to_string(),
        vec![
            "// drift-ignore".to_string(),
            "const x = unsafeQuery();".to_string(),
        ],
    );

    // Line 2 should be suppressed (drift-ignore on line 1)
    assert!(checker.is_suppressed("src/app.ts", 2, None, &source_lines));
}

/// Suppression with multiple rule IDs on one line.
#[test]
fn stress_suppression_multiple_rules() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/app.ts".to_string(),
        vec![
            "// drift-ignore security/sql-injection, naming/camelCase".to_string(),
            "const x = db.query(input);".to_string(),
        ],
    );

    assert!(checker.is_suppressed("src/app.ts", 2, Some("security/sql-injection"), &source_lines));
    assert!(checker.is_suppressed("src/app.ts", 2, Some("naming/camelCase"), &source_lines));
    assert!(!checker.is_suppressed("src/app.ts", 2, Some("security/xss"), &source_lines));
}

/// Suppression in Python-style comments.
#[test]
fn stress_suppression_python_comments() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/app.py".to_string(),
        vec![
            "# drift-ignore".to_string(),
            "x = unsafe_query()".to_string(),
        ],
    );

    assert!(checker.is_suppressed("src/app.py", 2, None, &source_lines));
}

/// Suppression must NOT trigger on non-comment drift-ignore (e.g., in a string).
#[test]
fn stress_suppression_not_in_string() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/app.ts".to_string(),
        vec![
            "const msg = 'drift-ignore this';".to_string(),
            "const x = unsafeQuery();".to_string(),
        ],
    );

    // "drift-ignore" is in a string, not a comment — should NOT suppress
    assert!(!checker.is_suppressed("src/app.ts", 2, None, &source_lines));
}

/// File not in source_lines map — should not suppress (not panic).
#[test]
fn stress_suppression_missing_file() {
    let checker = SuppressionChecker::new();
    let source_lines = HashMap::new(); // Empty

    assert!(!checker.is_suppressed("nonexistent.ts", 10, None, &source_lines));
}

// ═══════════════════════════════════════════════════════════════════════
// §8  CONFIDENCE FEEDBACK MATH VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

/// Bayesian confidence must be bounded [0, 1] for all valid inputs.
#[test]
fn stress_bayesian_confidence_bounds() {
    // Normal case
    assert!((ConfidenceFeedback::bayesian_confidence(10.0, 2.0) - 10.0 / 12.0).abs() < 0.001);

    // Edge: alpha=0, beta=0 → 0.5 (uninformative prior)
    assert!((ConfidenceFeedback::bayesian_confidence(0.0, 0.0) - 0.5).abs() < 0.001);

    // Edge: alpha=0, beta=10 → 0.0
    assert!((ConfidenceFeedback::bayesian_confidence(0.0, 10.0) - 0.0).abs() < 0.001);

    // Edge: alpha=10, beta=0 → 1.0
    assert!((ConfidenceFeedback::bayesian_confidence(10.0, 0.0) - 1.0).abs() < 0.001);

    // Large values
    let c = ConfidenceFeedback::bayesian_confidence(1_000_000.0, 1.0);
    assert!(c > 0.999 && c <= 1.0);
}

/// All feedback actions must produce valid (non-negative) Bayesian deltas.
#[test]
fn stress_feedback_action_deltas() {
    let fb = ConfidenceFeedback::new();

    let actions = [
        (FeedbackAction::Fix, None),
        (FeedbackAction::Dismiss, Some(DismissalReason::FalsePositive)),
        (FeedbackAction::Dismiss, Some(DismissalReason::WontFix)),
        (FeedbackAction::Dismiss, Some(DismissalReason::NotApplicable)),
        (FeedbackAction::Dismiss, Some(DismissalReason::Duplicate)),
        (FeedbackAction::Dismiss, None),
        (FeedbackAction::Suppress, None),
        (FeedbackAction::Escalate, None),
    ];

    for (action, reason) in &actions {
        let (da, db) = fb.compute_adjustment(*action, *reason);
        assert!(da >= 0.0, "Alpha delta must be non-negative for {action:?}/{reason:?}");
        assert!(db >= 0.0, "Beta delta must be non-negative for {action:?}/{reason:?}");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// §9  PERFORMANCE REGRESSION TRAPS
// ═══════════════════════════════════════════════════════════════════════

/// 50K violations through the full pipeline — must complete in reasonable time.
#[test]
fn stress_50k_violations_full_pipeline() {
    let outliers: Vec<OutlierLocation> = (0..50_000)
        .map(|i| OutlierLocation {
            file: format!("src/file{}.ts", i / 100),
            line: (i % 1000) as u32,
            column: Some((i % 80 + 1) as u32),
            end_line: None,
            end_column: None,
            deviation_score: 2.0 + (i % 5) as f64,
            message: format!("Violation {i}"),
        })
        .collect();

    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "perf-test".to_string(),
            category: "naming".to_string(),
            confidence: 0.8,
            locations: vec![],
            outliers,
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };

    let start = std::time::Instant::now();

    // Rules evaluation
    let evaluator = RulesEvaluator::new();
    let violations = evaluator.evaluate(&input);
    let rules_time = start.elapsed();

    // Gate evaluation
    let gate_input = GateInput {
        patterns: input.patterns.clone(),
        ..Default::default()
    };
    let orchestrator = GateOrchestrator::new();
    let gate_results = orchestrator.execute(&gate_input).unwrap();
    let gates_time = start.elapsed();

    // Policy evaluation
    let policy = Policy::standard();
    let engine = PolicyEngine::new(policy);
    let _pr = engine.evaluate(&gate_results);
    let policy_time = start.elapsed();

    // SARIF generation
    let reporter = SarifReporter::new();
    let sarif = reporter.generate(&gate_results).unwrap();
    let total_time = start.elapsed();

    assert!(!violations.is_empty());
    assert!(!sarif.is_empty());

    // Timing assertions (generous bounds for CI)
    assert!(
        rules_time.as_secs() < 10,
        "Rules evaluation took {}s for 50K violations",
        rules_time.as_secs()
    );
    assert!(
        total_time.as_secs() < 30,
        "Full pipeline took {}s for 50K violations",
        total_time.as_secs()
    );

    // Verify SARIF is valid JSON
    let _: serde_json::Value = serde_json::from_str(&sarif).unwrap();

    eprintln!(
        "50K pipeline: rules={:?}, gates={:?}, policy={:?}, total={:?}",
        rules_time,
        gates_time - rules_time,
        policy_time - gates_time,
        total_time
    );
}

/// Health scorer with 10K patterns — must not be O(n²).
#[test]
fn stress_health_scorer_10k_patterns() {
    let patterns: Vec<PatternAuditData> = (0..10_000)
        .map(|i| PatternAuditData {
            id: format!("p-{i}"),
            name: format!("pattern-{i}"),
            category: format!("cat-{}", i % 16),
            status: if i % 3 == 0 {
                PatternStatus::Approved
            } else {
                PatternStatus::Discovered
            },
            confidence: 0.5 + (i % 50) as f64 / 100.0,
            location_count: 10 + i % 100,
            outlier_count: i % 20,
            in_call_graph: i % 2 == 0,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        })
        .collect();

    let scorer = HealthScorer::new();
    let start = std::time::Instant::now();
    let (score, breakdown) = scorer.compute(&patterns, &[]);
    let elapsed = start.elapsed();

    assert!(!score.is_nan());
    assert!(score > 0.0 && score <= 100.0);
    assert!(!breakdown.raw_score.is_nan());
    assert!(
        elapsed.as_millis() < 500,
        "Health scorer took {}ms for 10K patterns",
        elapsed.as_millis()
    );

    // Per-category should produce 16 categories
    let categories = scorer.compute_per_category(&patterns, &[]);
    assert_eq!(categories.len(), 16, "Should have 16 categories");
}
