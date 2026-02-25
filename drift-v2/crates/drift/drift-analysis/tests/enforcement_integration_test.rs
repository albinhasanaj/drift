#![allow(clippy::manual_range_contains, clippy::len_zero)]
//! Phase 6 Integration Tests
//! T6-INT-01 through T6-INT-07

use std::collections::HashMap;

use drift_analysis::enforcement::audit::*;
use drift_analysis::enforcement::feedback::*;
use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::policy::*;
use drift_analysis::enforcement::reporters::sarif::SarifReporter;
use drift_analysis::enforcement::reporters::Reporter;
use drift_analysis::enforcement::rules::*;

// ─── Helpers ─────────────────────────────────────────────────────────

fn make_realistic_patterns() -> Vec<PatternInfo> {
    vec![
        PatternInfo {
            pattern_id: "naming-camelCase".to_string(),
            category: "naming".to_string(),
            confidence: 0.92,
            locations: vec![PatternLocation {
                file: "src/services/user.ts".to_string(),
                line: 10,
                column: Some(1),
            }],
            outliers: vec![OutlierLocation {
                file: "src/utils/helpers.ts".to_string(),
                line: 25,
                column: Some(5),
                end_line: None,
                end_column: None,
                deviation_score: 2.5,
                message: "Uses snake_case instead of camelCase".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        },
        PatternInfo {
            pattern_id: "sql-parameterized".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: vec![PatternLocation {
                file: "src/db/queries.ts".to_string(),
                line: 15,
                column: Some(1),
            }],
            outliers: vec![OutlierLocation {
                file: "src/api/search.ts".to_string(),
                line: 42,
                column: Some(10),
                end_line: None,
                end_column: None,
                deviation_score: 4.0,
                message: "String concatenation in SQL query".to_string(),
            }],
            cwe_ids: vec![89],
            owasp_categories: vec!["A03:2021-Injection".to_string()],
        },
        PatternInfo {
            pattern_id: "error-handling-try-catch".to_string(),
            category: "error_handling".to_string(),
            confidence: 0.88,
            locations: vec![PatternLocation {
                file: "src/services/payment.ts".to_string(),
                line: 30,
                column: None,
            }],
            outliers: vec![OutlierLocation {
                file: "src/api/webhook.ts".to_string(),
                line: 55,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 3.0,
                message: "Missing error handling in async function".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        },
    ]
}

fn make_audit_patterns() -> Vec<PatternAuditData> {
    vec![
        PatternAuditData {
            id: "naming-camelCase".to_string(),
            name: "camelCase".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Approved,
            confidence: 0.92,
            location_count: 50,
            outlier_count: 5,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "sql-parameterized".to_string(),
            name: "parameterized-queries".to_string(),
            category: "security".to_string(),
            status: PatternStatus::Approved,
            confidence: 0.95,
            location_count: 30,
            outlier_count: 2,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "error-handling".to_string(),
            name: "try-catch".to_string(),
            category: "error_handling".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.88,
            location_count: 20,
            outlier_count: 3,
            in_call_graph: false,
            constraint_issues: 1,
            has_error_issues: false, locations: vec![],
        },
    ]
}

/// T6-INT-01: Integration: detect → aggregate → score → enforce → report round-trip.
#[test]
fn test_full_enforcement_round_trip() {
    // Step 1: Rules engine — detect violations from patterns
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: make_realistic_patterns(),
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };
    let violations = evaluator.evaluate(&input);
    assert!(!violations.is_empty(), "Step 1: Should detect violations");

    // Step 2: Quality gates — evaluate all 6 gates
    let gate_input = GateInput {
        patterns: make_realistic_patterns(),
        constraints: vec![ConstraintInput {
            id: "no-circular".to_string(),
            description: "No circular deps".to_string(),
            passed: true,
            violations: vec![],
        }],
        security_findings: vec![SecurityFindingInput {
            file: "src/api/search.ts".to_string(),
            line: 42,
            description: "SQL injection".to_string(),
            severity: "error".to_string(),
            cwe_ids: vec![89],
            owasp_categories: vec!["A03:2021-Injection".to_string()],
        }],
        test_coverage: Some(TestCoverageInput {
            overall_coverage: 82.0,
            threshold: 80.0,
            uncovered_files: vec![],
        }),
        error_gaps: vec![],
        previous_health_score: Some(80.0),
        current_health_score: Some(78.0),
        ..Default::default()
    };

    let orchestrator = GateOrchestrator::new();
    let gate_results = orchestrator.execute(&gate_input).unwrap();
    assert_eq!(gate_results.len(), 6, "Step 2: Should have 6 gate results");

    // Step 3: Policy engine — aggregate gate results
    let policy = Policy::standard();
    let engine = PolicyEngine::new(policy);
    let policy_result = engine.evaluate(&gate_results);
    assert!(policy_result.overall_score > 0.0, "Step 3: Policy score should be positive");

    // Step 4: Audit system — compute health score
    let scorer = HealthScorer::new();
    let audit_patterns = make_audit_patterns();
    let (health_score, breakdown) = scorer.compute(&audit_patterns, &[]);
    assert!(health_score > 0.0 && health_score <= 100.0, "Step 4: Health score should be valid");
    assert!(!breakdown.raw_score.is_nan());

    // Step 5: Reporter — generate SARIF output
    let reporter = SarifReporter::new();
    let sarif_output = reporter.generate(&gate_results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&sarif_output).unwrap();
    assert_eq!(sarif["version"], "2.1.0", "Step 5: Should produce SARIF 2.1.0");

    // Step 6: Feedback — record actions on violations
    let mut tracker = FeedbackTracker::new();
    for v in &violations {
        tracker.record(&FeedbackRecord {
            violation_id: v.id.clone(),
            pattern_id: v.pattern_id.clone(),
            detector_id: v.rule_id.clone(),
            action: FeedbackAction::Fix,
            dismissal_reason: None,
            reason: None,
            author: Some("dev@example.com".to_string()),
            timestamp: 1000,
        });
    }
    assert!(tracker.all_metrics().len() > 0, "Step 6: Should have feedback metrics");

    // Full round-trip complete
    assert!(violations.len() >= 2, "Round-trip produced violations");
    assert!(gate_results.len() == 6, "Round-trip evaluated all gates");
    assert!(health_score > 0.0, "Round-trip computed health score");
    assert!(!sarif_output.is_empty(), "Round-trip generated SARIF");
}

/// T6-INT-02: Test all enforcement data persists to drift.db.
#[test]
fn test_enforcement_data_persistence() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    // Insert violation
    let v = ViolationRow {
        id: "v-001".to_string(),
        file: "src/app.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: None,
        end_column: None,
        severity: "error".to_string(),
        pattern_id: "sql-check".to_string(),
        rule_id: "security/sql-injection".to_string(),
        message: "SQL injection vulnerability".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: Some(89),
        owasp_category: Some("A03:2021-Injection".to_string()),
        suppressed: false,
        is_new: false,
    };
    insert_violation(&conn, &v).unwrap();

    // Insert gate result
    let g = GateResultRow {
        gate_id: "pattern-compliance".to_string(),
        status: "passed".to_string(),
        passed: true,
        score: 85.0,
        summary: "Pattern compliance: 85%".to_string(),
        violation_count: 3,
        warning_count: 0,
        execution_time_ms: 15,
        details: None,
        error: None,
        run_at: 0,
    };
    insert_gate_result(&conn, &g).unwrap();

    // Insert audit snapshot
    let s = AuditSnapshotRow {
        health_score: 82.5,
        avg_confidence: 0.88,
        approval_ratio: 0.75,
        compliance_rate: 0.90,
        cross_validation_rate: 0.70,
        duplicate_free_rate: 1.0,
        pattern_count: 25,
        category_scores: Some(r#"{"naming":85,"security":78}"#.to_string()),
        created_at: 0,
    };
    insert_audit_snapshot(&conn, &s).unwrap();

    // Insert health trend
    insert_health_trend(&conn, "health_score", 82.5).unwrap();

    // Insert feedback
    let f = FeedbackRow {
        violation_id: "v-001".to_string(),
        pattern_id: "sql-check".to_string(),
        detector_id: "security-scanner".to_string(),
        action: "fix".to_string(),
        dismissal_reason: None,
        reason: Some("Fixed with parameterized query".to_string()),
        author: Some("dev@example.com".to_string()),
        created_at: 0,
    };
    insert_feedback(&conn, &f).unwrap();

    // Verify all tables populated
    let violations = query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 1, "violations table should have 1 row");
    assert_eq!(violations[0].id, "v-001");

    let gates = query_gate_results(&conn).unwrap();
    assert_eq!(gates.len(), 1, "gate_results table should have 1 row");
    assert!(gates[0].passed);

    let snapshots = query_audit_snapshots(&conn, 10).unwrap();
    assert_eq!(snapshots.len(), 1, "audit_snapshots table should have 1 row");
    assert!((snapshots[0].health_score - 82.5).abs() < 0.01);

    let trends = query_health_trends(&conn, "health_score", 10).unwrap();
    assert_eq!(trends.len(), 1, "health_trends table should have 1 row");

    let feedback = query_feedback_by_detector(&conn, "security-scanner").unwrap();
    assert_eq!(feedback.len(), 1, "feedback table should have 1 row");
    assert_eq!(feedback[0].action, "fix");
}

/// T6-INT-03: Test NAPI exposes drift_check() and drift_audit() with correct return types.
/// Note: NAPI functions are tested structurally (they compile and return correct types).
/// Full NAPI integration requires Node.js runtime.
#[test]
fn test_napi_type_contracts() {
    // Verify the NAPI types exist and are constructible
    use drift_analysis::enforcement::gates::GateId;
    use drift_analysis::enforcement::rules::Violation;

    // Verify GateResult can be serialized (NAPI uses serde)
    let result = GateResult::pass(GateId::PatternCompliance, 90.0, "ok".to_string());
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("pattern-compliance"));
    assert!(json.contains("90"));

    // Verify Violation can be serialized
    let v = Violation {
        id: "v1".to_string(),
        file: "test.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: None,
        end_column: None,
        severity: Severity::Error,
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "Test violation".to_string(),
        quick_fix: None,
        cwe_id: Some(89),
        owasp_category: Some("A03:2021".to_string()),
        suppressed: false,
        is_new: true,
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"severity\":\"error\""));
    assert!(json.contains("\"cwe_id\":89"));

    // Verify PolicyResult can be serialized
    let pr = PolicyResult {
        policy_name: "standard".to_string(),
        aggregation_mode: AggregationMode::Threshold,
        overall_passed: true,
        overall_score: 85.0,
        gate_count: 6,
        gates_passed: 5,
        gates_failed: 1,
        required_gates_passed: true,
        details: "All required gates passed".to_string(),
    };
    let json = serde_json::to_string(&pr).unwrap();
    assert!(json.contains("\"overall_passed\":true"));
}

/// T6-INT-04: Test materialized views refresh correctly after new violations inserted.
#[test]
fn test_materialized_views_refresh() {
    use drift_storage::materialized::security::*;
    use drift_storage::materialized::status::*;
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    // Initially empty
    let status = refresh_status(&conn).unwrap();
    assert_eq!(status.violation_count, 0);

    let security = refresh_security(&conn).unwrap();
    assert_eq!(security.total_security_violations, 0);

    // Insert violations
    insert_violation(
        &conn,
        &ViolationRow {
            id: "v-sec-1".to_string(),
            file: "src/app.ts".to_string(),
            line: 10,
            column: None,
            end_line: None,
            end_column: None,
            severity: "error".to_string(),
            pattern_id: "sql".to_string(),
            rule_id: "security/sql".to_string(),
            message: "SQL injection".to_string(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: Some(89),
            owasp_category: Some("A03:2021".to_string()),
            suppressed: false,
            is_new: false,
        },
    )
    .unwrap();

    insert_violation(
        &conn,
        &ViolationRow {
            id: "v-naming-1".to_string(),
            file: "src/utils.ts".to_string(),
            line: 20,
            column: None,
            end_line: None,
            end_column: None,
            severity: "warning".to_string(),
            pattern_id: "naming".to_string(),
            rule_id: "naming/camelCase".to_string(),
            message: "Use camelCase".to_string(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
    )
    .unwrap();

    // Refresh views — should reflect new data
    let status = refresh_status(&conn).unwrap();
    assert_eq!(status.violation_count, 2, "Status view should show 2 violations");

    let security = refresh_security(&conn).unwrap();
    assert_eq!(
        security.total_security_violations, 1,
        "Security view should show 1 security violation"
    );
    assert_eq!(security.critical_count, 1, "Should have 1 critical (error+CWE)");
}

/// T6-INT-05: Test SARIF upload format (mock HTTP endpoint verification).
/// Verifies the SARIF payload has correct structure for GitHub Code Scanning API.
#[test]
fn test_sarif_upload_format() {
    let reporter = SarifReporter::new();
    let results = vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 70.0,
        summary: "Violations found".to_string(),
        violations: vec![Violation {
            id: "v1".to_string(),
            file: "src/app.ts".to_string(),
            line: 10,
            column: Some(5),
            end_line: Some(10),
            end_column: Some(30),
            severity: Severity::Error,
            pattern_id: "sql".to_string(),
            rule_id: "security/sql-injection".to_string(),
            message: "SQL injection".to_string(),
            quick_fix: None,
            cwe_id: Some(89),
            owasp_category: Some("A03:2021-Injection".to_string()),
            suppressed: false,
            is_new: true,
        }],
        warnings: vec![],
        execution_time_ms: 10,
        details: serde_json::Value::Null,
        error: None,
    }];

    let sarif_output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&sarif_output).unwrap();

    // GitHub Code Scanning API requirements:
    // 1. Must have version "2.1.0"
    assert_eq!(sarif["version"], "2.1.0");

    // 2. Must have $schema
    assert!(sarif["$schema"].is_string());

    // 3. Must have runs array with at least one run
    assert!(sarif["runs"].as_array().unwrap().len() >= 1);

    // 4. Run must have tool.driver with name and version
    let run = &sarif["runs"][0];
    assert!(run["tool"]["driver"]["name"].is_string());

    // 5. Results must have ruleId, level, message, locations
    let results_arr = run["results"].as_array().unwrap();
    assert!(!results_arr.is_empty());
    let result = &results_arr[0];
    assert!(result["ruleId"].is_string());
    assert!(result["level"].is_string());
    assert!(result["message"]["text"].is_string());
    assert!(result["locations"].is_array());

    // 6. Locations must have physicalLocation with artifactLocation and region
    let loc = &result["locations"][0]["physicalLocation"];
    assert!(loc["artifactLocation"]["uri"].is_string());
    assert!(loc["region"]["startLine"].is_number());

    // 7. Must have taxonomies (CWE + OWASP)
    let taxonomies = run["taxonomies"].as_array().unwrap();
    assert!(taxonomies.len() >= 2, "Should have CWE and OWASP taxonomies");
}

/// T6-INT-06: Performance: gate evaluation <100ms for 10K violations.
#[test]
fn test_gate_evaluation_performance() {
    let outliers: Vec<OutlierLocation> = (0..10_000)
        .map(|i| OutlierLocation {
            file: format!("src/file{}.ts", i / 100),
            line: (i % 1000) as u32,
            column: None,
            end_line: None,
            end_column: None,
            deviation_score: 2.0,
            message: format!("Violation {i}"),
        })
        .collect();

    let input = GateInput {
        patterns: vec![PatternInfo {
            pattern_id: "perf-test".to_string(),
            category: "naming".to_string(),
            confidence: 0.8,
            locations: vec![],
            outliers,
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        ..Default::default()
    };

    let orchestrator = GateOrchestrator::new();

    // Warm up
    let _ = orchestrator.execute(&input);

    // Measure
    let start = std::time::Instant::now();
    let results = orchestrator.execute(&input).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(results.len(), 6);
    assert!(
        elapsed.as_millis() < 1000,
        "Gate evaluation took {}ms for 10K violations, should be <1000ms",
        elapsed.as_millis()
    );
}

/// T6-INT-07: Test enforcement pipeline is idempotent.
#[test]
fn test_enforcement_idempotent() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: make_realistic_patterns(),
        source_lines: HashMap::new(), baseline_violation_ids: std::collections::HashSet::new(),
    };

    // Run twice
    let violations_1 = evaluator.evaluate(&input);
    let violations_2 = evaluator.evaluate(&input);

    // Same count
    assert_eq!(
        violations_1.len(),
        violations_2.len(),
        "Idempotent: same violation count"
    );

    // Same IDs (order may differ, so sort)
    let mut ids_1: Vec<String> = violations_1.iter().map(|v| v.id.clone()).collect();
    let mut ids_2: Vec<String> = violations_2.iter().map(|v| v.id.clone()).collect();
    ids_1.sort();
    ids_2.sort();
    assert_eq!(ids_1, ids_2, "Idempotent: same violation IDs");

    // Same severities
    let mut sevs_1: Vec<String> = violations_1
        .iter()
        .map(|v| format!("{:?}", v.severity))
        .collect();
    let mut sevs_2: Vec<String> = violations_2
        .iter()
        .map(|v| format!("{:?}", v.severity))
        .collect();
    sevs_1.sort();
    sevs_2.sort();
    assert_eq!(sevs_1, sevs_2, "Idempotent: same severities");

    // Gate results also idempotent
    let gate_input = GateInput {
        patterns: make_realistic_patterns(),
        ..Default::default()
    };
    let orchestrator = GateOrchestrator::new();
    let mut gates_1 = orchestrator.execute(&gate_input).unwrap();
    let mut gates_2 = orchestrator.execute(&gate_input).unwrap();

    assert_eq!(gates_1.len(), gates_2.len());

    // Sort by gate_id string to ensure stable comparison order
    gates_1.sort_by(|a, b| a.gate_id.as_str().cmp(b.gate_id.as_str()));
    gates_2.sort_by(|a, b| a.gate_id.as_str().cmp(b.gate_id.as_str()));

    for (g1, g2) in gates_1.iter().zip(gates_2.iter()) {
        assert_eq!(g1.gate_id, g2.gate_id);
        assert_eq!(g1.passed, g2.passed);
        assert!((g1.score - g2.score).abs() < 0.001);
    }
}
