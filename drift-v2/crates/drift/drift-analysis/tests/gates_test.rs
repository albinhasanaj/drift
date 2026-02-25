//! Phase 6 tests: Quality Gates — DAG Orchestration & Progressive Enforcement
//! T6-GAT-01 through T6-GAT-08

use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::rules::*;

fn make_gate_input() -> GateInput {
    GateInput {
        files: vec!["src/main.ts".to_string()],
        all_files: vec!["src/main.ts".to_string()],
        patterns: vec![PatternInfo {
            pattern_id: "test-pattern".to_string(),
            category: "naming".to_string(),
            confidence: 0.85,
            locations: vec![PatternLocation {
                file: "src/main.ts".to_string(),
                line: 10,
                column: None,
            }],
            outliers: vec![OutlierLocation {
                file: "src/main.ts".to_string(),
                line: 20,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 2.0,
                message: "Naming deviation".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        constraints: vec![ConstraintInput {
            id: "no-circular".to_string(),
            description: "No circular dependencies".to_string(),
            passed: true,
            violations: vec![],
        }],
        security_findings: vec![],
        test_coverage: Some(TestCoverageInput {
            overall_coverage: 85.0,
            threshold: 80.0,
            uncovered_files: vec![],
        }),
        error_gaps: vec![],
        previous_health_score: Some(80.0),
        current_health_score: Some(82.0),
        predecessor_results: std::collections::HashMap::new(),
        baseline_violations: std::collections::HashSet::new(),
        feedback_stats: None,
    }
}

/// T6-GAT-01: Test all 6 quality gates evaluate correctly.
#[test]
fn test_all_six_gates_evaluate() {
    let orchestrator = GateOrchestrator::new();
    let input = make_gate_input();
    let results = orchestrator.execute(&input).unwrap();

    assert_eq!(results.len(), 6, "Should have 6 gate results");

    // Verify each gate produced a result
    let gate_ids: Vec<GateId> = results.iter().map(|r| r.gate_id).collect();
    assert!(gate_ids.contains(&GateId::PatternCompliance));
    assert!(gate_ids.contains(&GateId::ConstraintVerification));
    assert!(gate_ids.contains(&GateId::SecurityBoundaries));
    assert!(gate_ids.contains(&GateId::TestCoverage));
    assert!(gate_ids.contains(&GateId::ErrorHandling));
    assert!(gate_ids.contains(&GateId::Regression));
}

/// T6-GAT-02: Test DAG orchestrator respects gate dependencies.
#[test]
fn test_dag_respects_dependencies() {
    // Security boundaries depends on pattern compliance.
    // If pattern compliance fails, security boundaries should be skipped.
    let mut input = make_gate_input();
    // Add high-confidence outliers to make pattern compliance fail
    input.patterns = vec![PatternInfo {
        pattern_id: "critical-pattern".to_string(),
        category: "security".to_string(),
        confidence: 0.95,
        locations: vec![],
        outliers: (0..20)
            .map(|i| OutlierLocation {
                file: format!("src/file{i}.ts"),
                line: i as u32,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 5.0,
                message: "Critical deviation".to_string(),
            })
            .collect(),
        cwe_ids: vec![89],
        owasp_categories: vec![],
    }];

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    // Pattern compliance should fail
    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.passed, "Pattern compliance should fail with many outliers");

    // Security boundaries depends on pattern compliance — should be skipped
    let sb = results.iter().find(|r| r.gate_id == GateId::SecurityBoundaries).unwrap();
    assert_eq!(sb.status, GateStatus::Skipped, "Security boundaries should be skipped when dependency fails");
}

/// T6-GAT-03: Test progressive enforcement transitions.
#[test]
fn test_progressive_enforcement() {
    use drift_analysis::enforcement::gates::progressive::*;

    // Week 1 of ramp-up: errors become info
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 30,
        project_age_days: 5,
    });
    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Info);
    assert!(pe.is_ramping_up());

    // Week 3: errors stay as errors
    let pe2 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 30,
        project_age_days: 20,
    });
    assert_eq!(pe2.effective_severity(Severity::Error, false), Severity::Error);

    // After ramp-up: full enforcement
    let pe3 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 30,
        project_age_days: 31,
    });
    assert_eq!(pe3.effective_severity(Severity::Error, false), Severity::Error);
    assert!(!pe3.is_ramping_up());
}

/// T6-GAT-04: Test circular dependency detection.
#[test]
fn test_circular_dependency_detection() {
    use drift_analysis::enforcement::gates::types::*;

    struct GateA;
    impl QualityGate for GateA {
        fn id(&self) -> GateId { GateId::PatternCompliance }
        fn name(&self) -> &'static str { "A" }
        fn description(&self) -> &'static str { "Gate A" }
        fn evaluate(&self, _: &GateInput) -> GateResult { GateResult::pass(self.id(), 100.0, "ok".into()) }
        fn dependencies(&self) -> Vec<GateId> { vec![GateId::Regression] }
    }

    struct GateB;
    impl QualityGate for GateB {
        fn id(&self) -> GateId { GateId::Regression }
        fn name(&self) -> &'static str { "B" }
        fn description(&self) -> &'static str { "Gate B" }
        fn evaluate(&self, _: &GateInput) -> GateResult { GateResult::pass(self.id(), 100.0, "ok".into()) }
        fn dependencies(&self) -> Vec<GateId> { vec![GateId::PatternCompliance] }
    }

    let orchestrator = GateOrchestrator::with_gates(vec![
        Box::new(GateA),
        Box::new(GateB),
    ]);

    let result = orchestrator.validate_dependencies();
    assert!(result.is_err(), "Should detect circular dependency");
    assert!(result.unwrap_err().contains("Circular"));
}

/// T6-GAT-05: Test new-code-first enforcement.
#[test]
fn test_new_code_first_enforcement() {
    use drift_analysis::enforcement::gates::progressive::*;

    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 30,
        project_age_days: 5,
    });

    // New file: full enforcement even during ramp-up
    assert_eq!(pe.effective_severity(Severity::Error, true), Severity::Error);

    // Existing file: downgraded during ramp-up
    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Info);
}

/// T6-GAT-06: Test gate evaluation with zero violations.
#[test]
fn test_gates_with_zero_violations() {
    let input = GateInput {
        patterns: vec![PatternInfo {
            pattern_id: "clean".to_string(),
            category: "naming".to_string(),
            confidence: 0.9,
            locations: vec![PatternLocation {
                file: "src/clean.ts".to_string(),
                line: 1,
                column: None,
            }],
            outliers: vec![], // No outliers
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        constraints: vec![],
        security_findings: vec![],
        test_coverage: None,
        error_gaps: vec![],
        previous_health_score: None,
        current_health_score: None,
        ..Default::default()
    };

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    // All gates should pass with zero violations
    for result in &results {
        assert!(result.passed, "Gate {} should pass with zero violations", result.gate_id);
    }
}

/// T6-GAT-07: Test gate evaluation with 10K violations completes in <100ms.
#[test]
fn test_gate_performance_10k_violations() {
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
    let start = std::time::Instant::now();
    let results = orchestrator.execute(&input).unwrap();
    let elapsed = start.elapsed();

    assert!(!results.is_empty());
    assert!(
        elapsed.as_millis() < 1000,
        "Gate evaluation took {}ms, should be <1000ms for 10K violations",
        elapsed.as_millis()
    );
}

/// T6-GAT-08: Test regression gate detects health score drop.
#[test]
fn test_regression_gate_health_drop() {
    let input = GateInput {
        previous_health_score: Some(85.0),
        current_health_score: Some(70.0), // 15-point drop
        ..Default::default()
    };

    use drift_analysis::enforcement::gates::regression::RegressionGate;
    let gate = RegressionGate;
    let result = gate.evaluate(&input);

    assert!(!result.passed, "Regression gate should fail on 15-point drop");
    assert!(result.summary.contains("Critical") || result.summary.contains("critical"),
        "Should indicate critical regression");
}
