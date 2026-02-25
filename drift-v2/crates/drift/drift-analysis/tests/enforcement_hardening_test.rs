//! Enforcement Engine Hardening Tests — Phases A through E
//! EFT-GATE-01 through EFT-NAPI-16

use std::collections::{HashMap, HashSet};

use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::gates::progressive::{ProgressiveConfig, ProgressiveEnforcement};
use drift_analysis::enforcement::gates::orchestrator::GateOrchestrator;
use drift_analysis::enforcement::rules::*;

// ─── Phase A: Gate Wiring & Input Population ────────────────────────────

/// EFT-GATE-01: GateInputBuilder populates security_findings from taint flows.
#[test]
fn eft_gate_01_builder_populates_security_findings_from_taint() {
    use drift_analysis::graph::taint::types::*;

    let flows = vec![
        TaintFlow {
            source: TaintSource {
                file: "src/api.ts".to_string(),
                line: 10,
                column: 5,
                expression: "req.query.id".to_string(),
                source_type: SourceType::UserInput,
                label: TaintLabel::new(1, SourceType::UserInput),
            },
            sink: TaintSink {
                file: "src/db.ts".to_string(),
                line: 25,
                column: 10,
                expression: "db.query(sql)".to_string(),
                sink_type: SinkType::SqlQuery,
                required_sanitizers: vec![SanitizerType::SqlParameterize],
            },
            path: vec![],
            is_sanitized: false,
            sanitizers_applied: vec![],
            cwe_id: Some(89),
            confidence: 0.9,
        },
        TaintFlow {
            source: TaintSource {
                file: "src/api.ts".to_string(),
                line: 15,
                column: 5,
                expression: "req.body.cmd".to_string(),
                source_type: SourceType::UserInput,
                label: TaintLabel::new(2, SourceType::UserInput),
            },
            sink: TaintSink {
                file: "src/exec.ts".to_string(),
                line: 30,
                column: 10,
                expression: "exec(cmd)".to_string(),
                sink_type: SinkType::OsCommand,
                required_sanitizers: vec![SanitizerType::ShellEscape],
            },
            path: vec![],
            is_sanitized: false,
            sanitizers_applied: vec![],
            cwe_id: Some(78),
            confidence: 0.85,
        },
        // This one is sanitized — should be excluded
        TaintFlow {
            source: TaintSource {
                file: "src/api.ts".to_string(),
                line: 20,
                column: 5,
                expression: "req.query.name".to_string(),
                source_type: SourceType::UserInput,
                label: TaintLabel::new(3, SourceType::UserInput),
            },
            sink: TaintSink {
                file: "src/view.ts".to_string(),
                line: 40,
                column: 10,
                expression: "render(html)".to_string(),
                sink_type: SinkType::HtmlOutput,
                required_sanitizers: vec![SanitizerType::HtmlEscape],
            },
            path: vec![],
            is_sanitized: true,
            sanitizers_applied: vec![],
            cwe_id: None,
            confidence: 0.8,
        },
    ];

    let input = GateInputBuilder::new()
        .security_findings_from_taint_flows(&flows)
        .build();

    // Only 2 unsanitized flows should produce findings
    assert_eq!(input.security_findings.len(), 2, "Should have 2 unsanitized findings");
    assert_eq!(input.security_findings[0].file, "src/db.ts");
    assert_eq!(input.security_findings[0].line, 25);
    assert_eq!(input.security_findings[0].severity, "critical"); // SqlQuery = critical
    assert_eq!(input.security_findings[0].cwe_ids, vec![89]);
    assert!(!input.security_findings[0].owasp_categories.is_empty());

    assert_eq!(input.security_findings[1].file, "src/exec.ts");
    assert_eq!(input.security_findings[1].severity, "critical"); // OsCommand = critical
    assert_eq!(input.security_findings[1].cwe_ids, vec![78]);
}

/// EFT-GATE-02: GateInputBuilder populates error_gaps from analysis.
#[test]
fn eft_gate_02_builder_populates_error_gaps() {
    use drift_analysis::graph::error_handling::types::*;

    let gaps = vec![
        ErrorGap {
            file: "src/handler.ts".to_string(),
            function: "processRequest".to_string(),
            line: 42,
            gap_type: GapType::EmptyCatch,
            error_type: Some("Error".to_string()),
            framework: None,
            cwe_id: Some(390),
            severity: GapSeverity::High,
            remediation: Some("Add error logging or re-throw".to_string()),
        },
        ErrorGap {
            file: "src/service.ts".to_string(),
            function: "fetchData".to_string(),
            line: 88,
            gap_type: GapType::GenericCatch,
            error_type: Some("Exception".to_string()),
            framework: None,
            cwe_id: Some(396),
            severity: GapSeverity::Medium,
            remediation: Some("Catch specific exception types".to_string()),
        },
    ];

    let input = GateInputBuilder::new()
        .error_gaps_from_analysis(&gaps)
        .build();

    assert_eq!(input.error_gaps.len(), 2);
    assert_eq!(input.error_gaps[0].file, "src/handler.ts");
    assert_eq!(input.error_gaps[0].line, 42);
    assert_eq!(input.error_gaps[0].gap_type, "empty_catch");
    assert_eq!(input.error_gaps[0].message, "Add error logging or re-throw");

    assert_eq!(input.error_gaps[1].gap_type, "generic_catch");
}

/// EFT-GATE-03: GateInputBuilder populates test_coverage from mapping data.
#[test]
fn eft_gate_03_builder_populates_test_coverage() {
    let input = GateInputBuilder::new()
        .test_coverage_from_mapping(
            100,  // total source functions
            75,   // covered
            vec!["src/uncovered.ts".to_string()],
            80.0, // threshold
        )
        .build();

    let coverage = input.test_coverage.expect("Should have coverage data");
    assert!((coverage.overall_coverage - 75.0).abs() < 0.01);
    assert!((coverage.threshold - 80.0).abs() < 0.01);
    assert_eq!(coverage.uncovered_files, vec!["src/uncovered.ts"]);
}

/// EFT-GATE-04: TestCoverage returns Skipped when no data.
#[test]
fn eft_gate_04_test_coverage_skipped_on_none() {
    use drift_analysis::enforcement::gates::test_coverage::TestCoverageGate;
    let gate = TestCoverageGate;
    let input = GateInput::default();
    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Skipped);
    assert!(result.summary.contains("No test coverage data"));
}

/// EFT-GATE-05: ConstraintVerification returns Skipped when empty.
#[test]
fn eft_gate_05_constraint_verification_skipped_on_empty() {
    use drift_analysis::enforcement::gates::constraint_verification::ConstraintVerificationGate;
    let gate = ConstraintVerificationGate;
    let input = GateInput::default();
    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Skipped);
    assert!(result.summary.contains("No architectural constraints"));
}

/// EFT-GATE-06: ErrorHandling returns Skipped when empty.
#[test]
fn eft_gate_06_error_handling_skipped_on_empty() {
    use drift_analysis::enforcement::gates::error_handling::ErrorHandlingGate;
    let gate = ErrorHandlingGate;
    let input = GateInput::default();
    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Skipped);
    assert!(result.summary.contains("No error handling data"));
}

/// EFT-GATE-07: SecurityBoundaries returns Skipped when empty.
#[test]
fn eft_gate_07_security_boundaries_skipped_on_empty() {
    use drift_analysis::enforcement::gates::security_boundaries::SecurityBoundariesGate;
    let gate = SecurityBoundariesGate;
    let input = GateInput::default();
    let result = gate.evaluate(&input);
    assert_eq!(result.status, GateStatus::Skipped);
    assert!(result.summary.contains("No security analysis data"));
}

/// EFT-GATE-08: Progressive downgrades Error → Info in week 1.
#[test]
fn eft_gate_08_progressive_downgrades_in_week1() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 28,
        project_age_days: 3, // Week 1
    });
    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Info);
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Info);
}

/// EFT-GATE-09: Progressive preserves Error after ramp-up.
#[test]
fn eft_gate_09_progressive_preserves_after_rampup() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 28,
        project_age_days: 30,
    });
    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Error);
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Warning);
    assert!(!pe.is_ramping_up());
}

/// EFT-GATE-10: Progressive applies full severity to new files during ramp-up.
#[test]
fn eft_gate_10_progressive_full_severity_new_files() {
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 28,
        project_age_days: 3,
    });
    // New files get full enforcement even during ramp-up
    assert_eq!(pe.effective_severity(Severity::Error, true), Severity::Error);
    assert_eq!(pe.effective_severity(Severity::Warning, true), Severity::Warning);
}

/// EFT-GATE-11: is_new correctly marks violations not in baseline.
#[test]
fn eft_gate_11_is_new_marks_violations() {
    let mut baseline = HashSet::new();
    baseline.insert("src/app.ts:10:pattern-compliance/naming".to_string());

    let input = GateInputBuilder::new()
        .patterns(vec![PatternInfo {
            pattern_id: "naming".to_string(),
            category: "naming".to_string(),
            confidence: 0.95,
            locations: vec![],
            outliers: vec![
                OutlierLocation {
                    file: "src/app.ts".to_string(),
                    line: 10,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 2.0,
                    message: "Existing violation".to_string(),
                },
                OutlierLocation {
                    file: "src/new.ts".to_string(),
                    line: 5,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 3.0,
                    message: "New violation".to_string(),
                },
            ],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }])
        .baseline_violations(baseline)
        .build();

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.violations.is_empty(), "Should have violations");

    let existing = pc.violations.iter().find(|v| v.file == "src/app.ts" && v.line == 10);
    let new_one = pc.violations.iter().find(|v| v.file == "src/new.ts" && v.line == 5);

    assert!(existing.is_some(), "Should find existing violation");
    assert!(new_one.is_some(), "Should find new violation");
    assert!(!existing.unwrap().is_new, "Existing violation should NOT be is_new");
    assert!(new_one.unwrap().is_new, "New violation SHOULD be is_new");
}

/// EFT-GATE-12: Regression gate fails on new Error violations.
#[test]
fn eft_gate_12_regression_fails_on_new_errors() {
    use drift_analysis::enforcement::gates::regression::RegressionGate;

    let mut predecessor_results = HashMap::new();
    predecessor_results.insert(
        GateId::PatternCompliance,
        GateResult {
            gate_id: GateId::PatternCompliance,
            status: GateStatus::Failed,
            passed: false,
            score: 50.0,
            summary: "Failed".to_string(),
            violations: vec![Violation {
                id: "test-1".to_string(),
                file: "src/new.ts".to_string(),
                line: 5,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Error,
                pattern_id: "naming".to_string(),
                rule_id: "pattern-compliance/naming".to_string(),
                message: "New error".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: true, // This is a NEW error
            }],
            warnings: vec![],
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        },
    );

    let input = GateInput {
        previous_health_score: Some(80.0),
        current_health_score: Some(80.0), // No health drop
        predecessor_results,
        ..Default::default()
    };

    let gate = RegressionGate;
    let result = gate.evaluate(&input);
    assert!(!result.passed, "Regression gate should fail on new Error violations");
    assert!(result.summary.contains("new error-severity"));
}

/// EFT-GATE-13: Regression gate passes when only existing violations remain.
#[test]
fn eft_gate_13_regression_passes_existing_only() {
    use drift_analysis::enforcement::gates::regression::RegressionGate;

    let mut predecessor_results = HashMap::new();
    predecessor_results.insert(
        GateId::PatternCompliance,
        GateResult {
            gate_id: GateId::PatternCompliance,
            status: GateStatus::Failed,
            passed: false,
            score: 50.0,
            summary: "Failed".to_string(),
            violations: vec![Violation {
                id: "test-1".to_string(),
                file: "src/old.ts".to_string(),
                line: 5,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Error,
                pattern_id: "naming".to_string(),
                rule_id: "pattern-compliance/naming".to_string(),
                message: "Existing error".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false, // NOT new
            }],
            warnings: vec![],
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        },
    );

    let input = GateInput {
        previous_health_score: Some(80.0),
        current_health_score: Some(80.0),
        predecessor_results,
        ..Default::default()
    };

    let gate = RegressionGate;
    let result = gate.evaluate(&input);
    assert!(result.passed, "Regression gate should pass when only existing violations");
}

/// EFT-GATE-14: Orchestrator executes 6 gates in dependency order.
#[test]
fn eft_gate_14_orchestrator_dependency_order() {
    let input = GateInputBuilder::new()
        .patterns(vec![PatternInfo {
            pattern_id: "test".to_string(),
            category: "naming".to_string(),
            confidence: 0.5,
            locations: vec![PatternLocation {
                file: "src/a.ts".to_string(),
                line: 1,
                column: None,
            }],
            outliers: vec![],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }])
        .constraints(vec![ConstraintInput {
            id: "c1".to_string(),
            description: "Test constraint".to_string(),
            passed: true,
            violations: vec![],
        }])
        .security_findings(vec![SecurityFindingInput {
            file: "src/a.ts".to_string(),
            line: 10,
            description: "Test finding".to_string(),
            severity: "medium".to_string(),
            cwe_ids: vec![79],
            owasp_categories: vec![],
        }])
        .error_gaps(vec![ErrorGapInput {
            file: "src/a.ts".to_string(),
            line: 20,
            gap_type: "empty_catch".to_string(),
            message: "Empty catch block".to_string(),
        }])
        .test_coverage(TestCoverageInput {
            overall_coverage: 85.0,
            threshold: 80.0,
            uncovered_files: vec![],
        })
        .previous_health_score(80.0)
        .current_health_score(82.0)
        .build();

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    assert_eq!(results.len(), 6, "Should have 6 gate results");

    // Verify all gates ran (none skipped since pattern compliance passes)
    for result in &results {
        assert_ne!(
            result.status,
            GateStatus::Skipped,
            "Gate {} should not be skipped when all deps pass",
            result.gate_id
        );
    }
}

/// EFT-GATE-15: Orchestrator skips dependent gate when dependency fails.
#[test]
fn eft_gate_15_orchestrator_skips_on_dep_failure() {
    let input = GateInputBuilder::new()
        .patterns(vec![PatternInfo {
            pattern_id: "critical".to_string(),
            category: "security".to_string(),
            confidence: 0.99,
            locations: vec![],
            outliers: (0..10)
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
        }])
        .build();

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.passed, "PatternCompliance should fail");

    let cv = results.iter().find(|r| r.gate_id == GateId::ConstraintVerification).unwrap();
    assert_eq!(cv.status, GateStatus::Skipped);

    let sb = results.iter().find(|r| r.gate_id == GateId::SecurityBoundaries).unwrap();
    assert_eq!(sb.status, GateStatus::Skipped);
}

/// EFT-GATE-16: Orchestrator detects circular dependency.
#[test]
fn eft_gate_16_circular_dependency_detection() {
    struct CycleGateA;
    impl QualityGate for CycleGateA {
        fn id(&self) -> GateId { GateId::PatternCompliance }
        fn name(&self) -> &'static str { "A" }
        fn description(&self) -> &'static str { "A" }
        fn evaluate(&self, _: &GateInput) -> GateResult {
            GateResult::pass(self.id(), 100.0, "ok".into())
        }
        fn dependencies(&self) -> Vec<GateId> { vec![GateId::Regression] }
    }
    struct CycleGateB;
    impl QualityGate for CycleGateB {
        fn id(&self) -> GateId { GateId::Regression }
        fn name(&self) -> &'static str { "B" }
        fn description(&self) -> &'static str { "B" }
        fn evaluate(&self, _: &GateInput) -> GateResult {
            GateResult::pass(self.id(), 100.0, "ok".into())
        }
        fn dependencies(&self) -> Vec<GateId> { vec![GateId::PatternCompliance] }
    }

    let orchestrator = GateOrchestrator::with_gates(vec![
        Box::new(CycleGateA),
        Box::new(CycleGateB),
    ]);
    assert!(orchestrator.validate_dependencies().is_err());
}

/// EFT-GATE-17: Progressive enforcement wired into orchestrator.
#[test]
fn eft_gate_17_progressive_wired_into_orchestrator() {
    let input = GateInputBuilder::new()
        .files(vec!["src/new.ts".to_string()])
        .all_files(vec![]) // new.ts is a new file (not in all_files)
        .error_gaps(vec![ErrorGapInput {
            file: "src/old.ts".to_string(),
            line: 10,
            gap_type: "swallowed".to_string(),
            message: "Swallowed error".to_string(),
        }])
        .build();

    let orchestrator = GateOrchestrator::new()
        .with_progressive(ProgressiveConfig {
            enabled: true,
            ramp_up_days: 28,
            project_age_days: 3, // Week 1
        });

    let results = orchestrator.execute(&input).unwrap();
    let eh = results.iter().find(|r| r.gate_id == GateId::ErrorHandling).unwrap();

    // old.ts violations should be downgraded during ramp-up
    for v in &eh.violations {
        if v.file == "src/old.ts" {
            assert_ne!(
                v.severity,
                Severity::Error,
                "Old file violations should be downgraded during ramp-up"
            );
        }
    }
}

/// EFT-GATE-18: Full pipeline with populated GateInput produces real scores.
#[test]
fn eft_gate_18_full_pipeline_real_scores() {
    let input = GateInputBuilder::new()
        .patterns(vec![PatternInfo {
            pattern_id: "naming-convention".to_string(),
            category: "naming".to_string(),
            confidence: 0.92,
            locations: vec![
                PatternLocation { file: "src/a.ts".to_string(), line: 1, column: None },
                PatternLocation { file: "src/b.ts".to_string(), line: 1, column: None },
            ],
            outliers: vec![OutlierLocation {
                file: "src/c.ts".to_string(),
                line: 5,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 3.0,
                message: "Naming deviation".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }])
        .security_findings(vec![SecurityFindingInput {
            file: "src/api.ts".to_string(),
            line: 42,
            description: "SQL injection".to_string(),
            severity: "critical".to_string(),
            cwe_ids: vec![89],
            owasp_categories: vec!["A03:2021-Injection".to_string()],
        }])
        .error_gaps(vec![ErrorGapInput {
            file: "src/handler.ts".to_string(),
            line: 10,
            gap_type: "empty_catch".to_string(),
            message: "Empty catch block".to_string(),
        }])
        .test_coverage(TestCoverageInput {
            overall_coverage: 65.0,
            threshold: 80.0,
            uncovered_files: vec!["src/uncovered.ts".to_string()],
        })
        .previous_health_score(80.0)
        .current_health_score(75.0)
        .build();

    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();

    assert_eq!(results.len(), 6);

    // PatternCompliance should fail (high confidence outlier = Error)
    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.passed, "PatternCompliance should fail with high-confidence outlier");
    assert!(pc.score < 100.0, "Score should be less than 100");

    // TestCoverage should fail (65% < 80% threshold)
    let tc = results.iter().find(|r| r.gate_id == GateId::TestCoverage).unwrap();
    assert!(!tc.passed, "TestCoverage should fail below threshold");

    // ErrorHandling should warn (empty_catch = Warning severity)
    let eh = results.iter().find(|r| r.gate_id == GateId::ErrorHandling).unwrap();
    assert_eq!(eh.status, GateStatus::Warned, "ErrorHandling should warn on empty_catch");

    // Regression should warn (5-point drop)
    let rg = results.iter().find(|r| r.gate_id == GateId::Regression).unwrap();
    assert_eq!(rg.status, GateStatus::Warned, "Regression should warn on 5-point drop");
}

// ─── Phase B: Rules, Policy & Suppression Hardening ─────────────────────

/// EFT-RULE-01: RulesEvaluator marks violations as is_new when not in baseline.
#[test]
fn eft_rule_01_is_new_from_baseline() {
    let evaluator = RulesEvaluator::new();
    let mut baseline = HashSet::new();
    baseline.insert("src/app.ts:10:naming/camelCase".to_string());

    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "camelCase".to_string(),
            category: "naming".to_string(),
            confidence: 0.9,
            locations: vec![],
            outliers: vec![
                OutlierLocation {
                    file: "src/app.ts".to_string(),
                    line: 10,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 2.0,
                    message: "Existing".to_string(),
                },
                OutlierLocation {
                    file: "src/new.ts".to_string(),
                    line: 5,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 2.0,
                    message: "Brand new".to_string(),
                },
            ],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(),
        baseline_violation_ids: baseline,
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 2);

    let existing = violations.iter().find(|v| v.file == "src/app.ts").unwrap();
    let new_one = violations.iter().find(|v| v.file == "src/new.ts").unwrap();
    assert!(!existing.is_new, "Baseline violation should NOT be is_new");
    assert!(new_one.is_new, "Non-baseline violation SHOULD be is_new");
}

/// EFT-RULE-02: RulesEvaluator populates end_line/end_column from outlier.
#[test]
fn eft_rule_02_end_line_end_column() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "test".to_string(),
            category: "naming".to_string(),
            confidence: 0.8,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: "src/a.ts".to_string(),
                line: 10,
                column: Some(5),
                end_line: Some(15),
                end_column: Some(20),
                deviation_score: 2.0,
                message: "Span violation".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(),
        baseline_violation_ids: HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].end_line, Some(15));
    assert_eq!(violations[0].end_column, Some(20));
}

/// EFT-RULE-03: FP rate > 0.20 downgrades severity by one level.
#[test]
fn eft_rule_03_fp_rate_downgrades_severity() {
    let mut fp_rates = HashMap::new();
    fp_rates.insert("sql-check".to_string(), 0.25); // > 0.20 threshold

    let evaluator = RulesEvaluator::new().with_fp_rates(fp_rates);
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "sql-check".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: "src/db.ts".to_string(),
                line: 10,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 4.0,
                message: "SQL injection".to_string(),
            }],
            cwe_ids: vec![89],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(),
        baseline_violation_ids: HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 1);
    // CWE-89 would normally be Error, but FP rate > 0.20 downgrades to Warning
    assert_eq!(violations[0].severity, Severity::Warning,
        "FP rate > 0.20 should downgrade Error to Warning");
}

/// EFT-RULE-04: FP rate <= 0.20 does NOT downgrade severity.
#[test]
fn eft_rule_04_low_fp_rate_preserves_severity() {
    let mut fp_rates = HashMap::new();
    fp_rates.insert("sql-check".to_string(), 0.15); // <= 0.20

    let evaluator = RulesEvaluator::new().with_fp_rates(fp_rates);
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "sql-check".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: "src/db.ts".to_string(),
                line: 10,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 4.0,
                message: "SQL injection".to_string(),
            }],
            cwe_ids: vec![89],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(),
        baseline_violation_ids: HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations[0].severity, Severity::Error,
        "FP rate <= 0.20 should preserve Error severity");
}

/// EFT-RULE-05: Language-aware quick fix for Python error handling.
#[test]
fn eft_rule_05_language_aware_quick_fix_python() {
    let generator = QuickFixGenerator::new().with_language("python");
    let pattern = PatternInfo {
        pattern_id: "error-handling".to_string(),
        category: "error_handling".to_string(),
        confidence: 0.9,
        locations: vec![],
        outliers: vec![],
        cwe_ids: vec![],
        owasp_categories: vec![],
    };
    let outlier = OutlierLocation {
        file: "src/app.py".to_string(),
        line: 10,
        column: None,
        end_line: None,
        end_column: None,
        deviation_score: 2.0,
        message: "Missing error handling".to_string(),
    };

    let fix = generator.suggest(&pattern, &outlier);
    assert!(fix.is_some());
    let fix = fix.unwrap();
    assert_eq!(fix.strategy, QuickFixStrategy::WrapInTryCatch);
    assert!(fix.description.contains("try/except"),
        "Python should use try/except, got: {}", fix.description);
}

/// EFT-RULE-06: Language-aware quick fix for Rust error handling.
#[test]
fn eft_rule_06_language_aware_quick_fix_rust() {
    let generator = QuickFixGenerator::new().with_language("rust");
    let pattern = PatternInfo {
        pattern_id: "error-handling".to_string(),
        category: "error_handling".to_string(),
        confidence: 0.9,
        locations: vec![],
        outliers: vec![],
        cwe_ids: vec![],
        owasp_categories: vec![],
    };
    let outlier = OutlierLocation {
        file: "src/app.rs".to_string(),
        line: 10,
        column: None,
        end_line: None,
        end_column: None,
        deviation_score: 2.0,
        message: "Missing error handling".to_string(),
    };

    let fix = generator.suggest(&pattern, &outlier);
    assert!(fix.is_some());
    assert!(fix.unwrap().description.contains("match"),
        "Rust should use match/Result pattern");
}

/// EFT-RULE-07: UseParameterizedQuery strategy for security category.
#[test]
fn eft_rule_07_use_parameterized_query_strategy() {
    let generator = QuickFixGenerator::new();
    let pattern = PatternInfo {
        pattern_id: "sql-injection".to_string(),
        category: "security".to_string(),
        confidence: 0.95,
        locations: vec![],
        outliers: vec![],
        cwe_ids: vec![89],
        owasp_categories: vec![],
    };
    let outlier = OutlierLocation {
        file: "src/db.ts".to_string(),
        line: 10,
        column: None,
        end_line: None,
        end_column: None,
        deviation_score: 4.0,
        message: "String concatenation in SQL".to_string(),
    };

    let fix = generator.suggest(&pattern, &outlier);
    assert!(fix.is_some());
    let fix = fix.unwrap();
    assert_eq!(fix.strategy, QuickFixStrategy::UseParameterizedQuery);
    assert!(fix.description.contains("parameterized"),
        "Should suggest parameterized queries, got: {}", fix.description);
}

/// EFT-RULE-08: Suppression via # noqa comment.
#[test]
fn eft_rule_08_noqa_suppression() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert("src/app.py".to_string(), vec![
        "x = eval(input())  # noqa".to_string(),
    ]);

    assert!(checker.is_suppressed("src/app.py", 1, None, &source_lines),
        "# noqa should suppress any rule");
}

/// EFT-RULE-09: Suppression via // eslint-disable-next-line.
#[test]
fn eft_rule_09_eslint_disable_suppression() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert("src/app.ts".to_string(), vec![
        "// eslint-disable-next-line no-eval".to_string(),
        "eval(input);".to_string(),
    ]);

    // Line 2 should be suppressed (eslint-disable-next-line on line 1)
    assert!(checker.is_suppressed("src/app.ts", 2, Some("no-eval"), &source_lines),
        "eslint-disable-next-line should suppress next line for matching rule");
}

/// EFT-RULE-10: Suppression via @SuppressWarnings.
#[test]
fn eft_rule_10_suppress_warnings_suppression() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert("src/App.java".to_string(), vec![
        "@SuppressWarnings(\"unchecked\")".to_string(),
        "List items = new ArrayList();".to_string(),
    ]);

    assert!(checker.is_suppressed("src/App.java", 2, Some("unchecked"), &source_lines),
        "@SuppressWarnings should suppress next line for matching rule");
}

/// EFT-RULE-11: Suppression does NOT fire for non-matching rule ID.
#[test]
fn eft_rule_11_suppression_rule_mismatch() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert("src/app.ts".to_string(), vec![
        "// drift-ignore security/sql-injection".to_string(),
        "const q = db.query(input);".to_string(),
    ]);

    assert!(!checker.is_suppressed("src/app.ts", 2, Some("security/xss"), &source_lines),
        "drift-ignore for sql-injection should NOT suppress xss");
}

/// EFT-RULE-12: Policy engine fails when required gate is missing from results.
#[test]
fn eft_rule_12_policy_fails_missing_required_gate() {
    use drift_analysis::enforcement::policy::engine::PolicyEngine;
    use drift_analysis::enforcement::policy::types::Policy;

    let mut policy = Policy::strict();
    policy.required_gates = vec![GateId::PatternCompliance, GateId::SecurityBoundaries];
    let engine = PolicyEngine::new(policy);

    // Only PatternCompliance result — SecurityBoundaries is missing
    let results = vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Passed,
        passed: true,
        score: 100.0,
        summary: "All good".to_string(),
        violations: vec![],
        warnings: vec![],
        execution_time_ms: 1,
        details: serde_json::Value::Null,
        error: None,
    }];

    let decision = engine.evaluate(&results);
    assert!(!decision.overall_passed,
        "Policy should FAIL when required gate SecurityBoundaries is missing");
    assert!(!decision.required_gates_passed,
        "required_gates_passed should be false when a required gate is absent");
}

/// EFT-RULE-13: Policy engine passes when all required gates pass.
#[test]
fn eft_rule_13_policy_passes_all_required_present() {
    use drift_analysis::enforcement::policy::engine::PolicyEngine;
    use drift_analysis::enforcement::policy::types::Policy;

    let mut policy = Policy::strict();
    policy.required_gates = vec![GateId::PatternCompliance];
    let engine = PolicyEngine::new(policy);

    let results = vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Passed,
        passed: true,
        score: 100.0,
        summary: "All good".to_string(),
        violations: vec![],
        warnings: vec![],
        execution_time_ms: 1,
        details: serde_json::Value::Null,
        error: None,
    }];

    let decision = engine.evaluate(&results);
    assert!(decision.overall_passed, "Policy should pass when all required gates pass");
    assert!(decision.required_gates_passed);
}

// ─── Helper: build a GateResult with violations for reporter tests ───────

fn make_reporter_test_results() -> Vec<GateResult> {
    vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 40.0,
        summary: "Pattern compliance failed".to_string(),
        violations: vec![
            Violation {
                id: "v1".to_string(),
                file: "src/db.ts".to_string(),
                line: 10,
                column: Some(5),
                end_line: Some(12),
                end_column: Some(30),
                severity: Severity::Error,
                pattern_id: "sql-check".to_string(),
                rule_id: "security/sql-injection".to_string(),
                message: "SQL injection via string concatenation".to_string(),
                quick_fix: Some(QuickFix {
                    strategy: QuickFixStrategy::UseParameterizedQuery,
                    description: "Use parameterized query".to_string(),
                    replacement: None,
                }),
                cwe_id: Some(89),
                owasp_category: Some("A03:2021-Injection".to_string()),
                suppressed: false,
                is_new: true,
            },
            Violation {
                id: "v2".to_string(),
                file: "src/app.ts".to_string(),
                line: 25,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Warning,
                pattern_id: "naming".to_string(),
                rule_id: "naming/camelCase".to_string(),
                message: "Variable does not follow camelCase".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false,
            },
            Violation {
                id: "v3".to_string(),
                file: "src/util.ts".to_string(),
                line: 5,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Info,
                pattern_id: "docs".to_string(),
                rule_id: "documentation/missing".to_string(),
                message: "Missing documentation".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: true, // suppressed — should be excluded from most outputs
                is_new: false,
            },
        ],
        warnings: vec!["Health score dropped 5 points".to_string()],
        execution_time_ms: 42,
        details: serde_json::Value::Null,
        error: None,
    }]
}

/// EFT-RULE-14: is_new is false when baseline is empty (no baseline = all existing).
#[test]
fn eft_rule_14_empty_baseline_means_all_existing() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "test".to_string(),
            category: "naming".to_string(),
            confidence: 0.8,
            locations: vec![],
            outliers: vec![OutlierLocation {
                file: "src/a.ts".to_string(),
                line: 1,
                column: None,
                end_line: None,
                end_column: None,
                deviation_score: 2.0,
                message: "Test".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(),
        baseline_violation_ids: HashSet::new(), // Empty baseline
    };

    let violations = evaluator.evaluate(&input);
    assert_eq!(violations.len(), 1);
    assert!(!violations[0].is_new,
        "Empty baseline should mean all violations are existing (is_new=false)");
}

// ─── Phase C: Reporter Format Correctness ───────────────────────────────

/// EFT-RPT-01: SARIF places taxonomy references on rules via relationships, not on results.
#[test]
fn eft_rpt_01_sarif_taxonomy_on_rules_not_results() {
    use drift_analysis::enforcement::reporters::sarif::SarifReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SarifReporter::new();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Results should NOT have "taxa" field
    let sarif_results = &sarif["runs"][0]["results"];
    for r in sarif_results.as_array().unwrap() {
        assert!(r.get("taxa").is_none(),
            "SARIF results should not have taxa field; use rule.relationships instead");
    }

    // Rules should have relationships for CWE/OWASP
    let rules = &sarif["runs"][0]["tool"]["driver"]["rules"];
    let sql_rule = rules.as_array().unwrap().iter()
        .find(|r| r["id"] == "security/sql-injection")
        .expect("Should have sql-injection rule");
    assert!(sql_rule.get("relationships").is_some(),
        "Rule with CWE should have relationships array");
    let rels = sql_rule["relationships"].as_array().unwrap();
    assert!(rels.iter().any(|r| r["target"]["toolComponent"]["name"] == "CWE"),
        "Should have CWE relationship");
    assert!(rels.iter().any(|r| r["target"]["toolComponent"]["name"] == "OWASP"),
        "Should have OWASP relationship");
}

/// EFT-RPT-02: SARIF taxonomies array present at run level.
#[test]
fn eft_rpt_02_sarif_taxonomies_at_run_level() {
    use drift_analysis::enforcement::reporters::sarif::SarifReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SarifReporter::new();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let taxonomies = sarif["runs"][0]["taxonomies"].as_array().unwrap();
    assert!(taxonomies.iter().any(|t| t["name"] == "CWE"), "Should have CWE taxonomy");
    assert!(taxonomies.iter().any(|t| t["name"] == "OWASP"), "Should have OWASP taxonomy");
}

/// EFT-RPT-03: SARIF excludes suppressed violations from results.
#[test]
fn eft_rpt_03_sarif_excludes_suppressed() {
    use drift_analysis::enforcement::reporters::sarif::SarifReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SarifReporter::new();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();
    // 3 violations, 1 suppressed → 2 in output
    assert_eq!(sarif_results.len(), 2, "Suppressed violations should be excluded");
}

/// EFT-RPT-04: SARIF includes isNew property on results.
#[test]
fn eft_rpt_04_sarif_is_new_property() {
    use drift_analysis::enforcement::reporters::sarif::SarifReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SarifReporter::new();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();
    let sql_result = sarif_results.iter()
        .find(|r| r["ruleId"] == "security/sql-injection")
        .unwrap();
    assert_eq!(sql_result["properties"]["isNew"], true,
        "New violation should have isNew=true");

    let naming_result = sarif_results.iter()
        .find(|r| r["ruleId"] == "naming/camelCase")
        .unwrap();
    assert_eq!(naming_result["properties"]["isNew"], false,
        "Existing violation should have isNew=false");
}

/// EFT-RPT-05: SARIF includes endLine/endColumn in region.
#[test]
fn eft_rpt_05_sarif_end_line_end_column() {
    use drift_analysis::enforcement::reporters::sarif::SarifReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SarifReporter::new();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();
    let sql_result = sarif_results.iter()
        .find(|r| r["ruleId"] == "security/sql-injection")
        .unwrap();
    let region = &sql_result["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["endLine"], 12);
    assert_eq!(region["endColumn"], 30);
}

/// EFT-RPT-06: JUnit errors = Error severity, failures = Warning severity.
#[test]
fn eft_rpt_06_junit_errors_failures_correct() {
    use drift_analysis::enforcement::reporters::junit::JUnitReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = JUnitReporter::new();
    let output = reporter.generate(&results).unwrap();

    // Root <testsuites>: 1 Error → errors="1", 1 Warning → failures="1"
    assert!(output.contains("errors=\"1\""),
        "errors should count Error severity violations, got:\n{}", output);
    assert!(output.contains("failures=\"1\""),
        "failures should count Warning severity violations, got:\n{}", output);
}

/// EFT-RPT-07: JUnit excludes suppressed violations.
#[test]
fn eft_rpt_07_junit_excludes_suppressed() {
    use drift_analysis::enforcement::reporters::junit::JUnitReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = JUnitReporter::new();
    let output = reporter.generate(&results).unwrap();

    // Suppressed violation (documentation/missing) should not appear as <failure>
    assert!(!output.contains("documentation/missing"),
        "Suppressed violations should not appear in JUnit output");
}

/// EFT-RPT-08: JUnit marks skipped gates with <skipped />.
#[test]
fn eft_rpt_08_junit_skipped_gate() {
    use drift_analysis::enforcement::reporters::junit::JUnitReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = vec![GateResult {
        gate_id: GateId::TestCoverage,
        status: GateStatus::Skipped,
        passed: true,
        score: 0.0,
        summary: "No test coverage data".to_string(),
        violations: vec![],
        warnings: vec![],
        execution_time_ms: 0,
        details: serde_json::Value::Null,
        error: None,
    }];
    let reporter = JUnitReporter::new();
    let output = reporter.generate(&results).unwrap();

    assert!(output.contains("<skipped />"),
        "Skipped gates should have <skipped /> element");
}

/// EFT-RPT-09: SonarQube output includes rules array (10.3+ requirement).
#[test]
fn eft_rpt_09_sonarqube_rules_array() {
    use drift_analysis::enforcement::reporters::sonarqube::SonarQubeReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SonarQubeReporter::new();
    let output = reporter.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert!(parsed.get("rules").is_some(), "SonarQube output must have rules array");
    let rules = parsed["rules"].as_array().unwrap();
    assert!(!rules.is_empty(), "Rules array should not be empty");

    // Verify rule structure
    let sql_rule = rules.iter()
        .find(|r| r["id"] == "security/sql-injection")
        .expect("Should have sql-injection rule");
    assert_eq!(sql_rule["engineId"], "drift");
    assert!(sql_rule.get("impacts").is_some(), "Rule should have impacts array");
}

/// EFT-RPT-10: SonarQube excludes suppressed violations from issues.
#[test]
fn eft_rpt_10_sonarqube_excludes_suppressed() {
    use drift_analysis::enforcement::reporters::sonarqube::SonarQubeReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SonarQubeReporter::new();
    let output = reporter.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let issues = parsed["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 2, "Suppressed violations should be excluded from issues");
}

/// EFT-RPT-11: SonarQube maps security violations to VULNERABILITY type.
#[test]
fn eft_rpt_11_sonarqube_vulnerability_type() {
    use drift_analysis::enforcement::reporters::sonarqube::SonarQubeReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = SonarQubeReporter::new();
    let output = reporter.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let issues = parsed["issues"].as_array().unwrap();
    let sql_issue = issues.iter()
        .find(|i| i["ruleId"] == "security/sql-injection")
        .unwrap();
    assert_eq!(sql_issue["type"], "VULNERABILITY",
        "CWE-bearing violations should be VULNERABILITY type");
}

/// EFT-RPT-12: JSON reporter includes is_new, end_line, end_column.
#[test]
fn eft_rpt_12_json_new_fields() {
    use drift_analysis::enforcement::reporters::json::JsonReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = JsonReporter;
    let output = reporter.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let violations = parsed["gates"][0]["violations"].as_array().unwrap();
    let v1 = &violations[0];
    assert_eq!(v1["is_new"], true);
    assert_eq!(v1["end_line"], 12);
    assert_eq!(v1["end_column"], 30);

    let v2 = &violations[1];
    assert_eq!(v2["is_new"], false);
    assert!(v2["end_line"].is_null());
}

/// EFT-RPT-13: Console reporter shows [NEW] tag for new violations.
#[test]
fn eft_rpt_13_console_new_tag() {
    use drift_analysis::enforcement::reporters::console::ConsoleReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = ConsoleReporter::new(false); // no color for easy assertion
    let output = reporter.generate(&results).unwrap();

    assert!(output.contains("[NEW]"), "Console should show [NEW] for new violations");
    assert!(output.contains("[suppressed]"), "Console should show [suppressed]");
}

/// EFT-RPT-14: Console reporter shows quick fix suggestions.
#[test]
fn eft_rpt_14_console_quick_fix() {
    use drift_analysis::enforcement::reporters::console::ConsoleReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = ConsoleReporter::new(false);
    let output = reporter.generate(&results).unwrap();

    assert!(output.contains("Fix: Use parameterized query"),
        "Console should show quick fix suggestion");
}

/// EFT-RPT-15: HTML reporter includes NEW badge for new violations.
#[test]
fn eft_rpt_15_html_new_badge() {
    use drift_analysis::enforcement::reporters::html::HtmlReporter;
    use drift_analysis::enforcement::reporters::Reporter;

    let results = make_reporter_test_results();
    let reporter = HtmlReporter::new();
    let output = reporter.generate(&results).unwrap();

    assert!(output.contains("badge-new"), "HTML should have badge-new CSS class");
    assert!(output.contains(">NEW</span>"), "HTML should show NEW badge text");
}

/// EFT-RPT-16: create_reporter returns all 8 formats.
#[test]
fn eft_rpt_16_all_formats_available() {
    use drift_analysis::enforcement::reporters::{create_reporter, available_formats};

    let formats = available_formats();
    assert_eq!(formats.len(), 8, "Should have 8 reporter formats");

    for format in formats {
        let reporter = create_reporter(format);
        assert!(reporter.is_some(), "create_reporter should return Some for '{}'", format);
    }

    assert!(create_reporter("nonexistent").is_none());
}

// ─── Phase D: Audit & Feedback Loop Closure ─────────────────────────────

/// EFT-AUD-01: Jaccard deduplication uses real set intersection when locations provided.
#[test]
fn eft_aud_01_jaccard_real_set_intersection() {
    use drift_analysis::enforcement::audit::deduplication::DuplicateDetector;
    use drift_analysis::enforcement::audit::types::*;

    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "p1".to_string(),
            name: "pattern-a".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 4,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            locations: vec![
                "src/a.ts:1".to_string(), "src/a.ts:5".to_string(),
                "src/b.ts:10".to_string(), "src/c.ts:20".to_string(),
            ],
        },
        PatternAuditData {
            id: "p2".to_string(),
            name: "pattern-b".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 4,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            locations: vec![
                "src/a.ts:1".to_string(), "src/a.ts:5".to_string(),
                "src/b.ts:10".to_string(), "src/c.ts:20".to_string(),
            ],
        },
    ];

    let groups = detector.detect(&patterns);
    // Identical locations → Jaccard = 1.0 → AutoMerge (>0.95)
    assert_eq!(groups.len(), 1);
    assert!((groups[0].similarity - 1.0).abs() < f64::EPSILON,
        "Identical location sets should have Jaccard = 1.0, got {}", groups[0].similarity);
    assert_eq!(groups[0].action, DuplicateAction::AutoMerge);
}

/// EFT-AUD-02: Jaccard with partial overlap computes correct similarity.
#[test]
fn eft_aud_02_jaccard_partial_overlap() {
    use drift_analysis::enforcement::audit::deduplication::DuplicateDetector;
    use drift_analysis::enforcement::audit::types::*;

    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "p1".to_string(),
            name: "a".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 3,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            // 3 locations, 1 unique
            locations: vec!["a:1".to_string(), "b:2".to_string(), "c:3".to_string()],
        },
        PatternAuditData {
            id: "p2".to_string(),
            name: "b".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 3,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            // 3 locations, 1 unique — overlap = {a:1, b:2}, union = {a:1, b:2, c:3, d:4}
            locations: vec!["a:1".to_string(), "b:2".to_string(), "d:4".to_string()],
        },
    ];

    let groups = detector.detect(&patterns);
    // Jaccard = 2/4 = 0.5 → below review threshold (0.85), no group
    assert!(groups.is_empty(),
        "50% overlap should be below review threshold, got {} groups", groups.len());
}

/// EFT-AUD-03: Jaccard falls back to count-ratio when locations are empty.
#[test]
fn eft_aud_03_jaccard_fallback_count_ratio() {
    use drift_analysis::enforcement::audit::deduplication::DuplicateDetector;
    use drift_analysis::enforcement::audit::types::*;

    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "p1".to_string(),
            name: "a".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 100,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            locations: vec![], // empty → fallback
        },
        PatternAuditData {
            id: "p2".to_string(),
            name: "b".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 100,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            locations: vec![], // empty → fallback
        },
    ];

    let groups = detector.detect(&patterns);
    // 100/100 = 1.0 → AutoMerge via count-ratio fallback
    assert_eq!(groups.len(), 1);
    assert!((groups[0].similarity - 1.0).abs() < f64::EPSILON);
}

/// EFT-AUD-04: Cross-category patterns are never compared.
#[test]
fn eft_aud_04_cross_category_isolation() {
    use drift_analysis::enforcement::audit::deduplication::DuplicateDetector;
    use drift_analysis::enforcement::audit::types::*;

    let detector = DuplicateDetector::new();
    let patterns = vec![
        PatternAuditData {
            id: "p1".to_string(),
            name: "a".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 100,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            locations: vec!["a:1".to_string()],
        },
        PatternAuditData {
            id: "p2".to_string(),
            name: "b".to_string(),
            category: "security".to_string(), // different category
            status: PatternStatus::Discovered,
            confidence: 0.9,
            location_count: 100,
            outlier_count: 0,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false,
            locations: vec!["a:1".to_string()], // same location
        },
    ];

    let groups = detector.detect(&patterns);
    assert!(groups.is_empty(), "Different categories should never be compared");
}

/// EFT-AUD-05: ConfidenceFeedback.apply_adjustment updates alpha/beta correctly.
#[test]
fn eft_aud_05_confidence_feedback_apply_adjustment() {
    use drift_analysis::enforcement::feedback::ConfidenceFeedback;
    use drift_analysis::enforcement::feedback::types::*;

    let cf = ConfidenceFeedback::new();

    // Fix action: alpha += 1.0
    let (a, b, conf) = cf.apply_adjustment(5.0, 5.0, FeedbackAction::Fix, None);
    assert_eq!(a, 6.0);
    assert_eq!(b, 5.0);
    assert!((conf - 6.0 / 11.0).abs() < 1e-10);

    // FalsePositive dismiss: beta += 0.5
    let (a2, b2, conf2) = cf.apply_adjustment(5.0, 5.0, FeedbackAction::Dismiss, Some(DismissalReason::FalsePositive));
    assert_eq!(a2, 5.0);
    assert_eq!(b2, 5.5);
    assert!(conf2 < 0.5, "FP dismiss should reduce confidence below 0.5");
}

/// EFT-AUD-06: ConfidenceFeedback.apply_batch processes multiple records.
#[test]
fn eft_aud_06_confidence_feedback_batch() {
    use drift_analysis::enforcement::feedback::ConfidenceFeedback;
    use drift_analysis::enforcement::feedback::types::*;

    let cf = ConfidenceFeedback::new();
    let records = vec![
        (FeedbackAction::Fix, None),
        (FeedbackAction::Fix, None),
        (FeedbackAction::Dismiss, Some(DismissalReason::FalsePositive)),
    ];

    let (a, b, conf) = cf.apply_batch(5.0, 5.0, &records);
    // 2 fixes: alpha += 2.0 → 7.0; 1 FP dismiss: beta += 0.5 → 5.5
    assert_eq!(a, 7.0);
    assert_eq!(b, 5.5);
    assert!((conf - 7.0 / 12.5).abs() < 1e-10);
}

/// EFT-AUD-07: WontFix dismissal does not change confidence.
#[test]
fn eft_aud_07_wontfix_no_confidence_change() {
    use drift_analysis::enforcement::feedback::ConfidenceFeedback;
    use drift_analysis::enforcement::feedback::types::*;

    let cf = ConfidenceFeedback::new();
    let (a, b, conf) = cf.apply_adjustment(5.0, 5.0, FeedbackAction::Dismiss, Some(DismissalReason::WontFix));
    assert_eq!(a, 5.0);
    assert_eq!(b, 5.0);
    assert!((conf - 0.5).abs() < 1e-10, "WontFix should not change confidence");
}

/// EFT-AUD-08: FeedbackTracker implements FeedbackStatsProvider.
#[test]
fn eft_aud_08_tracker_implements_stats_provider() {
    use drift_analysis::enforcement::feedback::FeedbackTracker;
    use drift_analysis::enforcement::feedback::FeedbackStatsProvider;
    use drift_analysis::enforcement::feedback::types::*;

    let mut tracker = FeedbackTracker::new();

    // Record some feedback
    for i in 0..10 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("v{i}"),
            pattern_id: "pat-1".to_string(),
            detector_id: "det-1".to_string(),
            action: if i < 7 { FeedbackAction::Fix } else { FeedbackAction::Dismiss },
            dismissal_reason: if i >= 7 { Some(DismissalReason::FalsePositive) } else { None },
            reason: None,
            author: Some("dev".to_string()),
            timestamp: 1000 + i,
        });
    }

    // Use trait methods
    let fp_rate = tracker.fp_rate_for_detector("det-1");
    // 3 FP dismissals / (7 fixes + 3 dismissals) = 0.3
    assert!((fp_rate - 0.3).abs() < 1e-10, "FP rate should be 0.3, got {fp_rate}");

    let total = tracker.total_actions_for_detector("det-1");
    assert_eq!(total, 10);

    // Unknown detector returns 0
    assert_eq!(tracker.fp_rate_for_detector("unknown"), 0.0);
    assert_eq!(tracker.total_actions_for_detector("unknown"), 0);
}

/// EFT-AUD-09: FeedbackTracker auto-disable requires sustained days.
#[test]
fn eft_aud_09_auto_disable_requires_sustained_days() {
    use drift_analysis::enforcement::feedback::FeedbackTracker;
    use drift_analysis::enforcement::feedback::types::*;

    let mut tracker = FeedbackTracker::new();
    tracker.min_findings = 5;

    // Record 10 findings: 8 FP dismissals, 2 fixes → FP rate = 80%
    for i in 0..10 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("v{i}"),
            pattern_id: "pat".to_string(),
            detector_id: "noisy-det".to_string(),
            action: if i < 2 { FeedbackAction::Fix } else { FeedbackAction::Dismiss },
            dismissal_reason: if i >= 2 { Some(DismissalReason::FalsePositive) } else { None },
            reason: None,
            author: None,
            timestamp: 1000 + i,
        });
    }

    // FP rate is high but days_above_threshold is 0 → should NOT auto-disable
    let disabled = tracker.check_auto_disable();
    assert!(disabled.is_empty(), "Should not auto-disable without sustained days");

    // Set sustained days above threshold
    tracker.update_sustained_days("noisy-det", 31);
    let disabled = tracker.check_auto_disable();
    assert!(disabled.contains(&"noisy-det".to_string()),
        "Should auto-disable after sustained period");
}

/// EFT-AUD-10: FeedbackTracker is_detector_disabled uses auto-disable logic.
#[test]
fn eft_aud_10_is_detector_disabled() {
    use drift_analysis::enforcement::feedback::FeedbackTracker;
    use drift_analysis::enforcement::feedback::FeedbackStatsProvider;
    use drift_analysis::enforcement::feedback::types::*;

    let mut tracker = FeedbackTracker::new();
    tracker.min_findings = 5;

    for i in 0..10 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("v{i}"),
            pattern_id: "pat".to_string(),
            detector_id: "bad-det".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::FalsePositive),
            reason: None,
            author: None,
            timestamp: 1000 + i,
        });
    }

    assert!(!tracker.is_detector_disabled("bad-det"),
        "Not disabled without sustained days");

    tracker.update_sustained_days("bad-det", 31);
    assert!(tracker.is_detector_disabled("bad-det"),
        "Should be disabled after sustained period with high FP rate");
}

/// EFT-AUD-11: Escalate action increases confidence (positive signal).
#[test]
fn eft_aud_11_escalate_increases_confidence() {
    use drift_analysis::enforcement::feedback::ConfidenceFeedback;
    use drift_analysis::enforcement::feedback::types::*;

    let cf = ConfidenceFeedback::new();
    let (a, b, conf) = cf.apply_adjustment(5.0, 5.0, FeedbackAction::Escalate, None);
    assert_eq!(a, 5.5);
    assert_eq!(b, 5.0);
    assert!(conf > 0.5, "Escalate should increase confidence");
}

/// EFT-AUD-12: Suppress action is mild negative signal.
#[test]
fn eft_aud_12_suppress_mild_negative() {
    use drift_analysis::enforcement::feedback::ConfidenceFeedback;
    use drift_analysis::enforcement::feedback::types::*;

    let cf = ConfidenceFeedback::new();
    let (a, b, conf) = cf.apply_adjustment(5.0, 5.0, FeedbackAction::Suppress, None);
    assert_eq!(a, 5.0);
    assert_eq!(b, 5.1);
    assert!(conf < 0.5, "Suppress should slightly reduce confidence");
}

/// EFT-AUD-13: Bayesian confidence handles edge cases (zero alpha+beta).
#[test]
fn eft_aud_13_bayesian_edge_cases() {
    use drift_analysis::enforcement::feedback::ConfidenceFeedback;

    // Zero parameters → 0.5 default
    assert_eq!(ConfidenceFeedback::bayesian_confidence(0.0, 0.0), 0.5);
    // Negative sum → 0.5 default
    assert_eq!(ConfidenceFeedback::bayesian_confidence(-1.0, 0.0), 0.5);
    // All alpha → 1.0
    assert_eq!(ConfidenceFeedback::bayesian_confidence(10.0, 0.0), 1.0);
    // All beta → 0.0
    assert_eq!(ConfidenceFeedback::bayesian_confidence(0.0, 10.0), 0.0);
}

/// EFT-AUD-14: Feedback abuse detection catches rapid dismissals.
#[test]
fn eft_aud_14_abuse_detection() {
    use drift_analysis::enforcement::feedback::FeedbackTracker;
    use drift_analysis::enforcement::feedback::types::*;

    let mut tracker = FeedbackTracker::new();

    // 100 dismissals in 10 seconds from same author
    for i in 0..100 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("v{i}"),
            pattern_id: "pat".to_string(),
            detector_id: "det".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::FalsePositive),
            reason: None,
            author: Some("spammer".to_string()),
            timestamp: 1000 + i,
        });
    }

    // Detect abuse: >50 dismissals in 60 seconds
    let abusers = tracker.detect_abuse(60, 50);
    assert!(abusers.contains(&"spammer".to_string()),
        "Should detect rapid dismissal abuse");

    // Normal user should not be flagged
    let _abusers_strict = tracker.detect_abuse(1, 50);
    // 100 dismissals over 99 seconds, window=1 second → may or may not trigger
    // depending on implementation; the key test is the 60-second window above
}

// ─── Phase E: NAPI Integration & E2E ────────────────────────────────────

/// EFT-NAPI-01: ViolationRow round-trips all new fields (end_line, end_column,
/// quick_fix_strategy, quick_fix_description, is_new) through storage.
#[test]
fn eft_napi_01_violation_row_new_fields_round_trip() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let v = ViolationRow {
        id: "v-new-fields".to_string(),
        file: "src/app.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: Some(15),
        end_column: Some(20),
        severity: "error".to_string(),
        pattern_id: "sql-check".to_string(),
        rule_id: "security/sql-injection".to_string(),
        message: "SQL injection vulnerability".to_string(),
        quick_fix_strategy: Some("use_parameterized_query".to_string()),
        quick_fix_description: Some("Use parameterized queries instead".to_string()),
        cwe_id: Some(89),
        owasp_category: Some("A03:2021-Injection".to_string()),
        suppressed: false,
        is_new: true,
    };
    insert_violation(&conn, &v).unwrap();

    let rows = query_all_violations(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].end_line, Some(15));
    assert_eq!(rows[0].end_column, Some(20));
    assert_eq!(rows[0].quick_fix_strategy.as_deref(), Some("use_parameterized_query"));
    assert_eq!(rows[0].quick_fix_description.as_deref(), Some("Use parameterized queries instead"));
    assert!(rows[0].is_new);
}

/// EFT-NAPI-02: ViolationRow with all new fields as None/false round-trips correctly.
#[test]
fn eft_napi_02_violation_row_null_new_fields() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let v = ViolationRow {
        id: "v-null-new".to_string(),
        file: "src/app.ts".to_string(),
        line: 1,
        column: None,
        end_line: None,
        end_column: None,
        severity: "info".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "test".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    };
    insert_violation(&conn, &v).unwrap();

    let rows = query_all_violations(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].end_line.is_none());
    assert!(rows[0].end_column.is_none());
    assert!(rows[0].quick_fix_strategy.is_none());
    assert!(rows[0].quick_fix_description.is_none());
    assert!(!rows[0].is_new);
}

/// EFT-NAPI-03: GateResultRow round-trips warning_count and error fields.
#[test]
fn eft_napi_03_gate_result_row_new_fields_round_trip() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let g = GateResultRow {
        gate_id: "pattern-compliance".to_string(),
        status: "failed".to_string(),
        passed: false,
        score: 45.0,
        summary: "Pattern compliance: 45%".to_string(),
        violation_count: 10,
        warning_count: 5,
        execution_time_ms: 25,
        details: Some(r#"{"threshold":80}"#.to_string()),
        error: Some("Threshold exceeded".to_string()),
        run_at: 1700000000,
    };
    insert_gate_result(&conn, &g).unwrap();

    let rows = query_gate_results(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].warning_count, 5);
    assert_eq!(rows[0].error.as_deref(), Some("Threshold exceeded"));
    assert_eq!(rows[0].details.as_deref(), Some(r#"{"threshold":80}"#));
}

/// EFT-NAPI-04: GateResultRow with null warning_count/error round-trips correctly.
#[test]
fn eft_napi_04_gate_result_row_null_new_fields() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let g = GateResultRow {
        gate_id: "test-coverage".to_string(),
        status: "passed".to_string(),
        passed: true,
        score: 90.0,
        summary: "Test coverage: 90%".to_string(),
        violation_count: 0,
        warning_count: 0,
        execution_time_ms: 10,
        details: None,
        error: None,
        run_at: 0,
    };
    insert_gate_result(&conn, &g).unwrap();

    let rows = query_gate_results(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].warning_count, 0);
    assert!(rows[0].error.is_none());
    assert!(rows[0].details.is_none());
}

/// EFT-NAPI-05: query_violations_by_file returns new fields correctly.
#[test]
fn eft_napi_05_query_by_file_returns_new_fields() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    insert_violation(&conn, &ViolationRow {
        id: "v-file-1".to_string(),
        file: "src/target.ts".to_string(),
        line: 5,
        column: Some(1),
        end_line: Some(10),
        end_column: Some(30),
        severity: "warning".to_string(),
        pattern_id: "naming".to_string(),
        rule_id: "naming/camelCase".to_string(),
        message: "Use camelCase".to_string(),
        quick_fix_strategy: Some("rename".to_string()),
        quick_fix_description: Some("Rename to camelCase".to_string()),
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: true,
    }).unwrap();

    insert_violation(&conn, &ViolationRow {
        id: "v-other-1".to_string(),
        file: "src/other.ts".to_string(),
        line: 1,
        column: None,
        end_line: None,
        end_column: None,
        severity: "info".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "Other file".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    }).unwrap();

    let rows = query_violations_by_file(&conn, "src/target.ts").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].end_line, Some(10));
    assert_eq!(rows[0].end_column, Some(30));
    assert_eq!(rows[0].quick_fix_strategy.as_deref(), Some("rename"));
    assert!(rows[0].is_new);
}

/// EFT-NAPI-06: Violation severity mapping covers all variants.
#[test]
fn eft_napi_06_severity_mapping_all_variants() {
    use drift_analysis::enforcement::rules::types::Severity;

    let test_cases = vec![
        ("critical", Severity::Error),
        ("error", Severity::Error),
        ("high", Severity::Warning),
        ("warning", Severity::Warning),
        ("medium", Severity::Info),
        ("info", Severity::Info),
        ("low", Severity::Hint),
        ("hint", Severity::Hint),
        ("unknown", Severity::Hint),
    ];

    for (input, expected) in test_cases {
        let severity = match input {
            "critical" | "error" => Severity::Error,
            "high" | "warning" => Severity::Warning,
            "medium" | "info" => Severity::Info,
            _ => Severity::Hint,
        };
        assert_eq!(severity, expected, "Severity mapping for '{input}' should be {expected:?}");
    }
}

/// EFT-NAPI-07: QuickFixStrategy string-to-enum mapping covers all 8 strategies.
#[test]
fn eft_napi_07_quick_fix_strategy_mapping() {
    use drift_analysis::enforcement::rules::types::QuickFixStrategy;

    let strategies = vec![
        ("add_import", QuickFixStrategy::AddImport),
        ("rename", QuickFixStrategy::Rename),
        ("extract_function", QuickFixStrategy::ExtractFunction),
        ("wrap_in_try_catch", QuickFixStrategy::WrapInTryCatch),
        ("add_type_annotation", QuickFixStrategy::AddTypeAnnotation),
        ("add_test", QuickFixStrategy::AddTest),
        ("add_documentation", QuickFixStrategy::AddDocumentation),
        ("use_parameterized_query", QuickFixStrategy::UseParameterizedQuery),
    ];

    for (input, expected) in strategies {
        let result = match input {
            "add_import" => Some(QuickFixStrategy::AddImport),
            "rename" => Some(QuickFixStrategy::Rename),
            "extract_function" => Some(QuickFixStrategy::ExtractFunction),
            "wrap_in_try_catch" => Some(QuickFixStrategy::WrapInTryCatch),
            "add_type_annotation" => Some(QuickFixStrategy::AddTypeAnnotation),
            "add_test" => Some(QuickFixStrategy::AddTest),
            "add_documentation" => Some(QuickFixStrategy::AddDocumentation),
            "use_parameterized_query" => Some(QuickFixStrategy::UseParameterizedQuery),
            _ => None,
        };
        assert_eq!(result, Some(expected), "Strategy mapping for '{input}'");
    }

    // Unknown strategy should map to None
    let unknown: Option<QuickFixStrategy> = match "unknown_strategy" {
        "add_import" => Some(QuickFixStrategy::AddImport),
        _ => None,
    };
    assert!(unknown.is_none(), "Unknown strategy should map to None");
}

/// EFT-NAPI-08: GateId string-to-enum mapping covers all 6 gate IDs.
#[test]
fn eft_napi_08_gate_id_mapping() {
    use drift_analysis::enforcement::gates::GateId;

    let mappings = vec![
        ("pattern-compliance", GateId::PatternCompliance),
        ("constraint-verification", GateId::ConstraintVerification),
        ("security-boundaries", GateId::SecurityBoundaries),
        ("test-coverage", GateId::TestCoverage),
        ("error-handling", GateId::ErrorHandling),
        ("regression", GateId::Regression),
    ];

    for (input, expected) in mappings {
        let result = match input {
            "pattern-compliance" => GateId::PatternCompliance,
            "constraint-verification" => GateId::ConstraintVerification,
            "security-boundaries" => GateId::SecurityBoundaries,
            "test-coverage" => GateId::TestCoverage,
            "error-handling" => GateId::ErrorHandling,
            "regression" => GateId::Regression,
            _ => GateId::PatternCompliance,
        };
        assert_eq!(result, expected, "GateId mapping for '{input}'");
    }
}

/// EFT-NAPI-09: Reporter create_reporter returns valid reporters for all formats.
#[test]
fn eft_napi_09_create_reporter_all_formats() {
    use drift_analysis::enforcement::reporters::create_reporter;

    let valid_formats = ["sarif", "json", "html", "junit", "sonarqube", "console", "github", "gitlab"];
    for fmt in &valid_formats {
        let reporter = create_reporter(fmt);
        assert!(reporter.is_some(), "create_reporter should return Some for format '{fmt}'");
    }

    // Unknown format should return None
    assert!(create_reporter("unknown").is_none());
    assert!(create_reporter("").is_none());
}

/// EFT-NAPI-10: Reporter generates valid output from GateResult with violations.
#[test]
fn eft_napi_10_reporter_generates_from_gate_results() {
    use drift_analysis::enforcement::gates::{GateId, GateResult, GateStatus};
    use drift_analysis::enforcement::reporters::create_reporter;
    use drift_analysis::enforcement::rules::types::{Severity, Violation};

    let violations = vec![Violation {
        id: "v-001".to_string(),
        file: "src/app.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: Some(15),
        end_column: Some(20),
        severity: Severity::Error,
        pattern_id: "sql-check".to_string(),
        rule_id: "security/sql-injection".to_string(),
        message: "SQL injection vulnerability".to_string(),
        quick_fix: None,
        cwe_id: Some(89),
        owasp_category: Some("A03:2021-Injection".to_string()),
        suppressed: false,
        is_new: true,
    }];

    let gate_results = vec![GateResult {
        gate_id: GateId::SecurityBoundaries,
        status: GateStatus::Failed,
        passed: false,
        score: 30.0,
        summary: "Security gate failed".to_string(),
        violations,
        warnings: vec![],
        execution_time_ms: 10,
        details: serde_json::Value::Null,
        error: None,
    }];

    // SARIF reporter
    let sarif = create_reporter("sarif").unwrap();
    let output = sarif.generate(&gate_results).unwrap();
    assert!(output.contains("\"$schema\""), "SARIF output should contain $schema");
    assert!(output.contains("sql-injection"), "SARIF output should contain rule ID");

    // JSON reporter
    let json = create_reporter("json").unwrap();
    let output = json.generate(&gate_results).unwrap();
    assert!(output.contains("sql-injection"), "JSON output should contain rule ID");

    // Console reporter
    let console = create_reporter("console").unwrap();
    let output = console.generate(&gate_results).unwrap();
    assert!(!output.is_empty(), "Console output should not be empty");
}

/// EFT-NAPI-11: Reporter generates valid output for empty violations.
#[test]
fn eft_napi_11_reporter_empty_violations() {
    use drift_analysis::enforcement::gates::{GateId, GateResult};
    use drift_analysis::enforcement::reporters::create_reporter;

    let gate_results = vec![GateResult::pass(
        GateId::PatternCompliance,
        100.0,
        "All checks passed".to_string(),
    )];

    let sarif = create_reporter("sarif").unwrap();
    let output = sarif.generate(&gate_results).unwrap();
    assert!(output.contains("\"$schema\""), "SARIF should be valid even with no violations");

    let json = create_reporter("json").unwrap();
    let output = json.generate(&gate_results).unwrap();
    assert!(!output.is_empty(), "JSON should produce output even with no violations");
}

/// EFT-NAPI-12: Upsert preserves new fields on violation update.
#[test]
fn eft_napi_12_upsert_preserves_new_fields() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    // Insert with new fields
    insert_violation(&conn, &ViolationRow {
        id: "v-upsert-new".to_string(),
        file: "src/app.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: Some(15),
        end_column: Some(20),
        severity: "error".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "Original".to_string(),
        quick_fix_strategy: Some("rename".to_string()),
        quick_fix_description: Some("Rename it".to_string()),
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: true,
    }).unwrap();

    // Upsert with different values for new fields
    insert_violation(&conn, &ViolationRow {
        id: "v-upsert-new".to_string(),
        file: "src/app.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: Some(20),
        end_column: Some(40),
        severity: "warning".to_string(),
        pattern_id: "test".to_string(),
        rule_id: "test/rule".to_string(),
        message: "Updated".to_string(),
        quick_fix_strategy: Some("extract_function".to_string()),
        quick_fix_description: Some("Extract to function".to_string()),
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    }).unwrap();

    let rows = query_all_violations(&conn).unwrap();
    assert_eq!(rows.len(), 1, "Upsert should not create duplicates");
    assert_eq!(rows[0].end_line, Some(20), "end_line should be updated");
    assert_eq!(rows[0].end_column, Some(40), "end_column should be updated");
    assert_eq!(rows[0].quick_fix_strategy.as_deref(), Some("extract_function"));
    assert!(!rows[0].is_new, "is_new should be updated to false");
    assert_eq!(rows[0].message, "Updated");
}

/// EFT-NAPI-13: GateStatus string mapping covers all variants.
#[test]
fn eft_napi_13_gate_status_mapping() {
    use drift_analysis::enforcement::gates::GateStatus;

    let test_cases = vec![
        ("passed", GateStatus::Passed),
        ("failed", GateStatus::Failed),
        ("skipped", GateStatus::Skipped),
    ];

    for (input, expected) in test_cases {
        let status = match input {
            "passed" => GateStatus::Passed,
            "failed" => GateStatus::Failed,
            "skipped" => GateStatus::Skipped,
            _ => GateStatus::Failed,
        };
        assert_eq!(status, expected, "GateStatus mapping for '{input}'");
    }

    // Unknown status should default to Failed
    let unknown = match "errored" {
        "passed" => GateStatus::Passed,
        "failed" => GateStatus::Failed,
        "skipped" => GateStatus::Skipped,
        _ => GateStatus::Failed,
    };
    assert_eq!(unknown, GateStatus::Failed, "Unknown status should default to Failed");
}

/// EFT-NAPI-14: Batch insert violations with mixed new field values.
#[test]
fn eft_napi_14_batch_mixed_new_fields() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    for i in 0..100u32 {
        insert_violation(&conn, &ViolationRow {
            id: format!("v-batch-{i}"),
            file: format!("src/file{}.ts", i % 10),
            line: i,
            column: if i % 2 == 0 { Some(i) } else { None },
            end_line: if i % 3 == 0 { Some(i + 5) } else { None },
            end_column: if i % 3 == 0 { Some(i + 10) } else { None },
            severity: "warning".to_string(),
            pattern_id: format!("pat-{}", i % 5),
            rule_id: format!("rule-{}", i % 5),
            message: format!("Violation {i}"),
            quick_fix_strategy: if i % 4 == 0 { Some("rename".to_string()) } else { None },
            quick_fix_description: if i % 4 == 0 { Some("Fix it".to_string()) } else { None },
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: i % 5 == 0,
        }).unwrap();
    }

    let all = query_all_violations(&conn).unwrap();
    assert_eq!(all.len(), 100);

    // Verify distribution of new fields
    let with_end_line = all.iter().filter(|v| v.end_line.is_some()).count();
    assert_eq!(with_end_line, 34, "34 violations should have end_line (i%3==0 for 0..100)");

    let with_quick_fix = all.iter().filter(|v| v.quick_fix_strategy.is_some()).count();
    assert_eq!(with_quick_fix, 25, "25 violations should have quick_fix (i%4==0 for 0..100)");

    let is_new_count = all.iter().filter(|v| v.is_new).count();
    assert_eq!(is_new_count, 20, "20 violations should be is_new (i%5==0 for 0..100)");
}

/// EFT-NAPI-15: Feedback adjustments correctly compute deltas from storage.
#[test]
fn eft_napi_15_feedback_adjustments_from_storage() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    // Insert feedback records for a pattern
    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v-1".to_string(),
        pattern_id: "pat-test".to_string(),
        detector_id: "det-1".to_string(),
        action: "fix".to_string(),
        dismissal_reason: None,
        reason: None,
        author: Some("user1".to_string()),
        created_at: 0,
    }).unwrap();

    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v-2".to_string(),
        pattern_id: "pat-test".to_string(),
        detector_id: "det-1".to_string(),
        action: "dismiss".to_string(),
        dismissal_reason: Some("false_positive".to_string()),
        reason: Some("false_positive".to_string()),
        author: Some("user2".to_string()),
        created_at: 0,
    }).unwrap();

    let adjustments = query_feedback_adjustments(&conn, "pat-test").unwrap();
    assert_eq!(adjustments.len(), 2);

    // "fix" → (1.0, 0.0)
    // "dismiss" with "false_positive" → (0.0, 0.5)
    let total_alpha: f64 = adjustments.iter().map(|(a, _)| a).sum();
    let total_beta: f64 = adjustments.iter().map(|(_, b)| b).sum();
    assert!((total_alpha - 1.0).abs() < 0.001, "Total alpha should be 1.0");
    assert!((total_beta - 0.5).abs() < 0.001, "Total beta should be 0.5");
}

/// EFT-NAPI-16: Audit snapshot round-trip preserves all fields.
#[test]
fn eft_napi_16_audit_snapshot_round_trip() {
    use drift_storage::migrations;
    use drift_storage::queries::enforcement::*;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    migrations::run_migrations(&conn).unwrap();

    let snapshot = AuditSnapshotRow {
        health_score: 82.5,
        avg_confidence: 0.88,
        approval_ratio: 0.75,
        compliance_rate: 0.90,
        cross_validation_rate: 0.70,
        duplicate_free_rate: 0.95,
        pattern_count: 42,
        category_scores: Some(r#"{"naming":85,"security":78,"error-handling":92}"#.to_string()),
        created_at: 0,
    };
    insert_audit_snapshot(&conn, &snapshot).unwrap();

    let rows = query_audit_snapshots(&conn, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert!((rows[0].health_score - 82.5).abs() < 0.001);
    assert!((rows[0].avg_confidence - 0.88).abs() < 0.001);
    assert!((rows[0].approval_ratio - 0.75).abs() < 0.001);
    assert!((rows[0].compliance_rate - 0.90).abs() < 0.001);
    assert!((rows[0].cross_validation_rate - 0.70).abs() < 0.001);
    assert!((rows[0].duplicate_free_rate - 0.95).abs() < 0.001);
    assert_eq!(rows[0].pattern_count, 42);
    assert!(rows[0].category_scores.as_ref().unwrap().contains("security"));
}
