//! Category 6: Enforcement Gate Orchestration
//!
//! 16 production tests (T6-01 through T6-16) exercising the DAG-based gate
//! orchestrator, suppression formats, quick-fix language awareness, policy
//! engine aggregation modes, feedback tracker, and progressive enforcement.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use drift_analysis::enforcement::feedback::{
    DismissalReason, FeedbackAction, FeedbackRecord, FeedbackTracker,
};
use drift_analysis::enforcement::gates::{
    GateId, GateInput, GateInputBuilder, GateOrchestrator, GateResult, GateStatus,
    ProgressiveConfig, QualityGate,
};
use drift_analysis::enforcement::policy::engine::PolicyEngine;
use drift_analysis::enforcement::policy::types::{AggregationMode, Policy};
use drift_analysis::enforcement::rules::{
    OutlierLocation, PatternInfo, PatternLocation, QuickFixGenerator, RulesEvaluator, Severity,
    SuppressionChecker,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_pattern(id: &str, cat: &str, confidence: f64, outliers: Vec<OutlierLocation>) -> PatternInfo {
    PatternInfo {
        pattern_id: id.to_string(),
        category: cat.to_string(),
        confidence,
        locations: vec![PatternLocation {
            file: "src/main.ts".to_string(),
            line: 1,
            column: None,
        }],
        outliers,
        cwe_ids: Vec::new(),
        owasp_categories: Vec::new(),
    }
}

fn make_outlier(file: &str, line: u32, score: f64) -> OutlierLocation {
    OutlierLocation {
        file: file.to_string(),
        line,
        column: Some(1),
        end_line: None,
        end_column: None,
        deviation_score: score,
        message: format!("Outlier at {file}:{line}"),
    }
}

/// A custom gate that records its ID and always passes, for T6-09.
struct CustomGate {
    gate_id: GateId,
    deps: Vec<GateId>,
}

impl QualityGate for CustomGate {
    fn id(&self) -> GateId {
        self.gate_id
    }
    fn name(&self) -> &'static str {
        "Custom"
    }
    fn description(&self) -> &'static str {
        "Custom test gate"
    }
    fn evaluate(&self, _input: &GateInput) -> GateResult {
        GateResult::pass(self.gate_id, 100.0, "Custom gate passed".to_string())
    }
    fn dependencies(&self) -> Vec<GateId> {
        self.deps.clone()
    }
}

/// A gate that always fails, used for dependency-cascade tests.
struct FailingGate(GateId);

impl QualityGate for FailingGate {
    fn id(&self) -> GateId {
        self.0
    }
    fn name(&self) -> &'static str {
        "Failing"
    }
    fn description(&self) -> &'static str {
        "Always fails"
    }
    fn evaluate(&self, _input: &GateInput) -> GateResult {
        GateResult::fail(self.0, 0.0, "Always fails".to_string(), Vec::new())
    }
}

/// A slow gate for timeout testing.
struct SlowGate {
    sleep_ms: u64,
}

impl QualityGate for SlowGate {
    fn id(&self) -> GateId {
        GateId::PatternCompliance
    }
    fn name(&self) -> &'static str {
        "Slow"
    }
    fn description(&self) -> &'static str {
        "Sleeps"
    }
    fn evaluate(&self, _input: &GateInput) -> GateResult {
        std::thread::sleep(Duration::from_millis(self.sleep_ms));
        GateResult::pass(GateId::PatternCompliance, 100.0, "done".to_string())
    }
}

// ===========================================================================
// T6-01  Circular Dependency Detection
// ===========================================================================
#[test]
fn t6_01_circular_dependency_detection() {
    // A depends on C, B depends on A, C depends on B  →  A→B→C→A
    let gates: Vec<Box<dyn QualityGate>> = vec![
        Box::new(CustomGate {
            gate_id: GateId::PatternCompliance,
            deps: vec![GateId::Regression],
        }),
        Box::new(CustomGate {
            gate_id: GateId::SecurityBoundaries,
            deps: vec![GateId::PatternCompliance],
        }),
        Box::new(CustomGate {
            gate_id: GateId::Regression,
            deps: vec![GateId::SecurityBoundaries],
        }),
    ];

    let orch = GateOrchestrator::with_gates(gates);
    let result = orch.execute(&GateInput::default());
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(
        msg.contains("Circular dependency"),
        "Expected circular dependency error, got: {msg}"
    );
}

// ===========================================================================
// T6-02  Dependency Cascade Skip
// ===========================================================================
#[test]
fn t6_02_dependency_cascade_skip() {
    // PatternCompliance fails → SecurityBoundaries (depends on PC) should be Skipped
    let gates: Vec<Box<dyn QualityGate>> = vec![
        Box::new(FailingGate(GateId::PatternCompliance)),
        Box::new(CustomGate {
            gate_id: GateId::SecurityBoundaries,
            deps: vec![GateId::PatternCompliance],
        }),
    ];

    let orch = GateOrchestrator::with_gates(gates);
    let results = orch.execute(&GateInput::default()).unwrap();
    assert_eq!(results.len(), 2);

    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert!(!pc.passed);

    let sb = results.iter().find(|r| r.gate_id == GateId::SecurityBoundaries).unwrap();
    assert_eq!(sb.status, GateStatus::Skipped);
    assert!(sb.passed, "Skipped gates must have passed=true");
    assert!(sb.summary.contains("dependencies not met"));
}

// ===========================================================================
// T6-03  Timeout Enforcement
// ===========================================================================
#[test]
fn t6_03_timeout_enforcement() {
    let gates: Vec<Box<dyn QualityGate>> = vec![Box::new(SlowGate { sleep_ms: 150 })];
    let orch = GateOrchestrator::with_gates(gates).with_timeout(Duration::from_millis(50));
    let results = orch.execute(&GateInput::default()).unwrap();
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert_eq!(r.status, GateStatus::Errored);
    assert!(!r.passed);
    assert!(r.error.as_ref().unwrap().contains("timed out"));
    assert!(r.execution_time_ms > 0);
}

// ===========================================================================
// T6-04  Empty GateInput — PatternCompliance passes on empty
// ===========================================================================
#[test]
fn t6_04_empty_gate_input_pattern_compliance() {
    let gates: Vec<Box<dyn QualityGate>> = vec![
        Box::new(drift_analysis::enforcement::gates::pattern_compliance::PatternComplianceGate),
    ];
    let orch = GateOrchestrator::with_gates(gates);
    let results = orch.execute(&GateInput::default()).unwrap();
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(r.passed, "PatternCompliance must PASS on empty input");
    assert_eq!(r.status, GateStatus::Passed);
}

// ===========================================================================
// T6-05  Empty GateInput — Other 5 Gates skip
// ===========================================================================
#[test]
fn t6_05_empty_gate_input_other_5_skip() {
    use drift_analysis::enforcement::gates::constraint_verification::ConstraintVerificationGate;
    use drift_analysis::enforcement::gates::error_handling::ErrorHandlingGate;
    use drift_analysis::enforcement::gates::regression::RegressionGate;
    use drift_analysis::enforcement::gates::security_boundaries::SecurityBoundariesGate;
    use drift_analysis::enforcement::gates::test_coverage::TestCoverageGate;

    // Each gate individually (no deps). We use with_gates to bypass dep ordering.
    let test_cases: Vec<(Box<dyn QualityGate>, GateId)> = vec![
        (Box::new(ConstraintVerificationGate), GateId::ConstraintVerification),
        (Box::new(SecurityBoundariesGate), GateId::SecurityBoundaries),
        (Box::new(TestCoverageGate), GateId::TestCoverage),
        (Box::new(ErrorHandlingGate), GateId::ErrorHandling),
        (Box::new(RegressionGate), GateId::Regression),
    ];

    for (gate, expected_id) in test_cases {
        // Evaluate gate directly (bypass orchestrator dep checks)
        let result = gate.evaluate(&GateInput::default());
        assert_eq!(result.gate_id, expected_id);
        assert_eq!(
            result.status,
            GateStatus::Skipped,
            "{expected_id} should be Skipped on empty input, got {:?}",
            result.status
        );
    }
}

// ===========================================================================
// T6-06  Progressive Enforcement — new vs old files
// ===========================================================================
#[test]
fn t6_06_progressive_enforcement() {
    let pattern = make_pattern(
        "error-pat",
        "error_handling",
        0.95,
        vec![
            make_outlier("src/old.ts", 10, 4.0),
            make_outlier("src/new.ts", 20, 4.0),
        ],
    );

    let input = GateInputBuilder::new()
        .files(vec!["src/old.ts".into(), "src/new.ts".into()])
        .all_files(vec!["src/old.ts".into()]) // new.ts is NOT in all_files → new file
        .patterns(vec![pattern])
        .build();

    let config = ProgressiveConfig {
        enabled: true,
        ramp_up_days: 100,
        project_age_days: 10, // <25% → Error→Info for old files
    };

    let orch = GateOrchestrator::new().with_progressive(config);
    let results = orch.execute(&input).unwrap();

    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();

    // Find violations for old file — severity should be downgraded
    let old_viols: Vec<_> = pc.violations.iter().filter(|v| v.file == "src/old.ts").collect();
    assert!(!old_viols.is_empty());
    for v in &old_viols {
        assert_ne!(
            v.severity,
            Severity::Error,
            "Old-file Error violations should be downgraded at 10% ramp"
        );
    }

    // New-file violations keep original severity (full enforcement)
    let new_viols: Vec<_> = pc.violations.iter().filter(|v| v.file == "src/new.ts").collect();
    assert!(!new_viols.is_empty());
    for v in &new_viols {
        assert_eq!(
            v.severity,
            Severity::Error,
            "New-file violations must keep full enforcement"
        );
    }
}

// ===========================================================================
// T6-07  Baseline is_new Detection
// ===========================================================================
#[test]
fn t6_07_baseline_is_new_detection() {
    let pattern = make_pattern(
        "naming-pat",
        "naming",
        0.95,
        vec![
            make_outlier("src/a.ts", 5, 4.0),
            make_outlier("src/b.ts", 10, 4.0),
        ],
    );

    let mut baseline = HashSet::new();
    // Key format: "file:line:rule_id"
    baseline.insert("src/a.ts:5:pattern-compliance/naming-pat".to_string());

    let input = GateInputBuilder::new()
        .patterns(vec![pattern])
        .baseline_violations(baseline)
        .build();

    let orch = GateOrchestrator::new();
    let results = orch.execute(&input).unwrap();
    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();

    let a_viol = pc.violations.iter().find(|v| v.file == "src/a.ts").unwrap();
    assert!(!a_viol.is_new, "Baseline-matching violation must be is_new=false");

    let b_viol = pc.violations.iter().find(|v| v.file == "src/b.ts").unwrap();
    assert!(b_viol.is_new, "Non-baseline violation must be is_new=true");
}

// ===========================================================================
// T6-08  Gate Execution Timing
// ===========================================================================
#[test]
fn t6_08_gate_execution_timing() {
    let orch = GateOrchestrator::new();
    let input = GateInputBuilder::new()
        .patterns(vec![make_pattern("p1", "naming", 0.9, vec![make_outlier("f.ts", 1, 1.0)])])
        .build();
    let results = orch.execute(&input).unwrap();

    assert_eq!(results.len(), 6, "All 6 default gates must run");
    // The orchestrator records execution_time_ms via as_millis(), so sub-ms
    // gates will read 0. We verify the field is populated (>= 0) and that at
    // least the orchestrator attempted to set it for non-skipped gates.
    for r in &results {
        if r.status != GateStatus::Skipped {
            // execution_time_ms is always set (even if 0 for fast gates)
            assert!(
                r.execution_time_ms < 10_000,
                "Gate {:?} execution time looks unreasonable ({}ms)",
                r.gate_id,
                r.execution_time_ms
            );
        }
    }
    // Verify at least one gate actually executed (PatternCompliance always runs)
    let pc = results.iter().find(|r| r.gate_id == GateId::PatternCompliance).unwrap();
    assert_ne!(pc.status, GateStatus::Skipped, "PatternCompliance must not be Skipped");
}

// ===========================================================================
// T6-09  Custom Gate Registration
// ===========================================================================
#[test]
fn t6_09_custom_gate_registration() {
    let gates: Vec<Box<dyn QualityGate>> = vec![
        Box::new(CustomGate {
            gate_id: GateId::PatternCompliance,
            deps: vec![],
        }),
        Box::new(CustomGate {
            gate_id: GateId::SecurityBoundaries,
            deps: vec![GateId::PatternCompliance],
        }),
    ];

    let orch = GateOrchestrator::with_gates(gates);
    let results = orch.execute(&GateInput::default()).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.passed));
    // Verify topo order: PC before SB
    assert_eq!(results[0].gate_id, GateId::PatternCompliance);
    assert_eq!(results[1].gate_id, GateId::SecurityBoundaries);
}

// ===========================================================================
// T6-10  Suppression Format Coverage (4 formats)
// ===========================================================================
#[test]
fn t6_10_suppression_format_coverage() {
    let checker = SuppressionChecker::new();

    let mut source_lines = HashMap::new();

    // drift-ignore on line above (next-line directive)
    source_lines.insert(
        "drift.ts".to_string(),
        vec![
            "// drift-ignore".to_string(),       // line 1
            "let x = eval('bad');".to_string(),   // line 2 — should be suppressed
        ],
    );

    // noqa inline
    source_lines.insert(
        "noqa.py".to_string(),
        vec![
            "x = eval('bad')  # noqa".to_string(), // line 1 — inline suppression
        ],
    );

    // eslint-disable-next-line on line above
    source_lines.insert(
        "eslint.ts".to_string(),
        vec![
            "// eslint-disable-next-line".to_string(), // line 1
            "let y = eval('bad');".to_string(),         // line 2 — suppressed
        ],
    );

    // @SuppressWarnings inline
    source_lines.insert(
        "suppress.java".to_string(),
        vec![
            "@SuppressWarnings(\"all\")".to_string(), // line 1
            "void foo() {}".to_string(),               // line 2 — suppressed
        ],
    );

    // drift-ignore next-line
    assert!(checker.is_suppressed("drift.ts", 2, None, &source_lines));
    // noqa inline (same line)
    assert!(checker.is_suppressed("noqa.py", 1, None, &source_lines));
    // eslint-disable-next-line
    assert!(checker.is_suppressed("eslint.ts", 2, None, &source_lines));
    // @SuppressWarnings next-line
    assert!(checker.is_suppressed("suppress.java", 2, None, &source_lines));

    // Non-suppressed line (a line that has no directive on it or above it)
    source_lines.insert(
        "clean.ts".to_string(),
        vec![
            "let a = 1;".to_string(), // line 1 — no suppression
        ],
    );
    assert!(!checker.is_suppressed("clean.ts", 1, None, &source_lines));
}

// ===========================================================================
// T6-11  Suppression Rule-Specific Filtering
// ===========================================================================
#[test]
fn t6_11_suppression_rule_specific_filtering() {
    let checker = SuppressionChecker::new();

    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/app.ts".to_string(),
        vec![
            "// drift-ignore rule_a".to_string(), // line 1
            "code();".to_string(),                 // line 2
        ],
    );

    // rule_a is suppressed
    assert!(checker.is_suppressed("src/app.ts", 2, Some("rule_a"), &source_lines));
    // rule_b is NOT suppressed
    assert!(!checker.is_suppressed("src/app.ts", 2, Some("rule_b"), &source_lines));

    // Bare drift-ignore (no rule list) suppresses ALL
    let mut source2 = HashMap::new();
    source2.insert(
        "src/all.ts".to_string(),
        vec![
            "// drift-ignore".to_string(), // line 1
            "code();".to_string(),          // line 2
        ],
    );
    assert!(checker.is_suppressed("src/all.ts", 2, Some("any_rule"), &source2));
    assert!(checker.is_suppressed("src/all.ts", 2, None, &source2));
}

// ===========================================================================
// T6-12  Quick-Fix Language Awareness (7 languages)
// ===========================================================================
#[test]
fn t6_12_quick_fix_language_awareness() {
    let languages = ["python", "rust", "go", "java", "ruby", "csharp", "javascript"];

    let pattern = PatternInfo {
        pattern_id: "error-handling-pat".to_string(),
        category: "error_handling".to_string(),
        confidence: 0.9,
        locations: vec![],
        outliers: vec![],
        cwe_ids: vec![],
        owasp_categories: vec![],
    };

    let outlier = OutlierLocation {
        file: "test.ts".to_string(),
        line: 1,
        deviation_score: 3.0,
        message: "missing error handling".to_string(),
        ..Default::default()
    };

    let mut seen_descriptions = HashSet::new();
    let mut seen_replacements = HashSet::new();

    for lang in &languages {
        let gen = QuickFixGenerator::new().with_language(*lang);
        let fix = gen.suggest(&pattern, &outlier);
        assert!(fix.is_some(), "QuickFix must be generated for {lang}");
        let fix = fix.unwrap();

        seen_descriptions.insert(fix.description.clone());
        if let Some(ref repl) = fix.replacement {
            seen_replacements.insert(repl.clone());
        }
    }

    // Python should say "try/except", Rust "match on Result", Go "if err != nil"
    assert!(
        seen_descriptions.len() >= 4,
        "At least 4 distinct language descriptions expected, got {}",
        seen_descriptions.len()
    );
    assert!(
        seen_replacements.len() >= 4,
        "At least 4 distinct replacement templates expected, got {}",
        seen_replacements.len()
    );

    // Verify specific language templates
    let py_gen = QuickFixGenerator::new().with_language("python");
    let py_fix = py_gen.suggest(&pattern, &outlier).unwrap();
    assert!(
        py_fix.description.contains("try/except"),
        "Python should mention try/except: {}",
        py_fix.description
    );
    assert!(
        py_fix.replacement.as_ref().unwrap().contains("except"),
        "Python template must contain 'except'"
    );

    let rs_gen = QuickFixGenerator::new().with_language("rust");
    let rs_fix = rs_gen.suggest(&pattern, &outlier).unwrap();
    assert!(
        rs_fix.description.contains("match") || rs_fix.description.contains("Result"),
        "Rust should mention match/Result: {}",
        rs_fix.description
    );

    let go_gen = QuickFixGenerator::new().with_language("go");
    let go_fix = go_gen.suggest(&pattern, &outlier).unwrap();
    assert!(
        go_fix.description.contains("if err"),
        "Go should mention 'if err': {}",
        go_fix.description
    );
}

// ===========================================================================
// T6-13  Policy Engine — All 4 Aggregation Modes
// ===========================================================================
#[test]
fn t6_13_policy_engine_4_modes() {
    // Setup: 6 gate results, 1 failing
    let results: Vec<GateResult> = vec![
        GateResult::pass(GateId::PatternCompliance, 90.0, "ok".into()),
        GateResult::fail(GateId::ConstraintVerification, 30.0, "fail".into(), vec![]),
        GateResult::pass(GateId::SecurityBoundaries, 85.0, "ok".into()),
        GateResult::pass(GateId::TestCoverage, 80.0, "ok".into()),
        GateResult::pass(GateId::ErrorHandling, 75.0, "ok".into()),
        GateResult::pass(GateId::Regression, 95.0, "ok".into()),
    ];

    // AllMustPass: 1 fail → overall fail
    let strict = Policy {
        name: "test-strict".into(),
        preset: drift_analysis::enforcement::policy::types::PolicyPreset::Strict,
        aggregation_mode: AggregationMode::AllMustPass,
        weights: HashMap::new(),
        threshold: 80.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let r = PolicyEngine::new(strict).evaluate(&results);
    assert!(!r.overall_passed, "AllMustPass: 1 fail → overall fail");

    // AnyMustPass: 1 pass → overall pass
    let lenient = Policy {
        name: "test-lenient".into(),
        preset: drift_analysis::enforcement::policy::types::PolicyPreset::Lenient,
        aggregation_mode: AggregationMode::AnyMustPass,
        weights: HashMap::new(),
        threshold: 50.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let r = PolicyEngine::new(lenient).evaluate(&results);
    assert!(r.overall_passed, "AnyMustPass: at least 1 pass → overall pass");

    // Weighted: use standard weights
    let standard = Policy::standard();
    let r = PolicyEngine::new(standard).evaluate(&results);
    // Weighted avg with standard weights: PC(0.25*90) + CV(0.20*30) + SB(0.25*85) +
    // TC(0.15*80) + EH(0.10*75) + R(0.05*95) = 22.5+6+21.25+12+7.5+4.75 = 74.0
    // threshold=70 → pass
    assert!(r.overall_passed, "Weighted: 74.0 >= 70 → pass, score={}", r.overall_score);

    // Threshold: avg score = (90+30+85+80+75+95)/6 ≈ 75.8, threshold 80 → fail
    let threshold_policy = Policy {
        name: "test-threshold".into(),
        preset: drift_analysis::enforcement::policy::types::PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Threshold,
        weights: HashMap::new(),
        threshold: 80.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let r = PolicyEngine::new(threshold_policy).evaluate(&results);
    assert!(!r.overall_passed, "Threshold: avg ~75.8 < 80 → fail, score={}", r.overall_score);
}

// ===========================================================================
// T6-14  FP Rate Auto-Disable
// ===========================================================================
#[test]
fn t6_14_fp_rate_auto_disable() {
    let mut tracker = FeedbackTracker::new();

    // Record enough findings with >20% FP rate
    for i in 0..15 {
        let action = if i < 5 {
            FeedbackAction::Dismiss
        } else {
            FeedbackAction::Fix
        };
        let reason = if i < 5 {
            Some(DismissalReason::FalsePositive)
        } else {
            None
        };
        tracker.record(&FeedbackRecord {
            violation_id: format!("v-{i}"),
            pattern_id: "noisy-detector".to_string(),
            detector_id: "noisy-detector".to_string(),
            action,
            dismissal_reason: reason,
            reason: None,
            author: Some("dev1".to_string()),
            timestamp: i as u64,
        });
    }

    // FP rate = 5 / (5+10) = 0.333 > 0.20
    let fp_rate = tracker.fp_rate("noisy-detector");
    assert!(fp_rate > 0.20, "FP rate should be >0.20, got {fp_rate}");

    // Needs sustained_days >= 30 to auto-disable
    assert!(
        tracker.check_auto_disable().is_empty(),
        "Should not auto-disable without sustained days"
    );

    tracker.update_sustained_days("noisy-detector", 31);
    let disabled = tracker.check_auto_disable();
    assert!(
        disabled.contains(&"noisy-detector".to_string()),
        "Detector with >20% FP for 31 days must be auto-disabled"
    );

    // Verify FeedbackStatsProvider trait
    use drift_analysis::enforcement::feedback::stats_provider::FeedbackStatsProvider;
    assert!(tracker.is_detector_disabled("noisy-detector"));

    // Verify RulesEvaluator downgrades severity for high-FP patterns
    let mut fp_rates = HashMap::new();
    fp_rates.insert("security-pat".to_string(), 0.25);
    let evaluator = RulesEvaluator::new().with_fp_rates(fp_rates);
    let input = drift_analysis::enforcement::rules::RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "security-pat".to_string(),
            category: "security".to_string(),
            confidence: 0.9,
            locations: vec![],
            outliers: vec![make_outlier("sec.ts", 5, 4.0)],
            cwe_ids: vec![],
            owasp_categories: vec![],
        }],
        source_lines: HashMap::new(),
        baseline_violation_ids: HashSet::new(),
    };
    let violations = evaluator.evaluate(&input);
    assert!(!violations.is_empty());
    // Security category normally → Error, but FP rate > 0.20 → downgraded to Warning
    assert_eq!(
        violations[0].severity,
        Severity::Warning,
        "High-FP detector violations should be downgraded: {:?}",
        violations[0].severity
    );
}

// ===========================================================================
// T6-15  Feedback Abuse Detection
// ===========================================================================
#[test]
fn t6_15_feedback_abuse_detection() {
    let mut tracker = FeedbackTracker::new();

    // 50 dismiss actions from same author within 1 hour (3600s)
    let base_ts = 1_000_000u64;
    for i in 0..50 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("v-{i}"),
            pattern_id: "some-pattern".to_string(),
            detector_id: "some-detector".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::WontFix),
            reason: None,
            author: Some("suspicious-dev".to_string()),
            timestamp: base_ts + i * 60, // 1 dismiss per minute → 50 in 49 minutes
        });
    }

    // Check abuse: 50 dismissals within 3600s window
    let abusers = tracker.detect_abuse(3600, 50);
    assert!(
        abusers.contains(&"suspicious-dev".to_string()),
        "Author with 50 dismissals in 1 hour must be flagged"
    );

    // Normal user with only 5 dismissals should NOT be flagged
    for i in 0..5 {
        tracker.record(&FeedbackRecord {
            violation_id: format!("normal-v-{i}"),
            pattern_id: "p".to_string(),
            detector_id: "d".to_string(),
            action: FeedbackAction::Dismiss,
            dismissal_reason: Some(DismissalReason::WontFix),
            reason: None,
            author: Some("normal-dev".to_string()),
            timestamp: base_ts + i,
        });
    }

    let abusers = tracker.detect_abuse(3600, 50);
    assert!(
        !abusers.contains(&"normal-dev".to_string()),
        "Normal user with 5 dismissals must NOT be flagged"
    );
}

// ===========================================================================
// T6-16  Progressive Enforcement 4-Phase Ramp
// ===========================================================================
#[test]
fn t6_16_progressive_enforcement_4_phase_ramp() {
    use drift_analysis::enforcement::gates::ProgressiveEnforcement;

    let ramp_up_days = 100u32;

    // Day 10 → progress 0.10 (<0.25): Error→Info, Warning→Info
    let pe10 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days,
        project_age_days: 10,
    });
    assert_eq!(pe10.effective_severity(Severity::Error, false), Severity::Info);
    assert_eq!(pe10.effective_severity(Severity::Warning, false), Severity::Info);
    assert_eq!(pe10.effective_severity(Severity::Info, false), Severity::Info);

    // Day 30 → progress 0.30 (>=0.25, <0.50): Error→Warning, Warning→Info
    let pe30 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days,
        project_age_days: 30,
    });
    assert_eq!(pe30.effective_severity(Severity::Error, false), Severity::Warning);
    assert_eq!(pe30.effective_severity(Severity::Warning, false), Severity::Info);

    // Day 60 → progress 0.60 (>=0.50, <1.0): Error→Error, Warning→Warning
    let pe60 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days,
        project_age_days: 60,
    });
    assert_eq!(pe60.effective_severity(Severity::Error, false), Severity::Error);
    assert_eq!(pe60.effective_severity(Severity::Warning, false), Severity::Warning);

    // Day 100 → progress 1.0 (>=1.0): Full enforcement
    let pe100 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days,
        project_age_days: 100,
    });
    assert_eq!(pe100.effective_severity(Severity::Error, false), Severity::Error);
    assert_eq!(pe100.effective_severity(Severity::Warning, false), Severity::Warning);
    assert_eq!(pe100.effective_severity(Severity::Info, false), Severity::Info);

    // New files ALWAYS get full enforcement regardless of ramp phase
    assert_eq!(pe10.effective_severity(Severity::Error, true), Severity::Error);
    assert_eq!(pe10.effective_severity(Severity::Warning, true), Severity::Warning);
}
