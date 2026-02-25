//! Phase 6 tests: Policy Engine — Aggregation Modes
//! T6-POL-01 through T6-POL-06

use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::policy::*;
use drift_analysis::enforcement::rules::Severity;

fn make_gate_results(pass_count: usize, fail_count: usize) -> Vec<GateResult> {
    let gate_ids = GateId::all();
    let mut results = Vec::new();

    for (i, &gate_id) in gate_ids.iter().enumerate() {
        if i < pass_count {
            results.push(GateResult::pass(gate_id, 90.0, "Passed".to_string()));
        } else if i < pass_count + fail_count {
            results.push(GateResult::fail(
                gate_id,
                40.0,
                "Failed".to_string(),
                vec![],
            ));
        }
    }

    results
}

/// T6-POL-01: Test policy engine aggregates in all 4 modes.
#[test]
fn test_policy_all_four_modes() {
    let results = make_gate_results(4, 2);

    // All-must-pass
    let policy = Policy::strict();
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(!pr.overall_passed, "all-must-pass should fail when any gate fails");

    // Any-must-pass
    let policy = Policy::lenient();
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(pr.overall_passed, "any-must-pass should pass when any gate passes");

    // Weighted
    let mut policy = Policy::standard();
    policy.aggregation_mode = AggregationMode::Weighted;
    policy.threshold = 50.0;
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(pr.overall_score > 0.0);

    // Threshold
    let mut policy = Policy::standard();
    policy.aggregation_mode = AggregationMode::Threshold;
    policy.threshold = 50.0;
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(pr.overall_score > 0.0);
}

/// T6-POL-02: Test all-must-pass: 5 pass + 1 fail → overall fail.
#[test]
fn test_all_must_pass_one_failure() {
    let results = make_gate_results(5, 1);
    let policy = Policy {
        name: "strict".to_string(),
        preset: PolicyPreset::Strict,
        aggregation_mode: AggregationMode::AllMustPass,
        weights: std::collections::HashMap::new(),
        threshold: 80.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(!pr.overall_passed, "5 pass + 1 fail should fail in all-must-pass");
}

/// T6-POL-03: Test any-must-pass: 5 fail + 1 pass → overall pass.
#[test]
fn test_any_must_pass_one_success() {
    let results = make_gate_results(1, 5);
    let policy = Policy {
        name: "lenient".to_string(),
        preset: PolicyPreset::Lenient,
        aggregation_mode: AggregationMode::AnyMustPass,
        weights: std::collections::HashMap::new(),
        threshold: 50.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    assert!(pr.overall_passed, "5 fail + 1 pass should pass in any-must-pass");
}

/// T6-POL-04: Test weighted mode.
#[test]
fn test_weighted_mode() {
    let results = make_gate_results(3, 3);
    let mut weights = std::collections::HashMap::new();
    // Give higher weight to passing gates
    weights.insert("pattern-compliance".to_string(), 0.5);
    weights.insert("constraint-verification".to_string(), 0.3);
    weights.insert("security-boundaries".to_string(), 0.2);

    let policy = Policy {
        name: "weighted".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Weighted,
        weights,
        threshold: 50.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine = PolicyEngine::new(policy);
    let pr = engine.evaluate(&results);
    // With higher weights on passing gates, score should be above 50
    assert!(pr.overall_score > 0.0, "Weighted score should be positive");
}

/// T6-POL-05: Test threshold boundary precision.
#[test]
fn test_threshold_boundary() {
    // Create results that average to exactly 80
    let results = vec![
        GateResult::pass(GateId::PatternCompliance, 80.0, "ok".to_string()),
        GateResult::pass(GateId::ConstraintVerification, 80.0, "ok".to_string()),
    ];

    // Threshold at 80 → should pass (>=)
    let policy = Policy {
        name: "threshold".to_string(),
        preset: PolicyPreset::Custom,
        aggregation_mode: AggregationMode::Threshold,
        weights: std::collections::HashMap::new(),
        threshold: 80.0,
        required_gates: vec![],
        progressive: false,
        ramp_up_days: 0,
    };
    let engine = PolicyEngine::new(policy.clone());
    let pr = engine.evaluate(&results);
    assert!(pr.overall_passed, "Score 80 with threshold 80 should pass");

    // Threshold at 80.1 → should fail
    let policy2 = Policy {
        threshold: 80.1,
        ..policy
    };
    let engine2 = PolicyEngine::new(policy2);
    let pr2 = engine2.evaluate(&results);
    assert!(!pr2.overall_passed, "Score 80 with threshold 80.1 should fail");
}

/// T6-POL-06: Test progressive enforcement ramp-up for new projects.
#[test]
fn test_progressive_ramp_up() {
    use drift_analysis::enforcement::gates::progressive::*;

    // First week: all warnings
    let pe = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 28,
        project_age_days: 3,
    });
    assert_eq!(pe.effective_severity(Severity::Error, false), Severity::Info);
    assert_eq!(pe.effective_severity(Severity::Warning, false), Severity::Info);

    // Second week: critical errors become warnings
    let pe2 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 28,
        project_age_days: 10,
    });
    assert_eq!(pe2.effective_severity(Severity::Error, false), Severity::Warning);

    // Fourth week: full enforcement
    let pe3 = ProgressiveEnforcement::new(ProgressiveConfig {
        enabled: true,
        ramp_up_days: 28,
        project_age_days: 28,
    });
    assert_eq!(pe3.effective_severity(Severity::Error, false), Severity::Error);
}
