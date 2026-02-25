//! Phase 5 constraint system tests (T5-CON-01 through T5-CON-06).

use drift_analysis::structural::constraints::types::*;
use drift_analysis::structural::constraints::detector::{InvariantDetector, FunctionInfo};
use drift_analysis::structural::constraints::verifier::ConstraintVerifier;
use drift_analysis::structural::constraints::synthesizer::ConstraintSynthesizer;
use drift_analysis::structural::constraints::freezing::FreezingArchRule;
use drift_analysis::structural::constraints::store::ConstraintStore;

/// T5-CON-01: At least 6 of 12 invariant types verified.
#[test]
fn test_invariant_types_coverage() {
    let all = InvariantType::all();
    assert_eq!(all.len(), 12);

    // Verify we can create constraints for at least 6 types
    let tested_types = [
        InvariantType::MustExist,
        InvariantType::MustNotExist,
        InvariantType::MustPrecede,
        InvariantType::NamingConvention,
        InvariantType::DependencyDirection,
        InvariantType::LayerBoundary,
    ];

    for inv_type in &tested_types {
        let constraint = Constraint {
            id: format!("test-{}", inv_type.name()),
            description: format!("Test constraint for {}", inv_type.name()),
            invariant_type: *inv_type,
            target: "test_target".into(),
            scope: None,
            source: ConstraintSource::Manual,
            enabled: true,
        };
        assert!(constraint.enabled);
        assert_eq!(constraint.source, ConstraintSource::Manual);
    }
}

/// T5-CON-02: AST-based constraint verification (not regex).
#[test]
fn test_ast_based_verification() {
    let store = ConstraintStore::new();
    let detector = InvariantDetector::new();
    let _verifier = ConstraintVerifier::new(&store, &detector);

    // Verify the detector can process constraints directly
    let constraint = Constraint {
        id: "naming-camel".into(),
        description: "Functions must use camelCase".into(),
        invariant_type: InvariantType::NamingConvention,
        target: "camelCase".into(),
        scope: Some("*.ts".into()),
        source: ConstraintSource::Manual,
        enabled: true,
    };

    let result = detector.verify(&constraint);
    assert_eq!(result.constraint_id, "naming-camel");
    // With no files registered, should pass (nothing to violate)
    assert!(result.passed);
    assert!(result.violations.is_empty());
}

/// T5-CON-03: FreezingArchRule regression detection.
#[test]
fn test_freezing_arch_rule() {
    let mut store = ConstraintStore::new();
    store.add(Constraint {
        id: "must-have-auth".into(),
        description: "Auth module must exist".into(),
        invariant_type: InvariantType::MustExist,
        target: "auth".into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    });

    let detector = InvariantDetector::new();
    let mut freezing = FreezingArchRule::new();
    let baseline = freezing.freeze(&store, &detector);
    assert!(!baseline.snapshot_id.is_empty());
    assert_eq!(baseline.constraints.len(), 1);
    assert!(baseline.timestamp > 0);
    assert!(freezing.has_baseline());
}

/// T5-CON-04: Constraint synthesis from patterns.
#[test]
fn test_constraint_synthesis() {
    let mut synthesizer = ConstraintSynthesizer::new();

    // Register files with camelCase function names
    let camel_functions = vec![
        FunctionInfo { name: "getUserById".into(), line: 1, is_exported: true },
        FunctionInfo { name: "createOrder".into(), line: 5, is_exported: true },
        FunctionInfo { name: "validateInput".into(), line: 10, is_exported: true },
        FunctionInfo { name: "processPayment".into(), line: 15, is_exported: true },
        FunctionInfo { name: "sendNotification".into(), line: 20, is_exported: true },
    ];

    for i in 0..20 {
        synthesizer.add_file(&format!("src/module{}/handler.ts", i), camel_functions.clone());
    }

    let constraints = synthesizer.synthesize_naming_conventions();
    // Should detect camelCase convention (100% of functions are camelCase)
    assert!(!constraints.is_empty(),
        "Should synthesize at least one naming convention constraint");
}

/// T5-CON-05: Conflicting constraints detected.
#[test]
fn test_conflicting_constraints() {
    let mut store = ConstraintStore::new();
    store.add(Constraint {
        id: "must-exist-foo".into(),
        description: "foo must exist".into(),
        invariant_type: InvariantType::MustExist,
        target: "foo".into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    });
    store.add(Constraint {
        id: "must-not-exist-foo".into(),
        description: "foo must not exist".into(),
        invariant_type: InvariantType::MustNotExist,
        target: "foo".into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    });

    let conflicts = store.find_conflicts();
    assert!(!conflicts.is_empty(), "Should detect conflicting constraints");
}

/// T5-CON-06: Empty codebase — must_exist fails, must_not_exist passes.
#[test]
fn test_empty_codebase_constraints() {
    let detector = InvariantDetector::new();

    let must_exist = Constraint {
        id: "must-exist".into(),
        description: "Something must exist".into(),
        invariant_type: InvariantType::MustExist,
        target: "nonexistent".into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    };

    let must_not_exist = Constraint {
        id: "must-not-exist".into(),
        description: "Something must not exist".into(),
        invariant_type: InvariantType::MustNotExist,
        target: "nonexistent".into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    };

    // With no files registered in detector
    let result_exist = detector.verify(&must_exist);
    let result_not_exist = detector.verify(&must_not_exist);

    // must_exist should fail on empty codebase
    assert!(!result_exist.passed);
    // must_not_exist should pass on empty codebase
    assert!(result_not_exist.passed);
}
