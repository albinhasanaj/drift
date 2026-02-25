//! Production stress tests for the constraints module.
//! Targets: all 12 invariant types, edge cases in verification, synthesis, freezing.

use drift_analysis::structural::constraints::types::*;
use drift_analysis::structural::constraints::detector::{FunctionInfo, InvariantDetector};
use drift_analysis::structural::constraints::store::ConstraintStore;
use drift_analysis::structural::constraints::verifier::ConstraintVerifier;
use drift_analysis::structural::constraints::synthesizer::ConstraintSynthesizer;
use drift_analysis::structural::constraints::freezing::FreezingArchRule;

// ─── Helpers ────────────────────────────────────────────────────────

fn constraint(id: &str, inv_type: InvariantType, target: &str) -> Constraint {
    Constraint {
        id: id.into(),
        description: format!("Test: {}", id),
        invariant_type: inv_type,
        target: target.into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    }
}

fn scoped_constraint(
    id: &str,
    inv_type: InvariantType,
    target: &str,
    scope: &str,
) -> Constraint {
    Constraint {
        id: id.into(),
        description: format!("Test: {}", id),
        invariant_type: inv_type,
        target: target.into(),
        scope: Some(scope.into()),
        source: ConstraintSource::Manual,
        enabled: true,
    }
}

fn detector_with_files() -> InvariantDetector {
    let mut d = InvariantDetector::new();
    d.add_file(
        "src/auth/login.ts",
        vec![
            FunctionInfo { name: "validateInput".into(), line: 5, is_exported: true },
            FunctionInfo { name: "authenticate".into(), line: 15, is_exported: true },
            FunctionInfo { name: "createSession".into(), line: 30, is_exported: false },
        ],
        vec!["src/db/users.ts".to_string()],
        100,
    );
    d.add_file(
        "src/db/users.ts",
        vec![
            FunctionInfo { name: "findUser".into(), line: 1, is_exported: true },
            FunctionInfo { name: "saveUser".into(), line: 20, is_exported: true },
        ],
        vec![],
        50,
    );
    d.add_file(
        "src/ui/dashboard.ts",
        vec![
            FunctionInfo { name: "renderDashboard".into(), line: 1, is_exported: true },
        ],
        vec!["src/db/users.ts".to_string()],
        200,
    );
    d
}

// ─── MustExist / MustNotExist stress ────────────────────────────────

#[test]
fn stress_must_exist_found() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::MustExist, "authenticate"));
    assert!(r.passed, "authenticate exists and should pass");
}

#[test]
fn stress_must_exist_not_found() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::MustExist, "nonexistent"));
    assert!(!r.passed);
    assert_eq!(r.violations.len(), 1);
}

#[test]
fn stress_must_not_exist_found() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::MustNotExist, "authenticate"));
    assert!(!r.passed);
    assert!(!r.violations.is_empty());
}

#[test]
fn stress_must_not_exist_not_found() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::MustNotExist, "nonexistent"));
    assert!(r.passed);
}

#[test]
fn stress_must_exist_empty_detector() {
    let d = InvariantDetector::new();
    let r = d.verify(&constraint("c1", InvariantType::MustExist, "anything"));
    assert!(!r.passed, "Empty detector → MustExist should fail");
}

// ─── MustPrecede / MustFollow stress ────────────────────────────────

#[test]
fn stress_must_precede_correct_order() {
    let d = detector_with_files();
    // validateInput (line 5) before authenticate (line 15) → should pass
    let r = d.verify(&constraint("c1", InvariantType::MustPrecede, "validateInput:authenticate"));
    assert!(r.passed);
}

#[test]
fn stress_must_precede_wrong_order() {
    let d = detector_with_files();
    // authenticate (line 15) before validateInput (line 5) → should fail
    let r = d.verify(&constraint("c1", InvariantType::MustPrecede, "authenticate:validateInput"));
    assert!(!r.passed);
}

#[test]
fn stress_must_precede_invalid_format() {
    let d = detector_with_files();
    // No colon separator → should pass (invalid format = no violations)
    let r = d.verify(&constraint("c1", InvariantType::MustPrecede, "noColonHere"));
    assert!(r.passed);
}

#[test]
fn stress_must_follow_correct_order() {
    let d = detector_with_files();
    // createSession (line 30) after authenticate (line 15) → should pass
    let r = d.verify(&constraint("c1", InvariantType::MustFollow, "createSession:authenticate"));
    assert!(r.passed);
}

#[test]
fn stress_must_follow_wrong_order() {
    let d = detector_with_files();
    // validateInput (line 5) after authenticate (line 15) → should fail
    let r = d.verify(&constraint("c1", InvariantType::MustFollow, "validateInput:authenticate"));
    assert!(!r.passed);
}

// ─── MustColocate / MustSeparate stress ─────────────────────────────

#[test]
fn stress_must_colocate_same_file() {
    let d = detector_with_files();
    // validateInput and authenticate are both in src/auth/login.ts
    let r = d.verify(&constraint("c1", InvariantType::MustColocate, "validateInput:authenticate"));
    assert!(r.passed);
}

#[test]
fn stress_must_colocate_different_files() {
    let d = detector_with_files();
    // authenticate (auth/login.ts) and findUser (db/users.ts)
    let r = d.verify(&constraint("c1", InvariantType::MustColocate, "authenticate:findUser"));
    assert!(!r.passed);
}

#[test]
fn stress_must_separate_different_files() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::MustSeparate, "authenticate:findUser"));
    assert!(r.passed);
}

#[test]
fn stress_must_separate_same_file() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::MustSeparate, "validateInput:authenticate"));
    assert!(!r.passed);
}

#[test]
fn stress_must_colocate_nonexistent_symbol() {
    let d = detector_with_files();
    // One symbol doesn't exist → should pass (can't violate)
    let r = d.verify(&constraint("c1", InvariantType::MustColocate, "authenticate:nonexistent"));
    assert!(r.passed);
}

// ─── NamingConvention stress ────────────────────────────────────────

#[test]
fn stress_naming_convention_camel_case() {
    let d = detector_with_files();
    // All functions in auth/login.ts are camelCase
    let r = d.verify(&scoped_constraint(
        "c1",
        InvariantType::NamingConvention,
        "camelCase",
        "auth",
    ));
    assert!(r.passed, "camelCase functions should pass camelCase check");
}

#[test]
fn stress_naming_convention_snake_case_fails() {
    let d = detector_with_files();
    // camelCase functions should fail snake_case check
    let r = d.verify(&scoped_constraint(
        "c1",
        InvariantType::NamingConvention,
        "snake_case",
        "auth",
    ));
    assert!(!r.passed, "camelCase functions should fail snake_case check");
}

#[test]
fn stress_naming_convention_unknown_convention() {
    let d = detector_with_files();
    // Unknown convention → should pass (permissive)
    let r = d.verify(&constraint("c1", InvariantType::NamingConvention, "kebab-case"));
    assert!(r.passed);
}

// ─── DependencyDirection stress ─────────────────────────────────────

#[test]
fn stress_dependency_direction_allowed() {
    let d = detector_with_files();
    // auth → db is allowed (auth imports db)
    let r = d.verify(&constraint("c1", InvariantType::DependencyDirection, "src/auth->src/db"));
    // This checks that db does NOT import auth (reverse direction)
    assert!(r.passed, "db does not import auth → should pass");
}

#[test]
fn stress_dependency_direction_violated() {
    let d = detector_with_files();
    // ui → db is the actual direction, so db->ui should be the allowed direction
    // But ui imports db, so checking "src/db->src/ui" means ui should not import db
    let r = d.verify(&constraint("c1", InvariantType::DependencyDirection, "src/db->src/ui"));
    // ui/dashboard.ts imports src/db/users.ts → violation
    assert!(!r.passed, "UI importing DB when only DB→UI is allowed should fail");
}

// ─── LayerBoundary stress ───────────────────────────────────────────

#[test]
fn stress_layer_boundary_violated() {
    let d = detector_with_files();
    // ui must not import from db
    let r = d.verify(&constraint("c1", InvariantType::LayerBoundary, "ui!->db"));
    assert!(!r.passed, "UI importing DB should violate layer boundary");
}

#[test]
fn stress_layer_boundary_clean() {
    let d = detector_with_files();
    // db must not import from ui — db has no imports → clean
    let r = d.verify(&constraint("c1", InvariantType::LayerBoundary, "db!->ui"));
    assert!(r.passed);
}

// ─── SizeLimit stress ───────────────────────────────────────────────

#[test]
fn stress_size_limit_exceeded() {
    let d = detector_with_files();
    // dashboard.ts has 200 lines, limit is 150
    let r = d.verify(&scoped_constraint("c1", InvariantType::SizeLimit, "150", "dashboard"));
    assert!(!r.passed);
}

#[test]
fn stress_size_limit_within() {
    let d = detector_with_files();
    // users.ts has 50 lines, limit is 500
    let r = d.verify(&scoped_constraint("c1", InvariantType::SizeLimit, "500", "users"));
    assert!(r.passed);
}

#[test]
fn stress_size_limit_invalid_target() {
    let d = detector_with_files();
    // Non-numeric target → defaults to 500
    let r = d.verify(&constraint("c1", InvariantType::SizeLimit, "not_a_number"));
    assert!(r.passed, "Invalid limit should default to 500");
}

// ─── ComplexityLimit stress ─────────────────────────────────────────

#[test]
fn stress_complexity_limit_exceeded() {
    let d = detector_with_files();
    // auth/login.ts has 3 functions, limit is 2
    let r = d.verify(&scoped_constraint("c1", InvariantType::ComplexityLimit, "2", "auth"));
    assert!(!r.passed);
}

#[test]
fn stress_complexity_limit_within() {
    let d = detector_with_files();
    // dashboard.ts has 1 function, limit is 5
    let r = d.verify(&scoped_constraint("c1", InvariantType::ComplexityLimit, "5", "dashboard"));
    assert!(r.passed);
}

// ─── DataFlow (deferred) ────────────────────────────────────────────

#[test]
fn stress_dataflow_always_passes() {
    let d = detector_with_files();
    let r = d.verify(&constraint("c1", InvariantType::DataFlow, "anything"));
    assert!(r.passed, "DataFlow is deferred to Phase 6 → should always pass");
}

// ─── Disabled constraint stress ─────────────────────────────────────

#[test]
fn stress_disabled_constraint_always_passes() {
    let d = detector_with_files();
    let mut c = constraint("c1", InvariantType::MustExist, "nonexistent");
    c.enabled = false;
    let r = d.verify(&c);
    assert!(r.passed, "Disabled constraint should always pass");
}

// ─── Store stress ───────────────────────────────────────────────────

#[test]
fn stress_store_empty() {
    let store = ConstraintStore::new();
    assert!(store.all().is_empty());
    assert!(store.enabled().is_empty());
}

#[test]
fn stress_store_enabled_filter() {
    let mut store = ConstraintStore::new();
    store.add(constraint("c1", InvariantType::MustExist, "a"));
    let mut disabled = constraint("c2", InvariantType::MustExist, "b");
    disabled.enabled = false;
    store.add(disabled);
    assert_eq!(store.all().len(), 2);
    assert_eq!(store.enabled().len(), 1);
}

#[test]
fn stress_store_conflict_detection() {
    let mut store = ConstraintStore::new();
    store.add(constraint("c1", InvariantType::MustExist, "foo"));
    store.add(constraint("c2", InvariantType::MustNotExist, "foo"));
    let conflicts = store.find_conflicts();
    assert!(!conflicts.is_empty(), "MustExist + MustNotExist on same target = conflict");
}

#[test]
fn stress_store_no_false_conflicts() {
    let mut store = ConstraintStore::new();
    store.add(constraint("c1", InvariantType::MustExist, "foo"));
    store.add(constraint("c2", InvariantType::MustExist, "bar"));
    let conflicts = store.find_conflicts();
    assert!(conflicts.is_empty(), "Different targets should not conflict");
}

// ─── Verifier stress ────────────────────────────────────────────────

#[test]
fn stress_verifier_empty_store() {
    let store = ConstraintStore::new();
    let detector = InvariantDetector::new();
    let verifier = ConstraintVerifier::new(&store, &detector);
    let results = verifier.verify_all().unwrap();
    assert!(results.is_empty());
}

#[test]
fn stress_verifier_summary() {
    let mut store = ConstraintStore::new();
    store.add(constraint("c1", InvariantType::MustExist, "authenticate"));
    store.add(constraint("c2", InvariantType::MustExist, "nonexistent"));
    let detector = detector_with_files();
    let verifier = ConstraintVerifier::new(&store, &detector);
    let (passed, failed) = verifier.summary().unwrap();
    assert_eq!(passed, 1);
    assert_eq!(failed, 1);
}

#[test]
fn stress_verifier_verify_one_not_found() {
    let store = ConstraintStore::new();
    let detector = InvariantDetector::new();
    let verifier = ConstraintVerifier::new(&store, &detector);
    let result = verifier.verify_one("nonexistent");
    assert!(result.is_err(), "Verifying nonexistent constraint should error");
}

// ─── Synthesizer stress ─────────────────────────────────────────────

#[test]
fn stress_synthesizer_empty() {
    let s = ConstraintSynthesizer::new();
    let constraints = s.synthesize_naming_conventions();
    assert!(constraints.is_empty(), "No files → no synthesized constraints");
}

#[test]
fn stress_synthesizer_mixed_conventions() {
    let mut s = ConstraintSynthesizer::new();
    // Mix of camelCase and snake_case — should not synthesize a strong convention
    let camel_fns = vec![
        FunctionInfo { name: "getUserById".into(), line: 1, is_exported: true },
        FunctionInfo { name: "createOrder".into(), line: 5, is_exported: true },
    ];
    let snake_fns = vec![
        FunctionInfo { name: "get_user_by_id".into(), line: 1, is_exported: true },
        FunctionInfo { name: "create_order".into(), line: 5, is_exported: true },
    ];
    for i in 0..10 {
        s.add_file(&format!("src/camel{}.ts", i), camel_fns.clone());
        s.add_file(&format!("src/snake{}.py", i), snake_fns.clone());
    }
    let constraints = s.synthesize_naming_conventions();
    // With 50/50 split, synthesizer may or may not produce a constraint
    // Just verify it doesn't panic
    let _ = constraints;
}

#[test]
fn stress_synthesizer_strong_convention() {
    let mut s = ConstraintSynthesizer::new();
    let camel_fns = vec![
        FunctionInfo { name: "getUserById".into(), line: 1, is_exported: true },
        FunctionInfo { name: "createOrder".into(), line: 5, is_exported: true },
        FunctionInfo { name: "validateInput".into(), line: 10, is_exported: true },
    ];
    for i in 0..30 {
        s.add_file(&format!("src/module{}/handler.ts", i), camel_fns.clone());
    }
    let constraints = s.synthesize_naming_conventions();
    assert!(
        !constraints.is_empty(),
        "100% camelCase across 30 files should synthesize a convention"
    );
}

// ─── Freezing stress ────────────────────────────────────────────────

#[test]
fn stress_freezing_no_baseline() {
    let freezing = FreezingArchRule::new();
    assert!(!freezing.has_baseline());
}

#[test]
fn stress_freezing_baseline_and_regression() {
    let mut store = ConstraintStore::new();
    store.add(constraint("c1", InvariantType::MustExist, "authenticate"));
    let detector = detector_with_files();
    let mut freezing = FreezingArchRule::new();

    let baseline = freezing.freeze(&store, &detector);
    assert!(freezing.has_baseline());
    assert!(!baseline.snapshot_id.is_empty());
    assert!(baseline.timestamp > 0);

    // Check regressions against same state → no regressions
    let regressions = freezing.check_regressions(&detector);
    assert!(
        regressions.is_empty(),
        "Same state should have no regressions"
    );
}

// ─── InvariantType coverage ─────────────────────────────────────────

#[test]
fn stress_invariant_type_all_12() {
    assert_eq!(InvariantType::all().len(), 12);
}

#[test]
fn stress_invariant_type_names_unique() {
    let names: Vec<&str> = InvariantType::all().iter().map(|t| t.name()).collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(names.len(), unique.len(), "InvariantType names must be unique");
}

#[test]
fn stress_invariant_type_display() {
    for t in InvariantType::all() {
        let display = format!("{}", t);
        assert!(!display.is_empty(), "{:?} has empty Display", t);
    }
}
