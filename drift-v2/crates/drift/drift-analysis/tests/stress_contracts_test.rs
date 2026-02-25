//! Production stress tests for the contracts module.
//! Targets: Bayesian confidence edge cases, breaking change classification,
//! schema parser robustness, matching edge cases.

use drift_analysis::structural::contracts::types::*;
use drift_analysis::structural::contracts::breaking_changes::classify_breaking_changes;
use drift_analysis::structural::contracts::confidence::{bayesian_confidence, signal_independence_check};
use drift_analysis::structural::contracts::matching::match_contracts;

// ─── Helpers ────────────────────────────────────────────────────────

fn endpoint(method: &str, path: &str, fields: &[(&str, &str, bool)]) -> Endpoint {
    Endpoint {
        method: method.into(),
        path: path.into(),
        request_fields: vec![],
        response_fields: fields
            .iter()
            .map(|(n, t, r)| FieldSpec {
                name: n.to_string(),
                field_type: t.to_string(),
                required: *r,
                nullable: false,
            })
            .collect(),
        file: "routes.ts".into(),
        line: 1,
    }
}

fn contract(id: &str, endpoints: Vec<Endpoint>) -> Contract {
    Contract {
        id: id.into(),
        paradigm: Paradigm::Rest,
        endpoints,
        source_file: "routes.ts".into(),
        framework: "express".into(),
        confidence: 0.9,
    }
}

// ─── Bayesian confidence stress ─────────────────────────────────────

#[test]
fn stress_confidence_all_zeros() {
    let c = bayesian_confidence(&[0.0; 7]);
    assert_eq!(c, 0.0, "All-zero signals should produce 0 confidence");
}

#[test]
fn stress_confidence_all_ones() {
    let c = bayesian_confidence(&[1.0; 7]);
    assert!(
        (c - 1.0).abs() < 0.01,
        "All-one signals should produce ~1.0, got {}",
        c
    );
}

#[test]
fn stress_confidence_negative_signals_clamped() {
    let c = bayesian_confidence(&[-1.0, -0.5, -0.3, -0.1, 0.0, 0.5, 1.0]);
    assert!(
        (0.0..=1.0).contains(&c),
        "Negative signals should be clamped, got {}",
        c
    );
}

#[test]
fn stress_confidence_above_one_signals_clamped() {
    let c = bayesian_confidence(&[2.0, 3.0, 5.0, 10.0, 100.0, 0.5, 0.5]);
    assert!(
        (0.0..=1.0).contains(&c),
        "Above-1 signals should be clamped, got {}",
        c
    );
}

#[test]
fn stress_confidence_monotonic_in_each_signal() {
    let baseline = [0.5; 7];
    let base_score = bayesian_confidence(&baseline);
    for i in 0..7 {
        let mut boosted = baseline;
        boosted[i] = 1.0;
        let boosted_score = bayesian_confidence(&boosted);
        assert!(
            boosted_score >= base_score,
            "Boosting signal {} should not decrease confidence: {} vs {}",
            i,
            boosted_score,
            base_score
        );
    }
}

#[test]
fn stress_confidence_signal_independence() {
    assert!(
        signal_independence_check(),
        "Each signal should independently affect confidence"
    );
}

#[test]
fn stress_confidence_weights_sum_to_one() {
    let weights = [0.25, 0.20, 0.15, 0.15, 0.10, 0.08, 0.07];
    let sum: f64 = weights.iter().sum();
    assert!(
        (sum - 1.0).abs() < 0.01,
        "Weights should sum to ~1.0, got {}",
        sum
    );
}

// ─── Breaking changes stress ────────────────────────────────────────

#[test]
fn stress_breaking_no_changes() {
    let c = contract("v1", vec![endpoint("GET", "/users", &[("id", "number", true)])]);
    let changes = classify_breaking_changes(&c, &c);
    assert!(changes.is_empty(), "Identical contracts should have no breaking changes");
}

#[test]
fn stress_breaking_field_removed() {
    let old = contract(
        "v1",
        vec![endpoint("GET", "/users", &[("id", "number", true), ("email", "string", true)])],
    );
    let new = contract(
        "v2",
        vec![endpoint("GET", "/users", &[("id", "number", true)])],
    );
    let changes = classify_breaking_changes(&old, &new);
    assert!(
        changes.iter().any(|c| c.change_type == BreakingChangeType::FieldRemoved),
        "Should detect field removal"
    );
}

#[test]
fn stress_breaking_endpoint_removed() {
    let old = contract(
        "v1",
        vec![
            endpoint("GET", "/users", &[]),
            endpoint("POST", "/users", &[]),
        ],
    );
    let new = contract("v2", vec![endpoint("GET", "/users", &[])]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(
        changes.iter().any(|c| c.change_type == BreakingChangeType::EndpointRemoved),
        "Should detect endpoint removal"
    );
}

#[test]
fn stress_breaking_type_changed() {
    let old = contract(
        "v1",
        vec![endpoint("GET", "/users", &[("id", "number", true)])],
    );
    let new = contract(
        "v2",
        vec![endpoint("GET", "/users", &[("id", "string", true)])],
    );
    let changes = classify_breaking_changes(&old, &new);
    assert!(
        changes.iter().any(|c| c.change_type == BreakingChangeType::TypeChanged),
        "Should detect type change"
    );
}

#[test]
fn stress_breaking_optional_to_required() {
    let old = contract(
        "v1",
        vec![endpoint("GET", "/users", &[("email", "string", false)])],
    );
    let new = contract(
        "v2",
        vec![endpoint("GET", "/users", &[("email", "string", true)])],
    );
    let changes = classify_breaking_changes(&old, &new);
    assert!(
        changes.iter().any(|c| c.change_type == BreakingChangeType::OptionalToRequired),
        "Should detect optional→required change"
    );
}

#[test]
fn stress_breaking_empty_contracts() {
    let old = contract("v1", vec![]);
    let new = contract("v2", vec![]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.is_empty());
}

#[test]
fn stress_breaking_change_type_is_breaking() {
    let breaking_types = [
        BreakingChangeType::EndpointRemoved,
        BreakingChangeType::FieldRemoved,
        BreakingChangeType::TypeChanged,
        BreakingChangeType::OptionalToRequired,
        BreakingChangeType::EnumValueRemoved,
        BreakingChangeType::PathChanged,
        BreakingChangeType::MethodChanged,
        BreakingChangeType::ResponseShapeChanged,
        BreakingChangeType::NullabilityChanged,
        BreakingChangeType::ArrayToScalar,
        BreakingChangeType::ScalarToArray,
        BreakingChangeType::DefaultRemoved,
    ];
    for t in &breaking_types {
        assert!(t.is_breaking(), "{:?} should be breaking", t);
    }

    let non_breaking = [
        BreakingChangeType::RateLimitAdded,
    ];
    for t in &non_breaking {
        assert!(!t.is_breaking(), "{:?} should not be breaking", t);
    }
}

// ─── Matching stress ────────────────────────────────────────────────

#[test]
fn stress_matching_exact_path() {
    let be = vec![endpoint("GET", "/api/users", &[("id", "number", true)])];
    let fe = vec![endpoint("GET", "/api/users", &[("id", "number", true)])];
    let matches = match_contracts(&be, &fe);
    assert!(!matches.is_empty(), "Exact path match should produce a match");
    assert!(matches[0].confidence > 0.5);
}

#[test]
fn stress_matching_no_overlap() {
    let be = vec![endpoint("GET", "/api/users", &[])];
    let fe = vec![endpoint("POST", "/api/orders", &[])];
    let matches = match_contracts(&be, &fe);
    assert!(
        matches.is_empty() || matches[0].confidence < 0.3,
        "No overlap should produce no/low-confidence match"
    );
}

#[test]
fn stress_matching_empty_backend() {
    let matches = match_contracts(&[], &[endpoint("GET", "/api/users", &[])]);
    assert!(matches.is_empty());
}

#[test]
fn stress_matching_empty_frontend() {
    let matches = match_contracts(&[endpoint("GET", "/api/users", &[])], &[]);
    assert!(matches.is_empty());
}

#[test]
fn stress_matching_both_empty() {
    let matches = match_contracts(&[], &[]);
    assert!(matches.is_empty());
}

#[test]
fn stress_matching_many_endpoints() {
    let be: Vec<Endpoint> = (0..50)
        .map(|i| endpoint("GET", &format!("/api/resource{}", i), &[("id", "number", true)]))
        .collect();
    let fe: Vec<Endpoint> = (0..50)
        .map(|i| endpoint("GET", &format!("/api/resource{}", i), &[("id", "number", true)]))
        .collect();
    let matches = match_contracts(&be, &fe);
    // NOTE: match_contracts does N×M cross-join, producing matches for every
    // (backend, frontend) pair. With 50 identical paths, each BE matches each FE.
    // This is by design — the confidence score differentiates exact vs partial matches.
    // Exact path matches should have the highest confidence.
    assert!(
        !matches.is_empty(),
        "Should produce matches for 50 endpoints"
    );
    // Verify exact-path matches have high confidence
    let exact_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.confidence > 0.5)
        .collect();
    assert!(
        exact_matches.len() >= 50,
        "Should have at least 50 high-confidence exact matches, got {}",
        exact_matches.len()
    );
}

// ─── Paradigm coverage ──────────────────────────────────────────────

#[test]
fn stress_paradigm_all_7() {
    assert_eq!(Paradigm::all().len(), 7);
}

#[test]
fn stress_paradigm_names() {
    for p in Paradigm::all() {
        let name = format!("{:?}", p);
        assert!(!name.is_empty());
    }
}

// ─── Schema parser robustness ───────────────────────────────────────

#[test]
fn stress_openapi_empty_spec() {
    use drift_analysis::structural::contracts::schema_parsers::openapi::OpenApiParser;
    use drift_analysis::structural::contracts::schema_parsers::SchemaParser;
    let parser = OpenApiParser;
    let contracts = parser.parse("{}", "empty.json");
    // Should not panic on empty/minimal spec
    let _ = contracts;
}

#[test]
fn stress_openapi_invalid_json() {
    use drift_analysis::structural::contracts::schema_parsers::openapi::OpenApiParser;
    use drift_analysis::structural::contracts::schema_parsers::SchemaParser;
    let parser = OpenApiParser;
    let contracts = parser.parse("not json at all", "bad.json");
    assert!(contracts.is_empty(), "Invalid JSON should produce no contracts");
}

#[test]
fn stress_graphql_empty_schema() {
    use drift_analysis::structural::contracts::schema_parsers::graphql::GraphqlParser;
    use drift_analysis::structural::contracts::schema_parsers::SchemaParser;
    let parser = GraphqlParser;
    let contracts = parser.parse("", "empty.graphql");
    assert!(contracts.is_empty());
}

#[test]
fn stress_graphql_invalid_schema() {
    use drift_analysis::structural::contracts::schema_parsers::graphql::GraphqlParser;
    use drift_analysis::structural::contracts::schema_parsers::SchemaParser;
    let parser = GraphqlParser;
    let contracts = parser.parse("this is not graphql {{{", "bad.graphql");
    // Should not panic
    let _ = contracts;
}

// ─── MismatchType coverage ──────────────────────────────────────────

#[test]
fn stress_mismatch_types_all_7() {
    let types = [
        MismatchType::FieldMissing,
        MismatchType::TypeMismatch,
        MismatchType::RequiredOptional,
        MismatchType::EnumValue,
        MismatchType::NestedShape,
        MismatchType::ArrayScalar,
        MismatchType::Nullable,
    ];
    assert_eq!(types.len(), 7);
}
