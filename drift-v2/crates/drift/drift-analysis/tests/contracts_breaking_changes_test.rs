//! Phase D breaking change detection hardening tests (CET-BC-*).

use drift_analysis::structural::contracts::types::*;
use drift_analysis::structural::contracts::breaking_changes::classify_breaking_changes;

fn make_contract(id: &str, endpoints: Vec<Endpoint>) -> Contract {
    Contract {
        id: id.into(),
        paradigm: Paradigm::Rest,
        endpoints,
        source_file: "test.ts".into(),
        framework: "express".into(),
        confidence: 0.9,
    }
}

fn field(name: &str, ft: &str, required: bool, nullable: bool) -> FieldSpec {
    FieldSpec { name: name.into(), field_type: ft.into(), required, nullable }
}

fn ep(method: &str, path: &str, req: Vec<FieldSpec>, resp: Vec<FieldSpec>) -> Endpoint {
    Endpoint {
        method: method.into(), path: path.into(),
        request_fields: req, response_fields: resp,
        file: "test.ts".into(), line: 1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Existing 5 types (regression)
// ═══════════════════════════════════════════════════════════════════════════

/// CET-BC-01: EndpointRemoved detection.
#[test]
fn test_endpoint_removed() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![]),
        ep("DELETE", "/users/:id", vec![], vec![]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::EndpointRemoved));
}

/// CET-BC-02: FieldRemoved from response.
#[test]
fn test_field_removed_response() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("id", "integer", true, false),
            field("email", "string", true, false),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("id", "integer", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::FieldRemoved
        && c.field.as_deref() == Some("email")));
}

/// CET-BC-03: TypeChanged.
#[test]
fn test_type_changed() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("age", "integer", true, false),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("age", "string", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::TypeChanged
        && c.field.as_deref() == Some("age")));
}

/// CET-BC-04: OptionalToRequired.
#[test]
fn test_optional_to_required() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("nickname", "string", false, false),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("nickname", "string", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::OptionalToRequired));
}

/// CET-BC-05: RequiredAdded to request.
#[test]
fn test_required_added() {
    let old = make_contract("old", vec![
        ep("POST", "/users", vec![
            field("name", "string", true, false),
        ], vec![]),
    ]);
    let new = make_contract("new", vec![
        ep("POST", "/users", vec![
            field("name", "string", true, false),
            field("email", "string", true, false),
        ], vec![]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::RequiredAdded
        && c.field.as_deref() == Some("email")));
}

// ═══════════════════════════════════════════════════════════════════════════
// New Phase D types
// ═══════════════════════════════════════════════════════════════════════════

/// CET-BC-06: CE-D-01 — FieldRenamed heuristic.
#[test]
fn test_field_renamed_heuristic() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("username", "string", true, false),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("user_name", "string", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::FieldRenamed),
        "Should detect possible rename from 'username' to 'user_name', got: {:?}",
        changes.iter().map(|c| &c.change_type).collect::<Vec<_>>());
}

/// CET-BC-07: CE-D-02 — MethodChanged detection.
#[test]
fn test_method_changed() {
    let old = make_contract("old", vec![
        ep("POST", "/users/activate", vec![], vec![]),
    ]);
    let new = make_contract("new", vec![
        ep("PUT", "/users/activate", vec![], vec![]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::MethodChanged),
        "Should detect method change POST→PUT, got: {:?}",
        changes.iter().map(|c| &c.change_type).collect::<Vec<_>>());
}

/// CET-BC-08: CE-D-02 — PathChanged detection.
#[test]
fn test_path_changed() {
    let old = make_contract("old", vec![
        ep("GET", "/api/v1/users", vec![], vec![]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/api/v2/users", vec![], vec![]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::PathChanged),
        "Should detect path change /api/v1/users→/api/v2/users, got: {:?}",
        changes.iter().map(|c| &c.change_type).collect::<Vec<_>>());
}

/// CET-BC-09: CE-D-03 — ArrayToScalar detection.
#[test]
fn test_array_to_scalar() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("tags", "array", true, false),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("tags", "string", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::ArrayToScalar),
        "Should detect array→scalar, got: {:?}",
        changes.iter().map(|c| &c.change_type).collect::<Vec<_>>());
}

/// CET-BC-10: CE-D-03 — ScalarToArray detection.
#[test]
fn test_scalar_to_array() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("email", "string", true, false),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("email", "array", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::ScalarToArray),
        "Should detect scalar→array, got: {:?}",
        changes.iter().map(|c| &c.change_type).collect::<Vec<_>>());
}

/// CET-BC-11: CE-D-04 — NullabilityChanged detection.
#[test]
fn test_nullability_changed() {
    let old = make_contract("old", vec![
        ep("GET", "/users", vec![], vec![
            field("avatar", "string", false, true),
        ]),
    ]);
    let new = make_contract("new", vec![
        ep("GET", "/users", vec![], vec![
            field("avatar", "string", false, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::NullabilityChanged),
        "Should detect nullable→non-nullable, got: {:?}",
        changes.iter().map(|c| &c.change_type).collect::<Vec<_>>());
}

/// CET-BC-12: Request field removed.
#[test]
fn test_request_field_removed() {
    let old = make_contract("old", vec![
        ep("POST", "/users", vec![
            field("name", "string", true, false),
            field("bio", "string", false, false),
        ], vec![]),
    ]);
    let new = make_contract("new", vec![
        ep("POST", "/users", vec![
            field("name", "string", true, false),
        ], vec![]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::FieldRemoved
        && c.field.as_deref() == Some("bio")),
        "Should detect request field 'bio' removed");
}

/// CET-BC-13: Request field type change.
#[test]
fn test_request_field_type_change() {
    let old = make_contract("old", vec![
        ep("POST", "/users", vec![
            field("age", "string", true, false),
        ], vec![]),
    ]);
    let new = make_contract("new", vec![
        ep("POST", "/users", vec![
            field("age", "integer", true, false),
        ], vec![]),
    ]);
    let changes = classify_breaking_changes(&old, &new);
    assert!(changes.iter().any(|c| c.change_type == BreakingChangeType::TypeChanged
        && c.field.as_deref() == Some("age")),
        "Should detect request field type change");
}

/// CET-BC-14: No changes produces empty result.
#[test]
fn test_no_changes() {
    let contract = make_contract("same", vec![
        ep("GET", "/users", vec![], vec![
            field("id", "integer", true, false),
        ]),
    ]);
    let changes = classify_breaking_changes(&contract, &contract);
    assert!(changes.is_empty(), "Identical contracts should produce no breaking changes");
}

/// CET-BC-15: is_breaking classification correctness.
#[test]
fn test_is_breaking_classification() {
    assert!(BreakingChangeType::EndpointRemoved.is_breaking());
    assert!(BreakingChangeType::FieldRemoved.is_breaking());
    assert!(BreakingChangeType::TypeChanged.is_breaking());
    assert!(BreakingChangeType::OptionalToRequired.is_breaking());
    assert!(BreakingChangeType::NullabilityChanged.is_breaking());
    assert!(BreakingChangeType::ArrayToScalar.is_breaking());
    assert!(BreakingChangeType::ScalarToArray.is_breaking());
    assert!(BreakingChangeType::FieldRenamed.is_breaking());
    assert!(BreakingChangeType::MethodChanged.is_breaking());
    assert!(BreakingChangeType::PathChanged.is_breaking());
    // Non-breaking:
    assert!(!BreakingChangeType::RateLimitAdded.is_breaking());
    assert!(!BreakingChangeType::DeprecationRemoved.is_breaking());
}
