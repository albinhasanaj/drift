//! BE↔FE matching via path similarity + schema compatibility scoring.

use super::types::*;

/// Match backend endpoints to frontend consumers.
pub fn match_contracts(
    backend: &[Endpoint],
    frontend: &[Endpoint],
) -> Vec<ContractMatch> {
    let mut matches = Vec::new();

    for be in backend {
        for fe in frontend {
            let confidence = compute_match_confidence(be, fe);
            if confidence >= 0.5 {
                let mismatches = detect_mismatches(be, fe);
                matches.push(ContractMatch {
                    backend: be.clone(),
                    frontend: fe.clone(),
                    confidence,
                    mismatches,
                });
            }
        }
    }

    // Sort by confidence descending
    matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    matches
}

/// Compute match confidence between a backend endpoint and frontend call.
fn compute_match_confidence(backend: &Endpoint, frontend: &Endpoint) -> f64 {
    let mut score = 0.0;
    let mut signals = 0.0;

    // Signal 1: Path similarity (highest weight)
    let path_sim = path_similarity(&backend.path, &frontend.path);
    score += path_sim * 3.0;
    signals += 3.0;

    // Signal 2: Method match
    if backend.method == frontend.method || frontend.method == "GET" || frontend.method == "ANY" {
        score += 1.0;
    }
    signals += 1.0;

    // Signal 3: Field overlap (CE-CONF-01)
    if !backend.response_fields.is_empty() || !frontend.request_fields.is_empty() {
        let overlap = field_overlap(&backend.response_fields, &frontend.request_fields);
        score += overlap;
    }
    signals += 1.0;

    // Signal 4: Type compatibility (CE-CONF-01)
    if !backend.response_fields.is_empty() && !frontend.request_fields.is_empty() {
        let type_compat = type_compatibility(&backend.response_fields, &frontend.request_fields);
        score += type_compat;
    }
    signals += 1.0;

    // Signal 5: Response shape match (CE-CONF-01)
    if !backend.response_fields.is_empty() && !frontend.request_fields.is_empty() {
        let shape = response_shape_match(&backend.response_fields, &frontend.request_fields);
        score += shape;
    }
    signals += 1.0;

    if signals == 0.0 { 0.0 } else { score / signals }
}

/// CE-CONF-01: Compute type compatibility between matching fields.
fn type_compatibility(backend_fields: &[FieldSpec], frontend_fields: &[FieldSpec]) -> f64 {
    let mut compatible = 0;
    let mut total = 0;
    for be in backend_fields {
        if let Some(fe) = frontend_fields.iter().find(|f| f.name == be.name) {
            total += 1;
            if types_compatible(&be.field_type, &fe.field_type) {
                compatible += 1;
            }
        }
    }
    if total == 0 { 0.0 } else { compatible as f64 / total as f64 }
}

/// Check if two type strings are compatible.
fn types_compatible(a: &str, b: &str) -> bool {
    let a = a.to_lowercase();
    let b = b.to_lowercase();
    if a == b { return true; }
    // number ↔ integer ↔ int ↔ float ↔ double
    let numeric = ["number", "integer", "int", "float", "double", "i32", "i64", "u32", "u64", "f32", "f64"];
    let string_types = ["string", "str", "text", "varchar"];
    let bool_types = ["boolean", "bool"];
    (numeric.contains(&a.as_str()) && numeric.contains(&b.as_str()))
        || (string_types.contains(&a.as_str()) && string_types.contains(&b.as_str()))
        || (bool_types.contains(&a.as_str()) && bool_types.contains(&b.as_str()))
        || a == "any" || b == "any"
}

/// CE-CONF-01: Response shape match — do both sides have similar field counts and nesting?
fn response_shape_match(backend_fields: &[FieldSpec], frontend_fields: &[FieldSpec]) -> f64 {
    // CT-FIX-03: Return 0.0 when both sides have no fields — no data means no match signal.
    if backend_fields.is_empty() && frontend_fields.is_empty() {
        return 0.0;
    }
    let be_count = backend_fields.len() as f64;
    let fe_count = frontend_fields.len() as f64;
    let max = be_count.max(fe_count);
    if max == 0.0 { return 0.0; }
    let min = be_count.min(fe_count);
    min / max
}

/// Compute path similarity (normalized Levenshtein-like).
fn path_similarity(a: &str, b: &str) -> f64 {
    let a_norm = normalize_path(a);
    let b_norm = normalize_path(b);

    if a_norm == b_norm {
        return 1.0;
    }

    let a_parts: Vec<&str> = a_norm.split('/').filter(|s| !s.is_empty()).collect();
    let b_parts: Vec<&str> = b_norm.split('/').filter(|s| !s.is_empty()).collect();

    if a_parts.is_empty() || b_parts.is_empty() {
        return 0.0;
    }

    let max_len = a_parts.len().max(b_parts.len());
    let matching = a_parts.iter().zip(b_parts.iter())
        .filter(|(a, b)| {
            a == b || a.starts_with(':') || b.starts_with(':')
                || a.starts_with('{') || b.starts_with('{')
        })
        .count();

    matching as f64 / max_len as f64
}

fn normalize_path(path: &str) -> String {
    path.trim_end_matches('/')
        .replace("//", "/")
        .to_lowercase()
}

fn field_overlap(a: &[FieldSpec], b: &[FieldSpec]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let a_names: std::collections::HashSet<&str> = a.iter().map(|f| f.name.as_str()).collect();
    let b_names: std::collections::HashSet<&str> = b.iter().map(|f| f.name.as_str()).collect();
    let intersection = a_names.intersection(&b_names).count();
    let union = a_names.union(&b_names).count();
    if union == 0 { 0.0 } else { intersection as f64 / union as f64 }
}

fn detect_mismatches(backend: &Endpoint, frontend: &Endpoint) -> Vec<ContractMismatch> {
    let mut mismatches = Vec::new();

    for be_field in &backend.response_fields {
        let fe_match = frontend.request_fields.iter().find(|f| f.name == be_field.name);

        match fe_match {
            None => {
                // 1. FieldMissing: required backend field not consumed by frontend
                if be_field.required {
                    mismatches.push(ContractMismatch {
                        backend_endpoint: backend.path.clone(),
                        frontend_call: frontend.path.clone(),
                        mismatch_type: MismatchType::FieldMissing,
                        severity: MismatchSeverity::High,
                        message: format!("Required field '{}' not consumed by frontend", be_field.name),
                    });
                }
            }
            Some(fe_field) => {
                // 2. TypeMismatch: same field name, incompatible types
                if !types_compatible(&be_field.field_type, &fe_field.field_type) {
                    // 5. ArrayScalar: one side is array, other is scalar
                    let be_array = is_array_type(&be_field.field_type);
                    let fe_array = is_array_type(&fe_field.field_type);
                    if be_array != fe_array {
                        mismatches.push(ContractMismatch {
                            backend_endpoint: backend.path.clone(),
                            frontend_call: frontend.path.clone(),
                            mismatch_type: MismatchType::ArrayScalar,
                            severity: MismatchSeverity::Critical,
                            message: format!(
                                "Field '{}': backend={}, frontend={} (array/scalar mismatch)",
                                be_field.name, be_field.field_type, fe_field.field_type
                            ),
                        });
                    } else {
                        mismatches.push(ContractMismatch {
                            backend_endpoint: backend.path.clone(),
                            frontend_call: frontend.path.clone(),
                            mismatch_type: MismatchType::TypeMismatch,
                            severity: MismatchSeverity::High,
                            message: format!(
                                "Field '{}': backend type '{}' != frontend type '{}'",
                                be_field.name, be_field.field_type, fe_field.field_type
                            ),
                        });
                    }
                }

                // 3. RequiredOptional: backend says required, frontend treats as optional
                if be_field.required && !fe_field.required {
                    mismatches.push(ContractMismatch {
                        backend_endpoint: backend.path.clone(),
                        frontend_call: frontend.path.clone(),
                        mismatch_type: MismatchType::RequiredOptional,
                        severity: MismatchSeverity::Medium,
                        message: format!(
                            "Field '{}': required in backend but optional in frontend",
                            be_field.name
                        ),
                    });
                }

                // 6. Nullable: backend non-nullable but frontend expects nullable
                if !be_field.nullable && fe_field.nullable {
                    mismatches.push(ContractMismatch {
                        backend_endpoint: backend.path.clone(),
                        frontend_call: frontend.path.clone(),
                        mismatch_type: MismatchType::Nullable,
                        severity: MismatchSeverity::Medium,
                        message: format!(
                            "Field '{}': non-nullable in backend but nullable in frontend",
                            be_field.name
                        ),
                    });
                }
            }
        }
    }

    mismatches
}

/// Check if a type string represents an array type.
fn is_array_type(type_str: &str) -> bool {
    let t = type_str.to_lowercase();
    t.starts_with('[') || t.starts_with("array") || t.ends_with("[]")
        || t.starts_with("list<") || t.starts_with("vec<")
}
