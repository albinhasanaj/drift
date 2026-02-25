//! Breaking change classifier: 20+ change types, paradigm-specific rules.

use super::types::*;

/// Classify breaking changes between two versions of a contract.
pub fn classify_breaking_changes(
    old_contract: &Contract,
    new_contract: &Contract,
) -> Vec<BreakingChange> {
    let mut changes = Vec::new();

    let old_endpoints: std::collections::HashMap<String, &Endpoint> = old_contract
        .endpoints
        .iter()
        .map(|e| (format!("{}:{}", e.method, e.path), e))
        .collect();

    let new_endpoints: std::collections::HashMap<String, &Endpoint> = new_contract
        .endpoints
        .iter()
        .map(|e| (format!("{}:{}", e.method, e.path), e))
        .collect();

    // Check for removed endpoints
    for (key, old_ep) in &old_endpoints {
        if !new_endpoints.contains_key(key) {
            changes.push(BreakingChange {
                change_type: BreakingChangeType::EndpointRemoved,
                endpoint: old_ep.path.clone(),
                field: None,
                severity: MismatchSeverity::Critical,
                message: format!("{} {} was removed", old_ep.method, old_ep.path),
            });
        }
    }

    // Check for field-level changes in existing endpoints
    for (key, new_ep) in &new_endpoints {
        if let Some(old_ep) = old_endpoints.get(key) {
            // ─── Response field changes ───

            // FieldRemoved: response field existed in old, missing in new
            for old_field in &old_ep.response_fields {
                if !new_ep.response_fields.iter().any(|f| f.name == old_field.name) {
                    // CE-D-01: FieldRenamed heuristic — if a field was removed and a new
                    // field of the same type AND similar name was added, it might be a rename.
                    let possible_rename = new_ep.response_fields.iter().find(|f| {
                        f.field_type == old_field.field_type
                            && !old_ep.response_fields.iter().any(|of| of.name == f.name)
                            && names_similar(&old_field.name, &f.name)
                    });

                    if let Some(renamed_to) = possible_rename {
                        changes.push(BreakingChange {
                            change_type: BreakingChangeType::FieldRenamed,
                            endpoint: new_ep.path.clone(),
                            field: Some(old_field.name.clone()),
                            severity: MismatchSeverity::High,
                            message: format!(
                                "Field '{}' possibly renamed to '{}'",
                                old_field.name, renamed_to.name
                            ),
                        });
                    } else {
                        changes.push(BreakingChange {
                            change_type: BreakingChangeType::FieldRemoved,
                            endpoint: new_ep.path.clone(),
                            field: Some(old_field.name.clone()),
                            severity: MismatchSeverity::High,
                            message: format!("Field '{}' removed from response", old_field.name),
                        });
                    }
                }
            }

            // Check type changes, nullability, array/scalar on response fields
            for new_field in &new_ep.response_fields {
                if let Some(old_field) = old_ep.response_fields.iter().find(|f| f.name == new_field.name) {
                    classify_field_changes(&mut changes, old_field, new_field, &new_ep.path);
                }
            }

            // ─── Request field changes ───

            // Request field removed (breaking — clients may still send it)
            for old_field in &old_ep.request_fields {
                if !new_ep.request_fields.iter().any(|f| f.name == old_field.name) {
                    changes.push(BreakingChange {
                        change_type: BreakingChangeType::FieldRemoved,
                        endpoint: new_ep.path.clone(),
                        field: Some(old_field.name.clone()),
                        severity: MismatchSeverity::Medium,
                        message: format!("Field '{}' removed from request", old_field.name),
                    });
                }
            }

            // New required fields added to request
            for new_field in &new_ep.request_fields {
                if new_field.required
                    && !old_ep.request_fields.iter().any(|f| f.name == new_field.name)
                {
                    changes.push(BreakingChange {
                        change_type: BreakingChangeType::RequiredAdded,
                        endpoint: new_ep.path.clone(),
                        field: Some(new_field.name.clone()),
                        severity: MismatchSeverity::Medium,
                        message: format!("New required field '{}' added to request", new_field.name),
                    });
                }
            }

            // Request field type/nullability changes
            for new_field in &new_ep.request_fields {
                if let Some(old_field) = old_ep.request_fields.iter().find(|f| f.name == new_field.name) {
                    classify_field_changes(&mut changes, old_field, new_field, &new_ep.path);
                }
            }
        }
    }

    // CE-D-02: Detect method/path changes by matching endpoints with same path but different method.
    for (key, old_ep) in &old_endpoints {
        if !new_endpoints.contains_key(key) {
            // Already reported as EndpointRemoved above.
            // Check if same path exists with different method → MethodChanged.
            if let Some((_, new_ep)) = new_endpoints.iter().find(|(_, ne)| {
                ne.path == old_ep.path && ne.method != old_ep.method
                    && !old_endpoints.contains_key(&format!("{}:{}", ne.method, ne.path))
            }) {
                changes.push(BreakingChange {
                    change_type: BreakingChangeType::MethodChanged,
                    endpoint: old_ep.path.clone(),
                    field: None,
                    severity: MismatchSeverity::Critical,
                    message: format!(
                        "Method changed from {} to {} for {}",
                        old_ep.method, new_ep.method, old_ep.path
                    ),
                });
            }

            // Check if same method exists with different path → PathChanged.
            if let Some((_, new_ep)) = new_endpoints.iter().find(|(_, ne)| {
                ne.method == old_ep.method && ne.path != old_ep.path
                    && !old_endpoints.contains_key(&format!("{}:{}", ne.method, ne.path))
            }) {
                changes.push(BreakingChange {
                    change_type: BreakingChangeType::PathChanged,
                    endpoint: old_ep.path.clone(),
                    field: None,
                    severity: MismatchSeverity::Critical,
                    message: format!(
                        "Path changed from {} to {} for {} endpoint",
                        old_ep.path, new_ep.path, old_ep.method
                    ),
                });
            }
        }
    }

    changes
}

/// Classify field-level changes between old and new versions of the same field.
fn classify_field_changes(
    changes: &mut Vec<BreakingChange>,
    old_field: &FieldSpec,
    new_field: &FieldSpec,
    endpoint_path: &str,
) {
    // TypeChanged
    if old_field.field_type != new_field.field_type {
        // CE-D-03: Detect array↔scalar transitions specifically.
        let old_is_array = is_array_type(&old_field.field_type);
        let new_is_array = is_array_type(&new_field.field_type);

        if old_is_array && !new_is_array {
            changes.push(BreakingChange {
                change_type: BreakingChangeType::ArrayToScalar,
                endpoint: endpoint_path.to_string(),
                field: Some(new_field.name.clone()),
                severity: MismatchSeverity::Critical,
                message: format!(
                    "Field '{}' changed from array ({}) to scalar ({})",
                    new_field.name, old_field.field_type, new_field.field_type
                ),
            });
        } else if !old_is_array && new_is_array {
            changes.push(BreakingChange {
                change_type: BreakingChangeType::ScalarToArray,
                endpoint: endpoint_path.to_string(),
                field: Some(new_field.name.clone()),
                severity: MismatchSeverity::Critical,
                message: format!(
                    "Field '{}' changed from scalar ({}) to array ({})",
                    new_field.name, old_field.field_type, new_field.field_type
                ),
            });
        } else {
            changes.push(BreakingChange {
                change_type: BreakingChangeType::TypeChanged,
                endpoint: endpoint_path.to_string(),
                field: Some(new_field.name.clone()),
                severity: MismatchSeverity::High,
                message: format!(
                    "Field '{}' type changed from {} to {}",
                    new_field.name, old_field.field_type, new_field.field_type
                ),
            });
        }
    }

    // OptionalToRequired
    if !old_field.required && new_field.required {
        changes.push(BreakingChange {
            change_type: BreakingChangeType::OptionalToRequired,
            endpoint: endpoint_path.to_string(),
            field: Some(new_field.name.clone()),
            severity: MismatchSeverity::High,
            message: format!("Field '{}' changed from optional to required", new_field.name),
        });
    }

    // CE-D-04: NullabilityChanged — nullable field became non-nullable.
    if old_field.nullable && !new_field.nullable {
        changes.push(BreakingChange {
            change_type: BreakingChangeType::NullabilityChanged,
            endpoint: endpoint_path.to_string(),
            field: Some(new_field.name.clone()),
            severity: MismatchSeverity::High,
            message: format!("Field '{}' changed from nullable to non-nullable", new_field.name),
        });
    }
}

/// Check if two field names are similar enough to suggest a rename.
/// Uses Levenshtein distance ratio and case-style normalization.
fn names_similar(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Normalize to lowercase with underscores (camelCase → camel_case)
    let norm_a = normalize_name(a);
    let norm_b = normalize_name(b);
    if norm_a == norm_b {
        return true;
    }
    // Levenshtein distance ratio on normalized names
    let max_len = norm_a.len().max(norm_b.len());
    if max_len == 0 {
        return false;
    }
    let dist = levenshtein(&norm_a, &norm_b);
    let ratio = 1.0 - (dist as f64 / max_len as f64);
    ratio > 0.5
}

/// Normalize a field name: camelCase/PascalCase → snake_case, lowercase.
fn normalize_name(name: &str) -> String {
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_lowercase().next().unwrap_or(ch));
    }
    result
}

/// Simple Levenshtein distance.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate().take(m + 1) { row[0] = i; }
    for (j, val) in dp[0].iter_mut().enumerate().take(n + 1) { *val = j; }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[m][n]
}

/// Check if a type string represents an array type.
fn is_array_type(type_str: &str) -> bool {
    type_str.starts_with('[') || type_str.starts_with("array")
        || type_str.starts_with("repeated:") || type_str.starts_with("List<")
        || type_str.ends_with("[]")
}
