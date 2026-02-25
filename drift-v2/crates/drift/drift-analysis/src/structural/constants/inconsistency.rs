//! Phase 4: Inconsistency detection — fuzzy name matching, case normalization.
//!
//! Detects constants that refer to the same concept but use different naming
//! conventions (e.g., `maxRetries` vs `MAX_RETRIES` vs `max_retries`).

use super::types::Constant;

/// A detected naming inconsistency between constants.
#[derive(Debug, Clone)]
pub struct NamingInconsistency {
    pub constant_a: String,
    pub constant_b: String,
    pub file_a: String,
    pub file_b: String,
    pub normalized_name: String,
    pub similarity: f64,
}

/// Detect naming inconsistencies among constants.
///
/// Normalizes names to a canonical form (lowercase, no separators) and
/// groups constants that normalize to the same string.
pub fn detect_inconsistencies(constants: &[Constant]) -> Vec<NamingInconsistency> {
    let mut results = Vec::new();
    let normalized: Vec<(usize, String)> = constants
        .iter()
        .enumerate()
        .map(|(i, c)| (i, normalize_name(&c.name)))
        .collect();

    for i in 0..normalized.len() {
        for j in (i + 1)..normalized.len() {
            if normalized[i].1 == normalized[j].1 && constants[i].name != constants[j].name {
                results.push(NamingInconsistency {
                    constant_a: constants[i].name.clone(),
                    constant_b: constants[j].name.clone(),
                    file_a: constants[i].file.clone(),
                    file_b: constants[j].file.clone(),
                    normalized_name: normalized[i].1.clone(),
                    similarity: 1.0,
                });
            }
        }
    }

    results
}

/// Normalize a name: convert camelCase/PascalCase/snake_case/SCREAMING_SNAKE to lowercase.
fn normalize_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());

    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            continue; // Strip separators
        }
        result.push(ch.to_ascii_lowercase());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_camel_case() {
        assert_eq!(normalize_name("maxRetries"), "maxretries");
    }

    #[test]
    fn test_normalize_screaming_snake() {
        assert_eq!(normalize_name("MAX_RETRIES"), "maxretries");
    }

    #[test]
    fn test_normalize_snake_case() {
        assert_eq!(normalize_name("max_retries"), "maxretries");
    }

    #[test]
    fn test_detect_inconsistency() {
        let constants = vec![
            Constant {
                name: "maxRetries".to_string(),
                value: "3".to_string(),
                file: "a.ts".to_string(),
                line: 1,
                is_used: true,
                language: "typescript".to_string(),
                is_named: true,
            },
            Constant {
                name: "MAX_RETRIES".to_string(),
                value: "3".to_string(),
                file: "b.ts".to_string(),
                line: 1,
                is_used: true,
                language: "typescript".to_string(),
                is_named: true,
            },
        ];

        let inconsistencies = detect_inconsistencies(&constants);
        assert_eq!(inconsistencies.len(), 1);
        assert_eq!(inconsistencies[0].normalized_name, "maxretries");
    }
}
