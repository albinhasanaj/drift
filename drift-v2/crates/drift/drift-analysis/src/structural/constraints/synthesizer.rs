//! Constraint synthesis — mine constraints from existing code patterns.

use drift_core::types::collections::FxHashMap;

use super::detector::FunctionInfo;
use super::types::{Constraint, ConstraintSource, InvariantType};

/// Mines constraints from existing code patterns.
pub struct ConstraintSynthesizer {
    /// Function names per file.
    functions: FxHashMap<String, Vec<FunctionInfo>>,
}

impl ConstraintSynthesizer {
    pub fn new() -> Self {
        Self {
            functions: FxHashMap::default(),
        }
    }

    /// Register parsed data for a file.
    pub fn add_file(&mut self, file: &str, functions: Vec<FunctionInfo>) {
        self.functions.insert(file.to_string(), functions);
    }

    /// Synthesize naming convention constraints from observed patterns.
    ///
    /// If ≥80% of functions follow a convention, synthesize a constraint for it.
    pub fn synthesize_naming_conventions(&self) -> Vec<Constraint> {
        let mut convention_counts: FxHashMap<&str, usize> = FxHashMap::default();
        let mut total = 0usize;

        for fns in self.functions.values() {
            for f in fns {
                total += 1;
                if is_camel_case(&f.name) {
                    *convention_counts.entry("camelCase").or_default() += 1;
                } else if is_snake_case(&f.name) {
                    *convention_counts.entry("snake_case").or_default() += 1;
                } else if is_pascal_case(&f.name) {
                    *convention_counts.entry("PascalCase").or_default() += 1;
                }
            }
        }

        if total == 0 {
            return vec![];
        }

        let mut constraints = Vec::new();
        for (convention, count) in &convention_counts {
            let ratio = *count as f64 / total as f64;
            if ratio >= 0.8 {
                constraints.push(Constraint {
                    id: format!("synth-naming-{}", convention),
                    description: format!(
                        "Auto-synthesized: {:.0}% of functions follow {} convention",
                        ratio * 100.0,
                        convention
                    ),
                    invariant_type: InvariantType::NamingConvention,
                    target: convention.to_string(),
                    scope: None,
                    source: ConstraintSource::Synthesized,
                    enabled: true,
                });
            }
        }
        constraints
    }

    /// Synthesize all constraint types.
    pub fn synthesize_all(&self) -> Vec<Constraint> {
        self.synthesize_naming_conventions()
    }
}

impl Default for ConstraintSynthesizer {
    fn default() -> Self {
        Self::new()
    }
}

fn is_camel_case(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.chars().next().unwrap();
    first.is_lowercase() && !name.contains('_') && name.chars().any(|c| c.is_uppercase())
}

fn is_snake_case(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.chars().all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_')
        && name.contains('_')
}

fn is_pascal_case(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.chars().next().unwrap();
    first.is_uppercase() && !name.contains('_')
}
