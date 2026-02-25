//! Taint label propagation with sanitizer tracking and label merging.

use drift_core::types::collections::FxHashMap;

use super::types::*;

/// Propagation context for tracking taint through a function.
#[derive(Debug, Default)]
pub struct PropagationContext {
    /// Variable → taint label mapping.
    labels: FxHashMap<String, TaintLabel>,
    /// Applied sanitizers.
    sanitizers: Vec<TaintSanitizer>,
    /// Next label ID.
    next_id: u64,
}

impl PropagationContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Introduce taint for a variable.
    pub fn taint_variable(&mut self, var: &str, source_type: SourceType) -> TaintLabel {
        let label = TaintLabel::new(self.next_id, source_type);
        self.next_id += 1;
        self.labels.insert(var.to_string(), label.clone());
        label
    }

    /// Propagate taint from one variable to another (assignment).
    pub fn propagate(&mut self, from: &str, to: &str) {
        if let Some(label) = self.labels.get(from).cloned() {
            self.labels.insert(to.to_string(), label);
        }
    }

    /// Merge taint labels at a join point (e.g., ternary, phi node).
    pub fn merge(&mut self, vars: &[&str], target: &str) {
        let mut merged_label: Option<TaintLabel> = None;

        for var in vars {
            if let Some(label) = self.labels.get(*var) {
                match &mut merged_label {
                    None => merged_label = Some(label.clone()),
                    Some(existing) => {
                        // Merge: take the union of applied sanitizers
                        for sanitizer in &label.applied_sanitizers {
                            if !existing.has_sanitizer(*sanitizer) {
                                existing.apply_sanitizer(*sanitizer);
                            }
                        }
                        // If either branch is unsanitized, the merge is unsanitized
                        if !label.sanitized {
                            existing.sanitized = false;
                        }
                    }
                }
            }
        }

        if let Some(label) = merged_label {
            self.labels.insert(target.to_string(), label);
        }
    }

    /// Apply a sanitizer to a variable.
    pub fn sanitize(&mut self, var: &str, sanitizer_type: SanitizerType, sink_types: &[SinkType]) {
        if let Some(label) = self.labels.get_mut(var) {
            label.apply_sanitizer(sanitizer_type);
        }
        self.sanitizers.push(TaintSanitizer {
            file: String::new(),
            line: 0,
            expression: var.to_string(),
            sanitizer_type,
            labels_sanitized: sink_types.to_vec(),
        });
    }

    /// Check if a variable is tainted.
    pub fn is_tainted(&self, var: &str) -> bool {
        self.labels.contains_key(var)
    }

    /// Check if a variable's taint has been sanitized for a specific sink type.
    pub fn is_sanitized_for(&self, _var: &str, sink_type: &SinkType) -> bool {
        self.sanitizers.iter().any(|s| s.labels_sanitized.contains(sink_type))
    }

    /// Get the taint label for a variable.
    pub fn get_label(&self, var: &str) -> Option<&TaintLabel> {
        self.labels.get(var)
    }

    /// Get all tainted variables.
    pub fn tainted_variables(&self) -> Vec<&str> {
        self.labels.keys().map(|s| s.as_str()).collect()
    }

    /// Get all applied sanitizers.
    pub fn applied_sanitizers(&self) -> &[TaintSanitizer] {
        &self.sanitizers
    }

    /// Clear all taint state.
    pub fn clear(&mut self) {
        self.labels.clear();
        self.sanitizers.clear();
    }
}

/// Propagate taint through a collection operation.
///
/// When a tainted value is inserted into a collection (array, map, set),
/// the collection itself becomes tainted. When a value is read from a
/// tainted collection, the read value is tainted.
pub fn propagate_through_collection(
    ctx: &mut PropagationContext,
    collection_var: &str,
    element_var: &str,
    is_insert: bool,
) {
    if is_insert {
        // Inserting tainted element → collection becomes tainted
        if ctx.is_tainted(element_var) {
            if let Some(label) = ctx.get_label(element_var).cloned() {
                ctx.labels.insert(collection_var.to_string(), label);
            }
        }
    } else {
        // Reading from tainted collection → element becomes tainted
        if ctx.is_tainted(collection_var) {
            ctx.propagate(collection_var, element_var);
        }
    }
}
