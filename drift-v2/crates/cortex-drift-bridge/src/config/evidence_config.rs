//! Per-evidence-type weight overrides for grounding score computation.
//!
//! Allows operators to adjust the relative importance of each evidence type
//! without recompiling. Falls back to defaults defined in EvidenceType::default_weight().

use std::collections::HashMap;

use crate::grounding::EvidenceType;

/// Per-evidence-type weight override configuration.
#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    /// Custom weights by evidence type. Missing entries use the default.
    overrides: HashMap<String, f64>,
}

impl EvidenceConfig {
    /// Create a config with all default weights.
    pub fn defaults() -> Self {
        Self {
            overrides: HashMap::new(),
        }
    }

    /// Set a custom weight for an evidence type.
    /// Weight must be in [0.0, 1.0].
    pub fn set_weight(&mut self, evidence_type: &str, weight: f64) {
        let clamped = weight.clamp(0.0, 1.0);
        self.overrides.insert(evidence_type.to_string(), clamped);
    }

    /// Get the effective weight for an evidence type.
    /// Returns the override if set, otherwise the default.
    pub fn weight_for(&self, evidence_type: &EvidenceType) -> f64 {
        let key = format!("{:?}", evidence_type);
        self.overrides
            .get(&key)
            .copied()
            .unwrap_or_else(|| evidence_type.default_weight())
    }

    /// Whether any overrides are configured.
    pub fn has_overrides(&self) -> bool {
        !self.overrides.is_empty()
    }

    /// Number of overrides.
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self::defaults()
    }
}
