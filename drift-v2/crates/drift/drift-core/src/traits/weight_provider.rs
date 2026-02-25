//! WeightProvider trait — D1 compliant.
//!
//! In standalone mode, static weights are used. The bridge (Phase 9)
//! implements the trait and provides adaptive weights from Cortex Skill
//! memories. Drift never imports from Cortex.

use std::collections::HashMap;

/// Migration path key for weight table lookup.
///
/// Keyed by (source_language, target_language, source_framework, target_framework).
/// `None` frameworks fall back to language-only lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MigrationPath {
    pub source_language: String,
    pub target_language: String,
    pub source_framework: Option<String>,
    pub target_framework: Option<String>,
}

impl MigrationPath {
    /// Create a new migration path.
    pub fn new(
        source_language: impl Into<String>,
        target_language: impl Into<String>,
        source_framework: Option<String>,
        target_framework: Option<String>,
    ) -> Self {
        Self {
            source_language: source_language.into(),
            target_language: target_language.into(),
            source_framework,
            target_framework,
        }
    }

    /// Create a language-only migration path (no frameworks).
    pub fn language_only(
        source_language: impl Into<String>,
        target_language: impl Into<String>,
    ) -> Self {
        Self {
            source_language: source_language.into(),
            target_language: target_language.into(),
            source_framework: None,
            target_framework: None,
        }
    }
}

/// Adaptive weight table for specification generation.
///
/// Contains per-section weights, failure distribution, sample size,
/// and last_updated timestamp.
#[derive(Debug, Clone)]
pub struct AdaptiveWeightTable {
    /// Per-section weights (section name → weight).
    pub weights: HashMap<String, f64>,
    /// Per-section failure distribution (section name → failure rate).
    pub failure_distribution: HashMap<String, f64>,
    /// Number of samples used to compute these weights.
    pub sample_size: usize,
    /// Unix timestamp of last update.
    pub last_updated: i64,
}

impl Default for AdaptiveWeightTable {
    fn default() -> Self {
        Self::static_defaults()
    }
}

impl AdaptiveWeightTable {
    /// Static default weights per the spec.
    pub fn static_defaults() -> Self {
        let mut weights = HashMap::new();
        weights.insert("public_api".to_string(), 2.0);
        weights.insert("data_model".to_string(), 1.8);
        weights.insert("data_flow".to_string(), 1.7);
        weights.insert("business_logic".to_string(), 1.6);
        weights.insert("conventions".to_string(), 1.5);
        weights.insert("constraints".to_string(), 1.5);
        weights.insert("security".to_string(), 1.4);
        weights.insert("error_handling".to_string(), 1.3);
        weights.insert("test_requirements".to_string(), 1.2);
        weights.insert("dependencies".to_string(), 1.0);
        weights.insert("overview".to_string(), 0.8);
        weights.insert("migration_notes".to_string(), 0.8);

        Self {
            weights,
            failure_distribution: HashMap::new(),
            sample_size: 0,
            last_updated: 0,
        }
    }

    /// Get weight for a section, falling back to 1.0 if not found.
    /// Clamps negative weights to 0.0, replaces NaN with static default.
    pub fn get_weight(&self, section: &str) -> f64 {
        let raw = self.weights.get(section).copied().unwrap_or(1.0);
        if raw.is_nan() {
            // Fall back to static default for this section
            let defaults = Self::static_defaults();
            defaults.weights.get(section).copied().unwrap_or(1.0)
        } else if raw < 0.0 {
            0.0
        } else {
            raw
        }
    }
}

/// Provider of adaptive weights for specification generation.
///
/// Default implementation returns static weights (D1 compliance).
/// The Cortex bridge (Phase 9) implements this trait to provide
/// adaptive weights from Cortex Skill memories.
pub trait WeightProvider: Send + Sync {
    /// Get weights for a given migration path.
    /// Returns static defaults if no adaptive data is available.
    fn get_weights(&self, path: &MigrationPath) -> AdaptiveWeightTable {
        let _ = path;
        AdaptiveWeightTable::static_defaults()
    }
}

/// No-op implementation for standalone mode — returns static weights.
pub struct StaticWeightProvider;

impl WeightProvider for StaticWeightProvider {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_defaults_have_correct_values() {
        let table = AdaptiveWeightTable::static_defaults();
        assert_eq!(table.weights.get("public_api"), Some(&2.0));
        assert_eq!(table.weights.get("data_model"), Some(&1.8));
        assert_eq!(table.weights.get("data_flow"), Some(&1.7));
        assert_eq!(table.weights.get("business_logic"), Some(&1.6));
        assert_eq!(table.weights.get("conventions"), Some(&1.5));
        assert_eq!(table.weights.get("constraints"), Some(&1.5));
        assert_eq!(table.weights.get("security"), Some(&1.4));
        assert_eq!(table.weights.get("error_handling"), Some(&1.3));
        assert_eq!(table.weights.get("test_requirements"), Some(&1.2));
        assert_eq!(table.weights.get("dependencies"), Some(&1.0));
        assert_eq!(table.weights.get("overview"), Some(&0.8));
    }

    #[test]
    fn test_negative_weight_clamped_to_zero() {
        let mut table = AdaptiveWeightTable::static_defaults();
        table.weights.insert("data_model".to_string(), -1.5);
        assert_eq!(table.get_weight("data_model"), 0.0);
    }

    #[test]
    fn test_nan_weight_falls_back_to_static() {
        let mut table = AdaptiveWeightTable::static_defaults();
        table.weights.insert("data_model".to_string(), f64::NAN);
        assert_eq!(table.get_weight("data_model"), 1.8);
    }

    #[test]
    fn test_static_weight_provider_returns_defaults() {
        let provider = StaticWeightProvider;
        let path = MigrationPath::language_only("python", "typescript");
        let table = provider.get_weights(&path);
        assert_eq!(table.weights.get("public_api"), Some(&2.0));
    }

    #[test]
    fn test_migration_path_language_only() {
        let path = MigrationPath::language_only("java", "kotlin");
        assert_eq!(path.source_language, "java");
        assert_eq!(path.target_language, "kotlin");
        assert!(path.source_framework.is_none());
        assert!(path.target_framework.is_none());
    }
}
