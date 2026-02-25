//! Weight application, clamping, NaN handling.

use drift_core::traits::{AdaptiveWeightTable, MigrationPath, StaticWeightProvider, WeightProvider};

/// Weight applicator — applies weights with clamping and NaN handling.
pub struct WeightApplicator {
    provider: Box<dyn WeightProvider>,
}

impl WeightApplicator {
    pub fn new() -> Self {
        Self {
            provider: Box::new(StaticWeightProvider),
        }
    }

    pub fn with_provider(provider: Box<dyn WeightProvider>) -> Self {
        Self { provider }
    }

    /// Get weights for a migration path, with clamping and NaN handling.
    pub fn get_weights(&self, migration_path: Option<&MigrationPath>) -> AdaptiveWeightTable {
        let default_path = MigrationPath::language_only("unknown", "unknown");
        let path = migration_path.unwrap_or(&default_path);
        let mut table = self.provider.get_weights(path);

        // Clamp negative weights to 0.0, replace NaN with static defaults
        let defaults = AdaptiveWeightTable::static_defaults();
        for (key, value) in table.weights.iter_mut() {
            if value.is_nan() {
                *value = defaults.weights.get(key).copied().unwrap_or(1.0);
            } else if *value < 0.0 {
                *value = 0.0;
            }
        }

        table
    }
}

impl Default for WeightApplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct CustomWeightProvider {
        weights: HashMap<String, f64>,
    }

    impl WeightProvider for CustomWeightProvider {
        fn get_weights(&self, _path: &MigrationPath) -> AdaptiveWeightTable {
            AdaptiveWeightTable {
                weights: self.weights.clone(),
                failure_distribution: HashMap::new(),
                sample_size: 10,
                last_updated: 1000,
            }
        }
    }

    #[test]
    fn test_static_weights_returned_by_default() {
        let applicator = WeightApplicator::new();
        let weights = applicator.get_weights(None);
        assert_eq!(weights.get_weight("public_api"), 2.0);
        assert_eq!(weights.get_weight("data_model"), 1.8);
    }

    #[test]
    fn test_custom_weights_applied() {
        let mut custom = HashMap::new();
        custom.insert("data_model".to_string(), 2.4);
        custom.insert("public_api".to_string(), 1.5);

        let provider = CustomWeightProvider { weights: custom };
        let applicator = WeightApplicator::with_provider(Box::new(provider));
        let weights = applicator.get_weights(None);

        assert_eq!(weights.get_weight("data_model"), 2.4);
        assert_eq!(weights.get_weight("public_api"), 1.5);
    }

    #[test]
    fn test_negative_weights_clamped() {
        let mut custom = HashMap::new();
        custom.insert("data_model".to_string(), -1.5);

        let provider = CustomWeightProvider { weights: custom };
        let applicator = WeightApplicator::with_provider(Box::new(provider));
        let weights = applicator.get_weights(None);

        assert_eq!(weights.get_weight("data_model"), 0.0);
    }

    #[test]
    fn test_nan_weights_replaced() {
        let mut custom = HashMap::new();
        custom.insert("data_model".to_string(), f64::NAN);

        let provider = CustomWeightProvider { weights: custom };
        let applicator = WeightApplicator::with_provider(Box::new(provider));
        let weights = applicator.get_weights(None);

        // Should fall back to static default
        assert_eq!(weights.get_weight("data_model"), 1.8);
    }

    #[test]
    fn test_weight_override_does_not_mutate_static() {
        let mut custom = HashMap::new();
        custom.insert("public_api".to_string(), 5.0);

        let provider = CustomWeightProvider { weights: custom };
        let applicator = WeightApplicator::with_provider(Box::new(provider));
        let _ = applicator.get_weights(None);

        // Static defaults should be unchanged
        let static_applicator = WeightApplicator::new();
        let static_weights = static_applicator.get_weights(None);
        assert_eq!(static_weights.get_weight("public_api"), 2.0);
    }
}
