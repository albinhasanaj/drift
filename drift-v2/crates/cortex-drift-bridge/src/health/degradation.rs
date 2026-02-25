//! DegradationTracker: tracks which features are degraded and why.

use std::collections::HashMap;

/// Tracks degraded features and their reasons.
#[derive(Debug, Clone, Default)]
pub struct DegradationTracker {
    /// Feature name → reason it's degraded.
    degraded: HashMap<String, String>,
}

impl DegradationTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            degraded: HashMap::new(),
        }
    }

    /// Mark a feature as degraded with a reason.
    pub fn mark_degraded(&mut self, feature: impl Into<String>, reason: impl Into<String>) {
        self.degraded.insert(feature.into(), reason.into());
    }

    /// Clear degradation for a feature (it recovered).
    pub fn mark_recovered(&mut self, feature: &str) {
        self.degraded.remove(feature);
    }

    /// Check if a specific feature is degraded.
    pub fn is_degraded(&self, feature: &str) -> bool {
        self.degraded.contains_key(feature)
    }

    /// Get the reason a feature is degraded.
    pub fn reason(&self, feature: &str) -> Option<&str> {
        self.degraded.get(feature).map(|s| s.as_str())
    }

    /// Get all degraded features.
    pub fn all_degraded(&self) -> &HashMap<String, String> {
        &self.degraded
    }

    /// Number of degraded features.
    pub fn degraded_count(&self) -> usize {
        self.degraded.len()
    }

    /// Whether any features are degraded.
    pub fn has_degradations(&self) -> bool {
        !self.degraded.is_empty()
    }

    /// Get a summary of all degradations.
    pub fn summary(&self) -> Vec<String> {
        self.degraded
            .iter()
            .map(|(feature, reason)| format!("{}: {}", feature, reason))
            .collect()
    }
}
