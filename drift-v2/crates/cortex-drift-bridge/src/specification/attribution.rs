//! DataSourceAttribution tracking — records which Drift system produced data,
//! confidence at generation time, and whether the data was correct.

use serde::{Deserialize, Serialize};

/// Attribution for a data source that contributed to a spec section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceAttribution {
    /// Which Drift system produced the data (e.g., "call_graph", "boundary", "convention").
    pub system: String,
    /// Confidence of the data at generation time.
    pub confidence_at_generation: f64,
    /// Whether the data was correct.
    pub was_correct: bool,
}

impl DataSourceAttribution {
    pub fn new(system: impl Into<String>, confidence: f64, was_correct: bool) -> Self {
        Self {
            system: system.into(),
            confidence_at_generation: confidence,
            was_correct,
        }
    }
}

/// Aggregate attribution statistics for system reliability analysis.
#[derive(Debug, Clone, Default)]
pub struct AttributionStats {
    /// Total attributions per system.
    pub total_by_system: std::collections::HashMap<String, u32>,
    /// Correct attributions per system.
    pub correct_by_system: std::collections::HashMap<String, u32>,
}

impl AttributionStats {
    /// Add an attribution to the stats.
    pub fn add(&mut self, attr: &DataSourceAttribution) {
        *self.total_by_system.entry(attr.system.clone()).or_insert(0) += 1;
        if attr.was_correct {
            *self.correct_by_system.entry(attr.system.clone()).or_insert(0) += 1;
        }
    }

    /// Get the accuracy rate for a system.
    pub fn accuracy(&self, system: &str) -> Option<f64> {
        let total = *self.total_by_system.get(system)? as f64;
        let correct = *self.correct_by_system.get(system).unwrap_or(&0) as f64;
        if total > 0.0 {
            Some(correct / total)
        } else {
            None
        }
    }
}
