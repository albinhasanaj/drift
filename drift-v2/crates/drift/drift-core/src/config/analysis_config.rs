//! Analysis configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the analysis subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AnalysisConfig {
    /// Minimum occurrences for pattern discovery. Default: 3.
    pub min_occurrences: Option<u32>,
    /// Dominance threshold for convention detection. Default: 0.60.
    pub dominance_threshold: Option<f64>,
    /// Minimum files for pattern to be considered. Default: 2.
    pub min_files: Option<u32>,
    /// Re-learning threshold (% files changed to trigger full re-learn). Default: 0.10.
    pub relearn_threshold: Option<f64>,
    /// Enabled analysis categories.
    #[serde(default)]
    pub enabled_categories: Vec<String>,
    /// Per-detector threshold overrides.
    #[serde(default)]
    pub detector_thresholds: std::collections::HashMap<String, f64>,
    /// Languages enabled for GAST analysis.
    #[serde(default)]
    pub gast_languages: Vec<String>,
    /// Enable incremental analysis. Default: true.
    pub incremental: Option<bool>,
}

impl AnalysisConfig {
    /// Returns the effective minimum occurrences, defaulting to 3.
    pub fn effective_min_occurrences(&self) -> u32 {
        self.min_occurrences.unwrap_or(3)
    }

    /// Returns the effective dominance threshold, defaulting to 0.60.
    pub fn effective_dominance_threshold(&self) -> f64 {
        self.dominance_threshold.unwrap_or(0.60)
    }

    /// Returns the effective minimum files, defaulting to 2.
    pub fn effective_min_files(&self) -> u32 {
        self.min_files.unwrap_or(2)
    }
}
