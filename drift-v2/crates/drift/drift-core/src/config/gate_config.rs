//! Quality gate configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the quality gates subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GateConfig {
    /// Fail level: "error" | "warning" | "info". Default: "error".
    pub fail_on: Option<String>,
    /// Required gates to pass. Default: all gates.
    #[serde(default)]
    pub required_gates: Vec<String>,
    /// Minimum drift score to pass (0-100). Default: 70.
    pub min_score: Option<u32>,
    /// Enabled gates.
    #[serde(default)]
    pub enabled_gates: Vec<String>,
    /// Enable progressive enforcement. Default: false.
    pub progressive_enforcement: Option<bool>,
    /// Ramp-up period in days for progressive enforcement.
    pub ramp_up_period: Option<u32>,
}

impl GateConfig {
    /// Returns the effective fail level, defaulting to "error".
    pub fn effective_fail_on(&self) -> &str {
        self.fail_on.as_deref().unwrap_or("error")
    }

    /// Returns the effective minimum score, defaulting to 70.
    pub fn effective_min_score(&self) -> u32 {
        self.min_score.unwrap_or(70)
    }
}
