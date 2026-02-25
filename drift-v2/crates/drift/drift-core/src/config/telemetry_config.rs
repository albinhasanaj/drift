//! Telemetry configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the telemetry subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Enable anonymous telemetry. Default: false.
    pub enabled: Option<bool>,
    /// Telemetry endpoint URL.
    pub endpoint: Option<String>,
    /// Anonymous identifier for telemetry.
    pub anonymous_id: Option<String>,
}

impl TelemetryConfig {
    /// Returns whether telemetry is enabled, defaulting to false.
    pub fn effective_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }
}
