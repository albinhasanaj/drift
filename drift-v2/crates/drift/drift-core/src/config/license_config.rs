//! License configuration.

use serde::{Deserialize, Serialize};

/// License tier for feature gating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LicenseTier {
    #[default]
    Community,
    Team,
    Enterprise,
}

/// Configuration for the licensing subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LicenseConfig {
    /// License tier. Default: Community.
    pub tier: LicenseTier,
    /// License key (alternative to env var / file).
    pub key: Option<String>,
    /// Path to JWT license file.
    pub jwt_path: Option<String>,
    /// Upgrade URL. Default: "https://driftscan.dev/pricing".
    pub upgrade_url: Option<String>,
    /// Feature flags enabled by the license.
    #[serde(default)]
    pub feature_flags: Vec<String>,
}

impl LicenseConfig {
    /// Returns the effective upgrade URL.
    pub fn effective_upgrade_url(&self) -> &str {
        self.upgrade_url
            .as_deref()
            .unwrap_or("https://driftscan.dev/pricing")
    }
}
