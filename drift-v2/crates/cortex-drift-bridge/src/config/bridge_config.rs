//! BridgeConfig: all bridge settings from drift.toml [bridge] section.

use crate::config::EventConfig;
use crate::config::EvidenceConfig;
use crate::grounding::GroundingConfig;
use crate::license::LicenseTier;

/// Bridge configuration from drift.toml [bridge] section.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Path to cortex.db.
    pub cortex_db_path: Option<String>,
    /// Path to drift.db.
    pub drift_db_path: Option<String>,
    /// Whether the bridge is enabled.
    pub enabled: bool,
    /// License tier.
    pub license_tier: LicenseTier,
    /// Grounding configuration.
    pub grounding: GroundingConfig,
    /// Per-event enable/disable toggles.
    pub event_config: EventConfig,
    /// Per-evidence-type weight overrides.
    pub evidence_config: EvidenceConfig,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            cortex_db_path: None,
            drift_db_path: None,
            enabled: true,
            license_tier: LicenseTier::Community,
            grounding: GroundingConfig::default(),
            event_config: EventConfig::default(),
            evidence_config: EvidenceConfig::default(),
        }
    }
}
