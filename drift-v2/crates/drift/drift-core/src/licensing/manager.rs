//! LicenseManager — load, validate, check, hot-reload.
//! Central authority for all feature gating decisions.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use tracing::{info, warn};

use crate::config::license_config::LicenseTier;

use super::features::{tier_allows, GatedFeature};
use super::jwt::{self, LicenseClaims};

/// License state — the resolved license after loading and validation.
#[derive(Debug, Clone)]
pub struct LicenseState {
    pub tier: LicenseTier,
    pub claims: Option<LicenseClaims>,
    pub source: LicenseSource,
    pub status: LicenseStatus,
    pub grace_remaining_days: Option<u64>,
}

/// Where the license was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseSource {
    Default,
    ConfigFile,
    EnvironmentVariable,
    JwtFile(PathBuf),
}

/// Current license status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    Valid,
    Expired,
    GracePeriod { days_remaining: u64 },
    Missing,
    Invalid(String),
}

/// Result of a feature gate check.
#[derive(Debug, Clone)]
pub enum FeatureAccess {
    Allowed,
    Denied {
        feature: GatedFeature,
        required_tier: LicenseTier,
        current_tier: LicenseTier,
        upgrade_url: String,
    },
    GracePeriod {
        feature: GatedFeature,
        days_remaining: u64,
    },
}

impl FeatureAccess {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::GracePeriod { .. })
    }

    pub fn denial_message(&self) -> Option<String> {
        match self {
            Self::Denied {
                feature,
                required_tier,
                upgrade_url,
                ..
            } => Some(format!(
                "Feature '{}' requires {} tier. Upgrade at {}",
                feature.as_str(),
                match required_tier {
                    LicenseTier::Team => "Team",
                    LicenseTier::Enterprise => "Enterprise",
                    _ => "a higher",
                },
                upgrade_url
            )),
            Self::GracePeriod {
                feature,
                days_remaining,
            } => Some(format!(
                "License expired. Feature '{}' available for {} more day(s). Renew to continue.",
                feature.as_str(),
                days_remaining
            )),
            Self::Allowed => None,
        }
    }
}

/// Grace period configuration.
const GRACE_PERIOD_DAYS: u64 = 7;
const DEFAULT_UPGRADE_URL: &str = "https://driftscan.dev/pricing";

/// LicenseManager — thread-safe, hot-reloadable license authority.
pub struct LicenseManager {
    state: RwLock<LicenseState>,
    jwt_path: Option<PathBuf>,
    upgrade_url: String,
}

impl LicenseManager {
    /// Create a new LicenseManager with default (Community) license.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(LicenseState {
                tier: LicenseTier::Community,
                claims: None,
                source: LicenseSource::Default,
                status: LicenseStatus::Valid,
                grace_remaining_days: None,
            }),
            jwt_path: None,
            upgrade_url: DEFAULT_UPGRADE_URL.to_string(),
        }
    }

    /// Load license from all available sources.
    /// Priority: JWT file > env var > config tier > default (Community).
    pub fn load(
        jwt_path: Option<&Path>,
        env_key: Option<&str>,
        config_tier: Option<&LicenseTier>,
        upgrade_url: Option<&str>,
    ) -> Self {
        let upgrade = upgrade_url
            .unwrap_or(DEFAULT_UPGRADE_URL)
            .to_string();

        let mgr = Self {
            state: RwLock::new(LicenseState {
                tier: LicenseTier::Community,
                claims: None,
                source: LicenseSource::Default,
                status: LicenseStatus::Missing,
                grace_remaining_days: None,
            }),
            jwt_path: jwt_path.map(|p| p.to_path_buf()),
            upgrade_url: upgrade,
        };

        // Try JWT file first
        if let Some(path) = jwt_path {
            if let Ok(state) = mgr.load_from_jwt_file(path) {
                *mgr.state.write().unwrap() = state;
                return mgr;
            }
        }

        // Try environment variable
        if let Some(key) = env_key {
            if let Ok(val) = std::env::var(key) {
                if let Ok(state) = mgr.load_from_jwt_string(&val, LicenseSource::EnvironmentVariable)
                {
                    *mgr.state.write().unwrap() = state;
                    return mgr;
                }
            }
        }

        // Fall back to config tier
        if let Some(tier) = config_tier {
            *mgr.state.write().unwrap() = LicenseState {
                tier: tier.clone(),
                claims: None,
                source: LicenseSource::ConfigFile,
                status: LicenseStatus::Valid,
                grace_remaining_days: None,
            };
            return mgr;
        }

        // Default: Community
        *mgr.state.write().unwrap() = LicenseState {
            tier: LicenseTier::Community,
            claims: None,
            source: LicenseSource::Default,
            status: LicenseStatus::Valid,
            grace_remaining_days: None,
        };

        mgr
    }

    /// Check if a feature is allowed under the current license.
    pub fn check_feature(&self, feature: GatedFeature) -> FeatureAccess {
        let state = self.state.read().unwrap();

        // Grace period: allow features that were previously available
        if let LicenseStatus::GracePeriod { days_remaining } = &state.status {
            if tier_allows(&state.tier, &feature) {
                return FeatureAccess::GracePeriod {
                    feature,
                    days_remaining: *days_remaining,
                };
            }
        }

        // Normal check
        if tier_allows(&state.tier, &feature) {
            FeatureAccess::Allowed
        } else {
            FeatureAccess::Denied {
                feature,
                required_tier: feature.min_tier(),
                current_tier: state.tier.clone(),
                upgrade_url: self.upgrade_url.clone(),
            }
        }
    }

    /// Get the current license state (read-only snapshot).
    pub fn state(&self) -> LicenseState {
        self.state.read().unwrap().clone()
    }

    /// Get the current tier.
    pub fn tier(&self) -> LicenseTier {
        self.state.read().unwrap().tier.clone()
    }

    /// Hot-reload: re-read the JWT file and update license state.
    /// Called when the JWT file changes (detected by file watcher or explicit call).
    pub fn reload(&self) -> Result<(), String> {
        let path = self
            .jwt_path
            .as_ref()
            .ok_or_else(|| "No JWT path configured".to_string())?;

        let state = self
            .load_from_jwt_file(path)
            .map_err(|e| format!("Failed to reload license: {}", e))?;

        let tier_label = match &state.tier {
            LicenseTier::Community => "Community",
            LicenseTier::Team => "Team",
            LicenseTier::Enterprise => "Enterprise",
        };
        info!(tier = tier_label, "License reloaded");

        *self.state.write().unwrap() = state;
        Ok(())
    }

    fn load_from_jwt_file(&self, path: &Path) -> Result<LicenseState, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Cannot read JWT file: {}", e))?;
        self.load_from_jwt_string(&content, LicenseSource::JwtFile(path.to_path_buf()))
    }

    fn load_from_jwt_string(
        &self,
        token: &str,
        source: LicenseSource,
    ) -> Result<LicenseState, String> {
        let claims =
            jwt::parse_jwt(token).map_err(|e| format!("JWT parse error: {}", e))?;

        let tier = match claims.tier.as_str() {
            "enterprise" => LicenseTier::Enterprise,
            "team" => LicenseTier::Team,
            _ => LicenseTier::Community,
        };

        // Check expiry
        let status = match jwt::validate_claims(&claims) {
            Ok(()) => LicenseStatus::Valid,
            Err(jwt::JwtError::Expired { .. }) => {
                if jwt::is_in_grace_period(&claims, GRACE_PERIOD_DAYS) {
                    let remaining =
                        (claims.exp + GRACE_PERIOD_DAYS * 86400).saturating_sub(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        )
                            / 86400;
                    warn!(
                        days_remaining = remaining,
                        "License expired but within grace period"
                    );
                    LicenseStatus::GracePeriod {
                        days_remaining: remaining,
                    }
                } else {
                    warn!("License expired and past grace period — downgrading to Community");
                    return Ok(LicenseState {
                        tier: LicenseTier::Community,
                        claims: Some(claims),
                        source,
                        status: LicenseStatus::Expired,
                        grace_remaining_days: Some(0),
                    });
                }
            }
            Err(e) => {
                return Ok(LicenseState {
                    tier: LicenseTier::Community,
                    claims: Some(claims),
                    source,
                    status: LicenseStatus::Invalid(e.to_string()),
                    grace_remaining_days: None,
                });
            }
        };

        let grace_remaining = if let LicenseStatus::GracePeriod { days_remaining } = &status {
            Some(*days_remaining)
        } else {
            None
        };

        Ok(LicenseState {
            tier,
            claims: Some(claims),
            source,
            status,
            grace_remaining_days: grace_remaining,
        })
    }
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new()
    }
}
