//! 3-tier feature gating: Community, Team, Enterprise.
//!
//! - Community: 5 event types mapped, manual grounding only
//! - Team: all 21 events, scheduled grounding, MCP tools
//! - Enterprise: full grounding loop, contradiction generation, cross-DB analytics

use serde::{Deserialize, Serialize};

/// License tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseTier {
    #[default]
    Community,
    Team,
    Enterprise,
}

/// Feature gate check results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    Allowed,
    Denied,
}

impl LicenseTier {
    /// Check if a feature is allowed at this tier.
    ///
    /// Routes through `feature_matrix::is_allowed()` as the single source of truth,
    /// with a legacy fallback for features not yet in the matrix.
    pub fn check(&self, feature: &str) -> FeatureGate {
        if super::feature_matrix::is_allowed(feature, self) {
            FeatureGate::Allowed
        } else {
            // Fall back to legacy matching for features not yet in the matrix
            match feature {
                "event_mapping_basic" | "manual_grounding" => FeatureGate::Allowed,
                "event_mapping_full" | "scheduled_grounding" | "mcp_tools" => {
                    if matches!(self, Self::Team | Self::Enterprise) {
                        FeatureGate::Allowed
                    } else {
                        FeatureGate::Denied
                    }
                }
                "full_grounding_loop" | "contradiction_generation" | "cross_db_analytics"
                | "adaptive_weights" | "decomposition_transfer" | "causal_corrections" => {
                    if matches!(self, Self::Enterprise) {
                        FeatureGate::Allowed
                    } else {
                        FeatureGate::Denied
                    }
                }
                _ => FeatureGate::Denied,
            }
        }
    }

    /// Get the maximum number of event types for this tier.
    pub fn max_event_types(&self) -> usize {
        match self {
            Self::Community => 5,
            Self::Team => 21,
            Self::Enterprise => 21,
        }
    }

    /// Check if scheduled grounding is allowed.
    pub fn allows_scheduled_grounding(&self) -> bool {
        matches!(self, Self::Team | Self::Enterprise)
    }

    /// Check if the full grounding loop (with contradiction generation) is allowed.
    pub fn allows_full_grounding(&self) -> bool {
        matches!(self, Self::Enterprise)
    }

    /// Check if MCP tools are available.
    pub fn allows_mcp_tools(&self) -> bool {
        matches!(self, Self::Team | Self::Enterprise)
    }

    /// Check if cross-DB analytics are available.
    pub fn allows_cross_db_analytics(&self) -> bool {
        matches!(self, Self::Enterprise)
    }
}
