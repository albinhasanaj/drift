//! Per-feature tier matrix: maps every bridge feature to its minimum required tier.
//!
//! Replaces the ad-hoc string matching in gating.rs with a comprehensive,
//! exhaustive feature matrix.

use super::gating::LicenseTier;

/// A bridge feature with its minimum required license tier.
#[derive(Debug, Clone)]
pub struct FeatureEntry {
    /// Feature identifier (used in license checks).
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Minimum tier required.
    pub min_tier: LicenseTier,
    /// Whether this feature is metered (has usage limits) at Community tier.
    pub metered: bool,
}

/// The complete feature matrix for the bridge.
pub const FEATURE_MATRIX: &[FeatureEntry] = &[
    // --- Event Mapping ---
    FeatureEntry {
        name: "event_mapping_basic",
        description: "Basic event→memory mapping (12 Community events)",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    FeatureEntry {
        name: "event_mapping_advanced",
        description: "Advanced event→memory mapping (9 Team/Enterprise events)",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "event_dedup",
        description: "Content-hash deduplication",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    // --- Grounding ---
    FeatureEntry {
        name: "grounding_basic",
        description: "Basic grounding loop (max 100 memories)",
        min_tier: LicenseTier::Community,
        metered: true,
    },
    FeatureEntry {
        name: "grounding_full",
        description: "Full grounding loop (max 500 memories)",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "grounding_unlimited",
        description: "Unlimited grounding loop",
        min_tier: LicenseTier::Enterprise,
        metered: false,
    },
    FeatureEntry {
        name: "active_evidence_collection",
        description: "Active evidence collection from drift.db",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "contradiction_generation",
        description: "Automatic contradiction memory creation",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    // --- Causal ---
    FeatureEntry {
        name: "causal_edges",
        description: "Causal edge creation and traversal",
        min_tier: LicenseTier::Community,
        metered: true,
    },
    FeatureEntry {
        name: "counterfactual",
        description: "Counterfactual analysis (what-if-removed)",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "intervention",
        description: "Intervention analysis (what-if-changed)",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "causal_pruning",
        description: "Automatic causal edge pruning",
        min_tier: LicenseTier::Enterprise,
        metered: false,
    },
    FeatureEntry {
        name: "unified_narrative",
        description: "Unified causal narrative generation",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    // --- Specification ---
    FeatureEntry {
        name: "spec_corrections",
        description: "Specification correction processing",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    FeatureEntry {
        name: "adaptive_weights",
        description: "Adaptive weight computation with decay",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "weight_persistence",
        description: "Persistent adaptive weight storage",
        min_tier: LicenseTier::Enterprise,
        metered: false,
    },
    // --- Tools ---
    FeatureEntry {
        name: "drift_why",
        description: "MCP drift_why tool",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    FeatureEntry {
        name: "drift_memory_learn",
        description: "MCP drift_memory_learn tool",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    FeatureEntry {
        name: "drift_grounding_check",
        description: "MCP drift_grounding_check tool",
        min_tier: LicenseTier::Community,
        metered: true,
    },
    FeatureEntry {
        name: "drift_counterfactual",
        description: "MCP drift_counterfactual tool",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "drift_intervention",
        description: "MCP drift_intervention tool",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "drift_health",
        description: "MCP drift_health tool",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    // --- Infrastructure ---
    FeatureEntry {
        name: "cross_db_queries",
        description: "Cross-database ATTACH queries",
        min_tier: LicenseTier::Community,
        metered: false,
    },
    FeatureEntry {
        name: "data_retention",
        description: "Configurable data retention policies",
        min_tier: LicenseTier::Team,
        metered: false,
    },
    FeatureEntry {
        name: "health_monitoring",
        description: "Bridge health monitoring and readiness probes",
        min_tier: LicenseTier::Community,
        metered: false,
    },
];

/// Look up a feature by name.
pub fn lookup_feature(name: &str) -> Option<&'static FeatureEntry> {
    FEATURE_MATRIX.iter().find(|f| f.name == name)
}

/// Check if a feature is allowed at the given tier.
pub fn is_allowed(name: &str, tier: &LicenseTier) -> bool {
    match lookup_feature(name) {
        Some(entry) => tier.level() >= entry.min_tier.level(),
        None => false, // Unknown features are denied
    }
}

/// Get all features available at a given tier.
pub fn features_for_tier(tier: &LicenseTier) -> Vec<&'static FeatureEntry> {
    FEATURE_MATRIX
        .iter()
        .filter(|f| tier.level() >= f.min_tier.level())
        .collect()
}

/// Get all metered features at a given tier.
pub fn metered_features(tier: &LicenseTier) -> Vec<&'static FeatureEntry> {
    FEATURE_MATRIX
        .iter()
        .filter(|f| f.metered && tier.level() >= f.min_tier.level())
        .collect()
}

impl LicenseTier {
    /// Numeric level for comparison.
    pub fn level(&self) -> u8 {
        match self {
            LicenseTier::Community => 0,
            LicenseTier::Team => 1,
            LicenseTier::Enterprise => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_has_basic_features() {
        assert!(is_allowed("event_mapping_basic", &LicenseTier::Community));
        assert!(is_allowed("drift_why", &LicenseTier::Community));
        assert!(is_allowed("drift_health", &LicenseTier::Community));
    }

    #[test]
    fn test_community_blocked_from_team_features() {
        assert!(!is_allowed("counterfactual", &LicenseTier::Community));
        assert!(!is_allowed("intervention", &LicenseTier::Community));
        assert!(!is_allowed("adaptive_weights", &LicenseTier::Community));
    }

    #[test]
    fn test_enterprise_has_all_features() {
        for entry in FEATURE_MATRIX {
            assert!(
                is_allowed(entry.name, &LicenseTier::Enterprise),
                "Enterprise should have access to {}",
                entry.name
            );
        }
    }

    #[test]
    fn test_unknown_feature_denied() {
        assert!(!is_allowed("nonexistent_feature", &LicenseTier::Enterprise));
    }

    #[test]
    fn test_feature_count() {
        assert!(FEATURE_MATRIX.len() >= 20, "Expected at least 20 features");
    }

    #[test]
    fn test_metered_features_community() {
        let metered = metered_features(&LicenseTier::Community);
        assert!(!metered.is_empty(), "Community should have metered features");
    }
}
