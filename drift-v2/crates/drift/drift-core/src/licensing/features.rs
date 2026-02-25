//! 16 gated features mapped to 3 license tiers.
//!
//! Community (free): Core analysis, pattern detection, call graph, boundaries, quality gates
//! Team: Advanced analysis, CI integration, scheduled grounding, MCP tools
//! Enterprise: Taint analysis, full grounding, contradiction gen, cross-DB, telemetry, custom detectors, export

use serde::{Deserialize, Serialize};

use crate::config::license_config::LicenseTier;

/// All 16 gated features in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GatedFeature {
    // ── Community (5) ──────────────────────────────────────────
    CoreAnalysis,
    PatternDetection,
    CallGraph,
    BoundaryDetection,
    QualityGates,

    // ── Team (4) ───────────────────────────────────────────────
    AdvancedAnalysis,
    CiIntegration,
    ScheduledGrounding,
    McpTools,

    // ── Enterprise (7) ─────────────────────────────────────────
    TaintAnalysis,
    FullGroundingLoop,
    ContradictionGeneration,
    CrossDbAnalytics,
    Telemetry,
    CustomDetectors,
    ExportImport,
}

impl GatedFeature {
    /// All 16 features.
    pub const ALL: [GatedFeature; 16] = [
        Self::CoreAnalysis,
        Self::PatternDetection,
        Self::CallGraph,
        Self::BoundaryDetection,
        Self::QualityGates,
        Self::AdvancedAnalysis,
        Self::CiIntegration,
        Self::ScheduledGrounding,
        Self::McpTools,
        Self::TaintAnalysis,
        Self::FullGroundingLoop,
        Self::ContradictionGeneration,
        Self::CrossDbAnalytics,
        Self::Telemetry,
        Self::CustomDetectors,
        Self::ExportImport,
    ];

    /// Community-tier features (5).
    pub const COMMUNITY: [GatedFeature; 5] = [
        Self::CoreAnalysis,
        Self::PatternDetection,
        Self::CallGraph,
        Self::BoundaryDetection,
        Self::QualityGates,
    ];

    /// Team-tier features (community + 4 = 9 total).
    pub const TEAM: [GatedFeature; 4] = [
        Self::AdvancedAnalysis,
        Self::CiIntegration,
        Self::ScheduledGrounding,
        Self::McpTools,
    ];

    /// Enterprise-tier features (team + 7 = 16 total).
    pub const ENTERPRISE: [GatedFeature; 7] = [
        Self::TaintAnalysis,
        Self::FullGroundingLoop,
        Self::ContradictionGeneration,
        Self::CrossDbAnalytics,
        Self::Telemetry,
        Self::CustomDetectors,
        Self::ExportImport,
    ];

    /// Minimum tier required for this feature.
    pub fn min_tier(&self) -> LicenseTier {
        match self {
            Self::CoreAnalysis
            | Self::PatternDetection
            | Self::CallGraph
            | Self::BoundaryDetection
            | Self::QualityGates => LicenseTier::Community,

            Self::AdvancedAnalysis
            | Self::CiIntegration
            | Self::ScheduledGrounding
            | Self::McpTools => LicenseTier::Team,

            Self::TaintAnalysis
            | Self::FullGroundingLoop
            | Self::ContradictionGeneration
            | Self::CrossDbAnalytics
            | Self::Telemetry
            | Self::CustomDetectors
            | Self::ExportImport => LicenseTier::Enterprise,
        }
    }

    /// Feature name as string (for config, logging, NAPI).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CoreAnalysis => "core_analysis",
            Self::PatternDetection => "pattern_detection",
            Self::CallGraph => "call_graph",
            Self::BoundaryDetection => "boundary_detection",
            Self::QualityGates => "quality_gates",
            Self::AdvancedAnalysis => "advanced_analysis",
            Self::CiIntegration => "ci_integration",
            Self::ScheduledGrounding => "scheduled_grounding",
            Self::McpTools => "mcp_tools",
            Self::TaintAnalysis => "taint_analysis",
            Self::FullGroundingLoop => "full_grounding_loop",
            Self::ContradictionGeneration => "contradiction_generation",
            Self::CrossDbAnalytics => "cross_db_analytics",
            Self::Telemetry => "telemetry",
            Self::CustomDetectors => "custom_detectors",
            Self::ExportImport => "export_import",
        }
    }

    /// Parse feature from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "core_analysis" => Some(Self::CoreAnalysis),
            "pattern_detection" => Some(Self::PatternDetection),
            "call_graph" => Some(Self::CallGraph),
            "boundary_detection" => Some(Self::BoundaryDetection),
            "quality_gates" => Some(Self::QualityGates),
            "advanced_analysis" => Some(Self::AdvancedAnalysis),
            "ci_integration" => Some(Self::CiIntegration),
            "scheduled_grounding" => Some(Self::ScheduledGrounding),
            "mcp_tools" => Some(Self::McpTools),
            "taint_analysis" => Some(Self::TaintAnalysis),
            "full_grounding_loop" => Some(Self::FullGroundingLoop),
            "contradiction_generation" => Some(Self::ContradictionGeneration),
            "cross_db_analytics" => Some(Self::CrossDbAnalytics),
            "telemetry" => Some(Self::Telemetry),
            "custom_detectors" => Some(Self::CustomDetectors),
            "export_import" => Some(Self::ExportImport),
            _ => None,
        }
    }

    /// Human-readable description for upgrade messages.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CoreAnalysis => "Core code analysis (scanning, parsing, persistence)",
            Self::PatternDetection => "Convention and pattern detection",
            Self::CallGraph => "Call graph construction and analysis",
            Self::BoundaryDetection => "Architectural boundary detection",
            Self::QualityGates => "Quality gate enforcement",
            Self::AdvancedAnalysis => "Advanced analysis (conventions, coupling, complexity)",
            Self::CiIntegration => "CI/CD pipeline integration (SARIF, CI agents)",
            Self::ScheduledGrounding => "Scheduled grounding loop execution",
            Self::McpTools => "MCP server tools for AI assistants",
            Self::TaintAnalysis => "Taint analysis (OWASP compliance)",
            Self::FullGroundingLoop => "Full grounding feedback loop",
            Self::ContradictionGeneration => "Contradiction and hypothesis generation",
            Self::CrossDbAnalytics => "Cross-database analytics",
            Self::Telemetry => "Usage telemetry and analytics",
            Self::CustomDetectors => "Custom detector authoring",
            Self::ExportImport => "Workspace export/import",
        }
    }
}

/// Check if a tier grants access to a feature.
pub fn tier_allows(tier: &LicenseTier, feature: &GatedFeature) -> bool {
    match tier {
        LicenseTier::Enterprise => true,
        LicenseTier::Team => {
            matches!(
                feature,
                GatedFeature::CoreAnalysis
                    | GatedFeature::PatternDetection
                    | GatedFeature::CallGraph
                    | GatedFeature::BoundaryDetection
                    | GatedFeature::QualityGates
                    | GatedFeature::AdvancedAnalysis
                    | GatedFeature::CiIntegration
                    | GatedFeature::ScheduledGrounding
                    | GatedFeature::McpTools
            )
        }
        LicenseTier::Community => {
            matches!(
                feature,
                GatedFeature::CoreAnalysis
                    | GatedFeature::PatternDetection
                    | GatedFeature::CallGraph
                    | GatedFeature::BoundaryDetection
                    | GatedFeature::QualityGates
            )
        }
    }
}

/// Get all features available at a given tier.
pub fn features_for_tier(tier: &LicenseTier) -> Vec<GatedFeature> {
    GatedFeature::ALL
        .iter()
        .copied()
        .filter(|f| tier_allows(tier, f))
        .collect()
}
