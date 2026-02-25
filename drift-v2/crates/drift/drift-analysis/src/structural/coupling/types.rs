//! Coupling analysis types — Martin metrics, zones, cycles.

use drift_core::types::collections::FxHashMap;
use serde::{Deserialize, Serialize};

/// Robert C. Martin coupling metrics for a single module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouplingMetrics {
    /// Module identifier (directory path or logical module name).
    pub module: String,
    /// Efferent coupling: number of modules this module depends on.
    pub ce: u32,
    /// Afferent coupling: number of modules that depend on this module.
    pub ca: u32,
    /// Instability: Ce / (Ce + Ca). Range [0, 1]. 1 = maximally unstable.
    pub instability: f64,
    /// Abstractness: ratio of abstract types to total types. Range [0, 1].
    pub abstractness: f64,
    /// Distance from main sequence: |A + I - 1|. Range [0, 1]. 0 = ideal.
    pub distance: f64,
    /// Zone classification based on (I, A) coordinates.
    pub zone: ZoneClassification,
}

/// Zone classification on the (I, A) plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZoneClassification {
    /// High Ca, low A — concrete and heavily depended upon. Hard to change.
    ZoneOfPain,
    /// Low Ca, high A — abstract but nobody uses it. Wasted abstraction.
    ZoneOfUselessness,
    /// Near the main sequence line (A + I ≈ 1). Balanced.
    MainSequence,
}

impl ZoneClassification {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ZoneOfPain => "zone_of_pain",
            Self::ZoneOfUselessness => "zone_of_uselessness",
            Self::MainSequence => "main_sequence",
        }
    }
}

impl std::fmt::Display for ZoneClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A detected dependency cycle (strongly connected component with >1 node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleInfo {
    /// Modules participating in the cycle.
    pub members: Vec<String>,
    /// Suggested edges to break to eliminate the cycle.
    pub break_suggestions: Vec<CycleBreakSuggestion>,
}

/// A suggestion for breaking a dependency cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleBreakSuggestion {
    /// Source module of the edge to remove.
    pub from: String,
    /// Target module of the edge to remove.
    pub to: String,
    /// Estimated impact of removing this edge (lower = easier to break).
    pub impact_score: f64,
}

/// The import graph: directed edges between modules.
#[derive(Debug, Clone, Default)]
pub struct ImportGraph {
    /// Module name → set of modules it imports from.
    pub edges: FxHashMap<String, Vec<String>>,
    /// All known module names.
    pub modules: Vec<String>,
    /// Abstract type counts per module (for abstractness calculation).
    pub abstract_counts: FxHashMap<String, u32>,
    /// Total type counts per module.
    pub total_type_counts: FxHashMap<String, u32>,
}

/// Trend direction for coupling metrics over time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Degrading,
    Stable,
}

/// Coupling trend between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouplingTrend {
    pub module: String,
    pub previous: CouplingMetrics,
    pub current: CouplingMetrics,
    pub direction: TrendDirection,
}

/// Full coupling analysis result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CouplingAnalysisResult {
    pub metrics: Vec<CouplingMetrics>,
    pub cycles: Vec<CycleInfo>,
    pub module_count: usize,
}
