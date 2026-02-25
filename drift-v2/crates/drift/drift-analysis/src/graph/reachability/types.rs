//! Reachability types — results, sensitivity categories, engine selection.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

/// Result of a reachability query.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    /// The source node from which reachability was computed.
    pub source: NodeIndex,
    /// Set of all reachable nodes (excluding source).
    pub reachable: FxHashSet<NodeIndex>,
    /// Sensitivity classification of the reachability result.
    pub sensitivity: SensitivityCategory,
    /// Maximum depth reached during BFS.
    pub max_depth: u32,
    /// Which engine was used for the computation.
    pub engine: ReachabilityEngine,
}

/// Sensitivity classification based on what data flows are reachable.
///
/// - Critical: user input → SQL/command execution
/// - High: user input → file/network operations
/// - Medium: admin → sensitive operations
/// - Low: internal only, no external input
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityCategory {
    /// User input reaches SQL queries or command execution.
    Critical,
    /// User input reaches file or network operations.
    High,
    /// Admin-only input reaches sensitive operations.
    Medium,
    /// Internal-only data flow, no external input.
    Low,
}

impl SensitivityCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Numeric severity for ordering (higher = more severe).
    pub fn severity(&self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }
}

impl std::fmt::Display for SensitivityCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Which BFS engine was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReachabilityEngine {
    /// In-memory petgraph BFS — used for graphs <10K nodes.
    Petgraph,
    /// SQLite recursive CTE — used for graphs ≥10K nodes.
    SqliteCte,
}

impl ReachabilityEngine {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Petgraph => "petgraph",
            Self::SqliteCte => "sqlite_cte",
        }
    }
}

impl std::fmt::Display for ReachabilityEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Direction of BFS traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraversalDirection {
    /// Forward: find all functions reachable from source.
    Forward,
    /// Inverse: find all callers that can reach source.
    Inverse,
}
