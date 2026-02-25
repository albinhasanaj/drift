//! Impact analysis types — blast radius, risk scoring, dead code.

use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

/// Blast radius for a function — how many other functions are affected by a change.
#[derive(Debug, Clone)]
pub struct BlastRadius {
    /// The function being analyzed.
    pub function_id: NodeIndex,
    /// All transitive callers (functions affected by a change).
    pub transitive_callers: Vec<NodeIndex>,
    /// Count of transitive callers.
    pub caller_count: u32,
    /// Composite risk score.
    pub risk_score: RiskScore,
    /// Maximum depth in the caller chain.
    pub max_depth: u32,
}

/// 5-factor risk score for a function.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RiskScore {
    /// Blast radius factor (0.0-1.0): normalized caller count.
    pub blast_radius: f32,
    /// Sensitivity factor (0.0-1.0): data sensitivity of reachable operations.
    pub sensitivity: f32,
    /// Test coverage factor (0.0-1.0): how well-tested this function is.
    pub test_coverage: f32,
    /// Complexity factor (0.0-1.0): cyclomatic/cognitive complexity.
    pub complexity: f32,
    /// Change frequency factor (0.0-1.0): how often this function changes.
    pub change_frequency: f32,
    /// Weighted aggregate score.
    pub overall: f32,
}

impl RiskScore {
    /// Compute the overall risk score from individual factors.
    pub fn compute(
        blast_radius: f32,
        sensitivity: f32,
        test_coverage: f32,
        complexity: f32,
        change_frequency: f32,
    ) -> Self {
        // Weights: blast_radius=0.30, sensitivity=0.25, test_coverage=0.20,
        //          complexity=0.15, change_frequency=0.10
        let overall = blast_radius * 0.30
            + sensitivity * 0.25
            + (1.0 - test_coverage) * 0.20 // Invert: low coverage = high risk
            + complexity * 0.15
            + change_frequency * 0.10;

        Self {
            blast_radius,
            sensitivity,
            test_coverage,
            complexity,
            change_frequency,
            overall: overall.clamp(0.0, 1.0),
        }
    }
}

impl Default for RiskScore {
    fn default() -> Self {
        Self {
            blast_radius: 0.0,
            sensitivity: 0.0,
            test_coverage: 0.0,
            complexity: 0.0,
            change_frequency: 0.0,
            overall: 0.0,
        }
    }
}

/// Result of dead code detection for a function.
#[derive(Debug, Clone)]
pub struct DeadCodeResult {
    /// The function identified as potentially dead.
    pub function_id: NodeIndex,
    /// Reason it was flagged.
    pub reason: DeadCodeReason,
    /// If excluded, which category.
    pub exclusion: Option<DeadCodeExclusion>,
    /// Whether this is actually dead (false if excluded).
    pub is_dead: bool,
    /// CG-DC-04: Confidence score (0.0-1.0). Lower when resolution rate is poor.
    pub confidence: f32,
}

/// Why a function was flagged as dead code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeadCodeReason {
    /// No callers in the call graph.
    NoCallers,
    /// No path from any entry point.
    NoEntryPath,
}

impl DeadCodeReason {
    pub fn name(&self) -> &'static str {
        match self {
            Self::NoCallers => "no_callers",
            Self::NoEntryPath => "no_entry_path",
        }
    }
}

/// 10 false-positive exclusion categories for dead code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeadCodeExclusion {
    /// Entry points (main, index, exported).
    EntryPoint,
    /// Event handlers (on_*, handle_*).
    EventHandler,
    /// Reflection targets.
    ReflectionTarget,
    /// Dependency injection.
    DependencyInjection,
    /// Test utilities.
    TestUtility,
    /// Framework hooks (lifecycle methods).
    FrameworkHook,
    /// Decorators/annotations.
    DecoratorTarget,
    /// Interface implementations.
    InterfaceImpl,
    /// Conditional compilation (#[cfg], #ifdef).
    ConditionalCompilation,
    /// Dynamic imports.
    DynamicImport,
}

impl DeadCodeExclusion {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EntryPoint => "entry_point",
            Self::EventHandler => "event_handler",
            Self::ReflectionTarget => "reflection_target",
            Self::DependencyInjection => "dependency_injection",
            Self::TestUtility => "test_utility",
            Self::FrameworkHook => "framework_hook",
            Self::DecoratorTarget => "decorator_target",
            Self::InterfaceImpl => "interface_impl",
            Self::ConditionalCompilation => "conditional_compilation",
            Self::DynamicImport => "dynamic_import",
        }
    }

    /// All 10 exclusion categories.
    pub fn all() -> &'static [DeadCodeExclusion] {
        &[
            Self::EntryPoint,
            Self::EventHandler,
            Self::ReflectionTarget,
            Self::DependencyInjection,
            Self::TestUtility,
            Self::FrameworkHook,
            Self::DecoratorTarget,
            Self::InterfaceImpl,
            Self::ConditionalCompilation,
            Self::DynamicImport,
        ]
    }
}

/// A path between two functions in the call graph.
#[derive(Debug, Clone)]
pub struct FunctionPath {
    /// Ordered list of nodes in the path.
    pub nodes: Vec<NodeIndex>,
    /// Total weight (sum of edge weights).
    pub weight: f32,
}
