//! Traversal engine: configurable graph traversal with depth, strength, and node limits.

pub mod bidirectional;
pub mod counterfactual;
pub mod intervention;
pub mod neighbors;
pub mod trace_effects;
pub mod trace_origins;

/// Configuration for traversal operations.
#[derive(Debug, Clone)]
pub struct TraversalConfig {
    /// Maximum traversal depth.
    pub max_depth: usize,
    /// Minimum edge strength to follow.
    pub min_strength: f64,
    /// Maximum nodes to return.
    pub max_nodes: usize,
}

impl Default for TraversalConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            min_strength: 0.3,
            max_nodes: 50,
        }
    }
}

/// A node in a traversal result.
#[derive(Debug, Clone)]
pub struct TraversalNode {
    pub memory_id: String,
    pub depth: usize,
    pub path_strength: f64,
}

/// Result of a traversal operation.
#[derive(Debug, Clone)]
pub struct TraversalResult {
    /// The starting node.
    pub origin_id: String,
    /// Nodes discovered during traversal.
    pub nodes: Vec<TraversalNode>,
    /// Maximum depth actually reached.
    pub max_depth_reached: usize,
}

/// The traversal engine wraps all traversal operations.
pub struct TraversalEngine {
    pub config: TraversalConfig,
}

impl TraversalEngine {
    pub fn new(config: TraversalConfig) -> Self {
        Self { config }
    }

    /// Trace origins: "what caused this?"
    pub fn trace_origins(
        &self,
        graph: &crate::graph::stable_graph::IndexedGraph,
        memory_id: &str,
    ) -> TraversalResult {
        trace_origins::trace(graph, memory_id, &self.config)
    }

    /// Trace effects: "what did this cause?"
    pub fn trace_effects(
        &self,
        graph: &crate::graph::stable_graph::IndexedGraph,
        memory_id: &str,
    ) -> TraversalResult {
        trace_effects::trace(graph, memory_id, &self.config)
    }

    /// Bidirectional: union of forward + backward.
    pub fn bidirectional(
        &self,
        graph: &crate::graph::stable_graph::IndexedGraph,
        memory_id: &str,
    ) -> TraversalResult {
        bidirectional::trace(graph, memory_id, &self.config)
    }

    /// Direct neighbors (depth=1).
    pub fn neighbors(
        &self,
        graph: &crate::graph::stable_graph::IndexedGraph,
        memory_id: &str,
    ) -> TraversalResult {
        neighbors::get(graph, memory_id, &self.config)
    }

    /// Counterfactual: "what if we hadn't adopted pattern X?"
    pub fn counterfactual(
        &self,
        graph: &crate::graph::stable_graph::IndexedGraph,
        memory_id: &str,
    ) -> TraversalResult {
        counterfactual::analyze(graph, memory_id, &self.config)
    }

    /// Intervention: "if we change convention X, what needs updating?"
    pub fn intervention(
        &self,
        graph: &crate::graph::stable_graph::IndexedGraph,
        memory_id: &str,
    ) -> TraversalResult {
        intervention::analyze(graph, memory_id, &self.config)
    }
}

impl Default for TraversalEngine {
    fn default() -> Self {
        Self::new(TraversalConfig::default())
    }
}
