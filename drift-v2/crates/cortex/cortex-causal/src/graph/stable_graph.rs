//! petgraph::StableGraph wrapper with CausalNode and CausalEdgeWeight types.

use std::collections::HashMap;

use petgraph::stable_graph::{NodeIndex, StableGraph};
use petgraph::Directed;
use serde::{Deserialize, Serialize};

use crate::relations::CausalRelation;

/// A node in the causal graph, representing a memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalNode {
    /// The memory ID this node represents.
    pub memory_id: String,
    /// The memory type (e.g. "core", "decision").
    pub memory_type: String,
    /// Short summary of the memory.
    pub summary: String,
}

/// Evidence supporting a causal edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeEvidence {
    pub description: String,
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Weight on a causal edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalEdgeWeight {
    /// The type of causal relation.
    pub relation: CausalRelation,
    /// Strength of the causal link, 0.0–1.0.
    pub strength: f64,
    /// Evidence supporting this edge.
    pub evidence: Vec<EdgeEvidence>,
    /// Whether this edge was inferred (vs. explicitly stated).
    pub inferred: bool,
}

/// The underlying directed graph type.
pub type CausalStableGraph = StableGraph<CausalNode, CausalEdgeWeight, Directed>;

/// Wrapper providing indexed access to the causal graph.
pub struct IndexedGraph {
    /// The petgraph stable graph.
    pub graph: CausalStableGraph,
    /// Map from memory_id → NodeIndex for O(1) lookup.
    pub node_index: HashMap<String, NodeIndex>,
}

impl IndexedGraph {
    /// Create an empty indexed graph.
    pub fn new() -> Self {
        Self {
            graph: StableGraph::new(),
            node_index: HashMap::new(),
        }
    }

    /// Get or create a node for the given memory.
    pub fn ensure_node(&mut self, memory_id: &str, memory_type: &str, summary: &str) -> NodeIndex {
        if let Some(&idx) = self.node_index.get(memory_id) {
            return idx;
        }
        let node = CausalNode {
            memory_id: memory_id.to_string(),
            memory_type: memory_type.to_string(),
            summary: summary.to_string(),
        };
        let idx = self.graph.add_node(node);
        self.node_index.insert(memory_id.to_string(), idx);
        idx
    }

    /// Look up a node index by memory ID.
    pub fn get_node(&self, memory_id: &str) -> Option<NodeIndex> {
        self.node_index.get(memory_id).copied()
    }

    /// Remove a node and all its edges.
    pub fn remove_node(&mut self, memory_id: &str) -> bool {
        if let Some(idx) = self.node_index.remove(memory_id) {
            self.graph.remove_node(idx);
            true
        } else {
            false
        }
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}

impl Default for IndexedGraph {
    fn default() -> Self {
        Self::new()
    }
}
