//! Graph management: Arc<RwLock<StableGraph>> with DAG enforcement, sync, and pruning.

pub mod cross_agent;
pub mod dag_enforcement;
pub mod pruning;
pub mod stable_graph;
pub mod sync;
pub mod temporal_graph;

use std::sync::{Arc, RwLock};

use cortex_core::errors::{CortexError, CortexResult};

use self::stable_graph::{CausalEdgeWeight, IndexedGraph};

/// Thread-safe graph manager wrapping the indexed causal graph.
pub struct GraphManager {
    inner: Arc<RwLock<IndexedGraph>>,
}

impl GraphManager {
    /// Create a new empty graph manager.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(IndexedGraph::new())),
        }
    }

    /// Create from an existing indexed graph.
    pub fn from_graph(graph: IndexedGraph) -> Self {
        Self {
            inner: Arc::new(RwLock::new(graph)),
        }
    }

    /// Get a clone of the Arc for shared access.
    pub fn shared(&self) -> Arc<RwLock<IndexedGraph>> {
        Arc::clone(&self.inner)
    }

    /// Add a node to the graph. Returns true if newly added.
    pub fn add_node(
        &self,
        memory_id: &str,
        memory_type: &str,
        summary: &str,
    ) -> CortexResult<bool> {
        let mut graph = self.write()?;
        let existed = graph.get_node(memory_id).is_some();
        graph.ensure_node(memory_id, memory_type, summary);
        Ok(!existed)
    }

    /// Add an edge with DAG enforcement. Returns error if it would create a cycle.
    pub fn add_edge(
        &self,
        source_id: &str,
        target_id: &str,
        source_type: &str,
        target_type: &str,
        weight: CausalEdgeWeight,
    ) -> CortexResult<()> {
        let mut graph = self.write()?;

        let source_idx = graph.ensure_node(source_id, source_type, "");
        let target_idx = graph.ensure_node(target_id, target_type, "");

        // DAG enforcement: reject if adding this edge would create a cycle.
        if dag_enforcement::would_create_cycle(&graph, source_idx, target_idx) {
            return Err(CortexError::CausalCycle {
                path: format!("{} -> {}", source_id, target_id),
            });
        }

        graph.graph.add_edge(source_idx, target_idx, weight);
        Ok(())
    }

    /// Remove an edge between two nodes.
    pub fn remove_edge(&self, source_id: &str, target_id: &str) -> CortexResult<bool> {
        let mut graph = self.write()?;
        let source_idx = match graph.get_node(source_id) {
            Some(idx) => idx,
            None => return Ok(false),
        };
        let target_idx = match graph.get_node(target_id) {
            Some(idx) => idx,
            None => return Ok(false),
        };

        if let Some(edge_idx) = graph.graph.find_edge(source_idx, target_idx) {
            graph.graph.remove_edge(edge_idx);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get all edges for a node (both incoming and outgoing).
    pub fn get_edges(
        &self,
        memory_id: &str,
    ) -> CortexResult<Vec<(String, String, CausalEdgeWeight)>> {
        let graph = self.read()?;
        let mut edges = Vec::new();

        if let Some(idx) = graph.get_node(memory_id) {
            use petgraph::Direction;

            // Outgoing edges
            for neighbor in graph.graph.neighbors_directed(idx, Direction::Outgoing) {
                if let Some(edge_idx) = graph.graph.find_edge(idx, neighbor) {
                    if let (Some(weight), Some(target_node)) = (
                        graph.graph.edge_weight(edge_idx),
                        graph.graph.node_weight(neighbor),
                    ) {
                        edges.push((
                            memory_id.to_string(),
                            target_node.memory_id.clone(),
                            weight.clone(),
                        ));
                    }
                }
            }

            // Incoming edges
            for neighbor in graph.graph.neighbors_directed(idx, Direction::Incoming) {
                if let Some(edge_idx) = graph.graph.find_edge(neighbor, idx) {
                    if let (Some(weight), Some(source_node)) = (
                        graph.graph.edge_weight(edge_idx),
                        graph.graph.node_weight(neighbor),
                    ) {
                        edges.push((
                            source_node.memory_id.clone(),
                            memory_id.to_string(),
                            weight.clone(),
                        ));
                    }
                }
            }
        }

        Ok(edges)
    }

    /// Get node count.
    pub fn node_count(&self) -> CortexResult<usize> {
        Ok(self.read()?.node_count())
    }

    /// Get edge count.
    pub fn edge_count(&self) -> CortexResult<usize> {
        Ok(self.read()?.edge_count())
    }

    /// Run a full pruning pass.
    pub fn prune(&self, min_strength: f64) -> CortexResult<pruning::PruneResult> {
        let mut graph = self.write()?;
        Ok(pruning::full_cleanup(&mut graph, min_strength))
    }

    /// Read lock helper.
    fn read(&self) -> CortexResult<std::sync::RwLockReadGuard<'_, IndexedGraph>> {
        self.inner
            .read()
            .map_err(|e| CortexError::ConcurrencyError(e.to_string()))
    }

    /// Write lock helper.
    fn write(&self) -> CortexResult<std::sync::RwLockWriteGuard<'_, IndexedGraph>> {
        self.inner
            .write()
            .map_err(|e| CortexError::ConcurrencyError(e.to_string()))
    }
}

impl Default for GraphManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for GraphManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
