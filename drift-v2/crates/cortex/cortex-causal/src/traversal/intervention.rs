//! Intervention analysis: "if we change convention X, what needs updating?"
//! Identifies both upstream dependencies and downstream effects.

use std::collections::HashSet;

use crate::graph::stable_graph::IndexedGraph;

use super::{trace_effects, trace_origins, TraversalConfig, TraversalResult};

/// Analyze the impact of changing a memory.
/// Returns all memories that are causally connected (both causes and effects).
pub fn analyze(graph: &IndexedGraph, memory_id: &str, config: &TraversalConfig) -> TraversalResult {
    // An intervention affects everything downstream (effects)
    // and may invalidate upstream assumptions (origins).
    let effects = trace_effects::trace(graph, memory_id, config);
    let origins = trace_origins::trace(graph, memory_id, config);

    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut max_depth = 0;

    // Effects are the primary concern (what needs updating).
    for node in &effects.nodes {
        if seen.insert(node.memory_id.clone()) {
            nodes.push(node.clone());
            max_depth = max_depth.max(node.depth);
        }
    }

    // Origins provide context (what assumptions led here).
    for node in &origins.nodes {
        if seen.insert(node.memory_id.clone()) {
            nodes.push(node.clone());
            max_depth = max_depth.max(node.depth);
        }
    }

    nodes.truncate(config.max_nodes);

    TraversalResult {
        origin_id: memory_id.to_string(),
        nodes,
        max_depth_reached: max_depth,
    }
}
