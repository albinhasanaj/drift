//! Bidirectional traversal: union of forward (effects) + backward (origins).

use std::collections::HashSet;

use crate::graph::stable_graph::IndexedGraph;

use super::{trace_effects, trace_origins, TraversalConfig, TraversalResult};

/// Trace both directions and return the union.
pub fn trace(graph: &IndexedGraph, memory_id: &str, config: &TraversalConfig) -> TraversalResult {
    let origins = trace_origins::trace(graph, memory_id, config);
    let effects = trace_effects::trace(graph, memory_id, config);

    // Union: deduplicate by memory_id, keeping the entry with the shorter depth.
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut max_depth = 0;

    for node in origins.nodes.iter().chain(effects.nodes.iter()) {
        if seen.insert(node.memory_id.clone()) {
            nodes.push(node.clone());
            max_depth = max_depth.max(node.depth);
        }
    }

    // Enforce max_nodes limit.
    nodes.truncate(config.max_nodes);

    TraversalResult {
        origin_id: memory_id.to_string(),
        nodes,
        max_depth_reached: max_depth,
    }
}
