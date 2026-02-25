//! Counterfactual analysis: "what if we hadn't adopted pattern X?"
//! Identifies all downstream effects that would be impacted if a memory were removed.

use crate::graph::stable_graph::IndexedGraph;

use super::{trace_effects, TraversalConfig, TraversalResult};

/// Analyze the counterfactual: what downstream memories depend on this one?
/// This is essentially a forward traversal that identifies the "blast radius"
/// of removing a memory from the causal graph.
pub fn analyze(graph: &IndexedGraph, memory_id: &str, config: &TraversalConfig) -> TraversalResult {
    // A counterfactual is the forward trace: everything this memory caused.
    // If we remove it, all these downstream effects are potentially impacted.
    trace_effects::trace(graph, memory_id, config)
}
