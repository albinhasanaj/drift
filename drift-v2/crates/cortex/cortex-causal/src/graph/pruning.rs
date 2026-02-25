//! Prune weak edges (strength < threshold), old unvalidated edges, and periodic cleanup.

use petgraph::stable_graph::EdgeIndex;

use super::stable_graph::IndexedGraph;

/// Default minimum strength threshold. Edges below this are pruned.
pub const DEFAULT_PRUNE_STRENGTH: f64 = 0.2;

/// Result of a pruning pass.
#[derive(Debug, Clone)]
pub struct PruneResult {
    /// Number of edges removed.
    pub edges_removed: usize,
    /// Number of orphaned nodes removed.
    pub nodes_removed: usize,
}

/// Prune all edges with strength below the threshold.
pub fn prune_weak_edges(graph: &mut IndexedGraph, min_strength: f64) -> PruneResult {
    let weak: Vec<EdgeIndex> = graph
        .graph
        .edge_indices()
        .filter(|&idx| {
            graph
                .graph
                .edge_weight(idx)
                .is_some_and(|w| w.strength < min_strength)
        })
        .collect();

    let edges_removed = weak.len();
    for idx in weak {
        graph.graph.remove_edge(idx);
    }

    let nodes_removed = remove_orphaned_nodes(graph);

    PruneResult {
        edges_removed,
        nodes_removed,
    }
}

/// Prune inferred edges that have no evidence (unvalidated).
pub fn prune_unvalidated_inferred(graph: &mut IndexedGraph) -> usize {
    let unvalidated: Vec<EdgeIndex> = graph
        .graph
        .edge_indices()
        .filter(|&idx| {
            graph
                .graph
                .edge_weight(idx)
                .is_some_and(|w| w.inferred && w.evidence.is_empty())
        })
        .collect();

    let count = unvalidated.len();
    for idx in unvalidated {
        graph.graph.remove_edge(idx);
    }
    count
}

/// Remove nodes with no incoming or outgoing edges.
fn remove_orphaned_nodes(graph: &mut IndexedGraph) -> usize {
    use petgraph::Direction;

    let orphans: Vec<String> = graph
        .graph
        .node_indices()
        .filter(|&idx| {
            graph
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .next()
                .is_none()
                && graph
                    .graph
                    .neighbors_directed(idx, Direction::Outgoing)
                    .next()
                    .is_none()
        })
        .filter_map(|idx| graph.graph.node_weight(idx).map(|n| n.memory_id.clone()))
        .collect();

    let count = orphans.len();
    for id in &orphans {
        graph.remove_node(id);
    }
    count
}

/// Full cleanup pass: prune weak, prune unvalidated, remove orphans.
pub fn full_cleanup(graph: &mut IndexedGraph, min_strength: f64) -> PruneResult {
    let weak_result = prune_weak_edges(graph, min_strength);
    let unvalidated = prune_unvalidated_inferred(graph);
    // Orphans already handled by prune_weak_edges, but run again for unvalidated removals.
    let extra_orphans = remove_orphaned_nodes(graph);

    PruneResult {
        edges_removed: weak_result.edges_removed + unvalidated,
        nodes_removed: weak_result.nodes_removed + extra_orphans,
    }
}
