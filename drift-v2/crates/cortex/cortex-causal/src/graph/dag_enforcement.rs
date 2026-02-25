//! Cycle detection using Tarjan's SCC before every edge insertion.
//! Rejects any edge that would create a cycle in the DAG.

use petgraph::algo::tarjan_scc;
use petgraph::stable_graph::NodeIndex;

use super::stable_graph::IndexedGraph;

/// Check whether adding an edge from `source` to `target` would create a cycle.
/// Uses Tarjan's SCC algorithm on the graph with the proposed edge temporarily added.
///
/// Returns `true` if a cycle would be created (edge should be rejected).
pub fn would_create_cycle(graph: &IndexedGraph, source: NodeIndex, target: NodeIndex) -> bool {
    // Self-loops are always cycles.
    if source == target {
        return true;
    }

    // Fast path: check if target can already reach source via DFS.
    // If so, adding source→target creates a cycle.
    has_path(&graph.graph, target, source)
}

/// DFS-based reachability check: can we reach `to` from `from`?
fn has_path(
    graph: &petgraph::stable_graph::StableGraph<
        super::stable_graph::CausalNode,
        super::stable_graph::CausalEdgeWeight,
        petgraph::Directed,
    >,
    from: NodeIndex,
    to: NodeIndex,
) -> bool {
    use petgraph::visit::Dfs;
    let mut dfs = Dfs::new(graph, from);
    while let Some(node) = dfs.next(graph) {
        if node == to {
            return true;
        }
    }
    false
}

/// Validate the entire graph is a DAG (no cycles).
/// Returns the list of SCCs with more than one node (i.e., cycles).
pub fn find_cycles(graph: &IndexedGraph) -> Vec<Vec<NodeIndex>> {
    tarjan_scc(&graph.graph)
        .into_iter()
        .filter(|scc| scc.len() > 1)
        .collect()
}
