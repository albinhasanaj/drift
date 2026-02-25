//! Tarjan's SCC cycle detection via petgraph.

use drift_core::types::collections::FxHashMap;
use petgraph::graph::{DiGraph, NodeIndex};

use super::types::{CycleBreakSuggestion, CycleInfo, ImportGraph};

/// Detect dependency cycles using Tarjan's SCC algorithm.
///
/// Returns only SCCs with more than one member (actual cycles).
pub fn detect_cycles(graph: &ImportGraph) -> Vec<CycleInfo> {
    // Build a petgraph DiGraph from the import graph
    let mut pg: DiGraph<String, ()> = DiGraph::new();
    let mut node_map: FxHashMap<String, NodeIndex> = FxHashMap::default();

    for module in &graph.modules {
        let idx = pg.add_node(module.clone());
        node_map.insert(module.clone(), idx);
    }

    for (src, targets) in &graph.edges {
        if let Some(&src_idx) = node_map.get(src) {
            for target in targets {
                if let Some(&dst_idx) = node_map.get(target) {
                    pg.add_edge(src_idx, dst_idx, ());
                }
            }
        }
    }

    // Run Tarjan's SCC
    let sccs = petgraph::algo::tarjan_scc(&pg);

    sccs.into_iter()
        .filter(|scc| scc.len() > 1)
        .map(|scc| {
            let members: Vec<String> = scc
                .iter()
                .map(|idx| pg[*idx].clone())
                .collect();

            let break_suggestions = suggest_cycle_breaks(&pg, &scc, &members);

            CycleInfo {
                members,
                break_suggestions,
            }
        })
        .collect()
}

/// Suggest edges to break to eliminate a cycle.
///
/// Strategy: for each edge within the SCC, score it by the in-degree of the
/// target node. Removing an edge to a high-in-degree node has lower impact
/// because that node has other dependents. We suggest the lowest-impact edges.
fn suggest_cycle_breaks(
    pg: &DiGraph<String, ()>,
    scc: &[NodeIndex],
    _members: &[String],
) -> Vec<CycleBreakSuggestion> {
    use petgraph::visit::EdgeRef;

    let scc_set: std::collections::HashSet<NodeIndex> = scc.iter().copied().collect();
    let mut suggestions = Vec::new();

    for &node in scc {
        for edge in pg.edges(node) {
            let target = edge.target();
            if scc_set.contains(&target) {
                // Impact: inverse of target's in-degree within the SCC
                let in_degree = pg
                    .edges_directed(target, petgraph::Direction::Incoming)
                    .filter(|e| scc_set.contains(&e.source()))
                    .count();

                let impact_score = if in_degree <= 1 {
                    1.0 // Only edge into this node — high impact to remove
                } else {
                    1.0 / in_degree as f64
                };

                suggestions.push(CycleBreakSuggestion {
                    from: pg[node].clone(),
                    to: pg[target].clone(),
                    impact_score,
                });
            }
        }
    }

    // Sort by impact (lowest first = easiest to break)
    suggestions.sort_by(|a, b| a.impact_score.partial_cmp(&b.impact_score).unwrap_or(std::cmp::Ordering::Equal));
    suggestions
}
