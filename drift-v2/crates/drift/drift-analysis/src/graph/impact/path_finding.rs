//! Dijkstra shortest path + K-shortest paths for impact visualization.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use drift_core::types::collections::{FxHashMap, FxHashSet};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::call_graph::types::CallGraph;

use super::types::FunctionPath;

/// Find the shortest path between two functions using Dijkstra's algorithm.
///
/// Edge weights are derived from call edge confidence (lower confidence = higher weight).
pub fn shortest_path(
    graph: &CallGraph,
    from: NodeIndex,
    to: NodeIndex,
) -> Option<FunctionPath> {
    let mut dist: FxHashMap<NodeIndex, f32> = FxHashMap::default();
    let mut prev: FxHashMap<NodeIndex, NodeIndex> = FxHashMap::default();
    let mut heap = BinaryHeap::new();

    dist.insert(from, 0.0);
    heap.push(DijkstraState { cost: 0.0, node: from });

    while let Some(DijkstraState { cost, node }) = heap.pop() {
        if node == to {
            // Reconstruct path
            let mut path = vec![to];
            let mut current = to;
            while let Some(&p) = prev.get(&current) {
                path.push(p);
                current = p;
            }
            path.reverse();
            return Some(FunctionPath {
                nodes: path,
                weight: cost,
            });
        }

        if let Some(&best) = dist.get(&node) {
            if cost > best {
                continue;
            }
        }

        for edge in graph.graph.edges(node) {
            let next = edge.target();
            let edge_weight = 1.0 - edge.weight().confidence; // Lower confidence = higher cost
            let next_cost = cost + edge_weight;

            let is_better = dist
                .get(&next)
                .map(|&d| next_cost < d)
                .unwrap_or(true);

            if is_better {
                dist.insert(next, next_cost);
                prev.insert(next, node);
                heap.push(DijkstraState { cost: next_cost, node: next });
            }
        }
    }

    None
}

/// Find K shortest paths using Yen's algorithm.
pub fn k_shortest_paths(
    graph: &CallGraph,
    from: NodeIndex,
    to: NodeIndex,
    k: usize,
) -> Vec<FunctionPath> {
    let mut result: Vec<FunctionPath> = Vec::new();
    let mut candidates: BinaryHeap<std::cmp::Reverse<WeightedPath>> = BinaryHeap::new();

    // Find the first shortest path
    if let Some(first) = shortest_path(graph, from, to) {
        result.push(first);
    } else {
        return result;
    }

    for ki in 1..k {
        let prev_path = &result[ki - 1];

        for spur_idx in 0..prev_path.nodes.len().saturating_sub(1) {
            let spur_node = prev_path.nodes[spur_idx];
            let root_path: Vec<NodeIndex> = prev_path.nodes[..=spur_idx].to_vec();

            // Build excluded edges set (edges used by previous paths at this spur)
            let mut excluded_edges: FxHashSet<(NodeIndex, NodeIndex)> = FxHashSet::default();
            for path in &result {
                if path.nodes.len() > spur_idx
                    && path.nodes[..=spur_idx] == root_path
                {
                    if let Some(&next) = path.nodes.get(spur_idx + 1) {
                        excluded_edges.insert((spur_node, next));
                    }
                }
            }

            // Find spur path avoiding excluded edges
            if let Some(spur_path) = shortest_path_excluding(
                graph, spur_node, to, &excluded_edges, &root_path,
            ) {
                let mut total_path = root_path[..root_path.len() - 1].to_vec();
                total_path.extend_from_slice(&spur_path.nodes);
                let total_weight = compute_path_weight(graph, &total_path);

                candidates.push(std::cmp::Reverse(WeightedPath {
                    path: FunctionPath {
                        nodes: total_path,
                        weight: total_weight,
                    },
                }));
            }
        }

        if let Some(std::cmp::Reverse(best)) = candidates.pop() {
            result.push(best.path);
        } else {
            break;
        }
    }

    result
}

/// Shortest path excluding certain edges and nodes.
fn shortest_path_excluding(
    graph: &CallGraph,
    from: NodeIndex,
    to: NodeIndex,
    excluded_edges: &FxHashSet<(NodeIndex, NodeIndex)>,
    excluded_nodes: &[NodeIndex],
) -> Option<FunctionPath> {
    let excluded_node_set: FxHashSet<NodeIndex> = excluded_nodes.iter().copied().collect();
    let mut dist: FxHashMap<NodeIndex, f32> = FxHashMap::default();
    let mut prev: FxHashMap<NodeIndex, NodeIndex> = FxHashMap::default();
    let mut heap = BinaryHeap::new();

    dist.insert(from, 0.0);
    heap.push(DijkstraState { cost: 0.0, node: from });

    while let Some(DijkstraState { cost, node }) = heap.pop() {
        if node == to {
            let mut path = vec![to];
            let mut current = to;
            while let Some(&p) = prev.get(&current) {
                path.push(p);
                current = p;
            }
            path.reverse();
            return Some(FunctionPath { nodes: path, weight: cost });
        }

        if let Some(&best) = dist.get(&node) {
            if cost > best {
                continue;
            }
        }

        for edge in graph.graph.edges(node) {
            let next = edge.target();

            if excluded_edges.contains(&(node, next)) {
                continue;
            }
            if next != from && next != to && excluded_node_set.contains(&next) {
                continue;
            }

            let edge_weight = 1.0 - edge.weight().confidence;
            let next_cost = cost + edge_weight;

            let is_better = dist.get(&next).map(|&d| next_cost < d).unwrap_or(true);
            if is_better {
                dist.insert(next, next_cost);
                prev.insert(next, node);
                heap.push(DijkstraState { cost: next_cost, node: next });
            }
        }
    }

    None
}

/// Compute total weight of a path.
fn compute_path_weight(graph: &CallGraph, path: &[NodeIndex]) -> f32 {
    let mut weight = 0.0;
    for window in path.windows(2) {
        let from = window[0];
        let to = window[1];
        if let Some(edge) = graph.graph.edges(from).find(|e| e.target() == to) {
            weight += 1.0 - edge.weight().confidence;
        } else {
            weight += 1.0; // No edge found, max weight
        }
    }
    weight
}

/// State for Dijkstra's priority queue.
#[derive(Debug, Clone)]
struct DijkstraState {
    cost: f32,
    node: NodeIndex,
}

impl PartialEq for DijkstraState {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}

impl Eq for DijkstraState {}

impl PartialOrd for DijkstraState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DijkstraState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap
        other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
    }
}

/// Wrapper for paths in the candidate heap.
#[derive(Debug, Clone)]
struct WeightedPath {
    path: FunctionPath,
}

impl PartialEq for WeightedPath {
    fn eq(&self, other: &Self) -> bool {
        self.path.weight == other.path.weight
    }
}

impl Eq for WeightedPath {}

impl PartialOrd for WeightedPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WeightedPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .weight
            .partial_cmp(&other.path.weight)
            .unwrap_or(Ordering::Equal)
    }
}
