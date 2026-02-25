//! Forward traversal: "what did this cause?" — follows outgoing edges.

use std::collections::{HashSet, VecDeque};

use petgraph::Direction;

use crate::graph::stable_graph::IndexedGraph;

use super::{TraversalConfig, TraversalNode, TraversalResult};

/// Trace forward from a memory to find its effects.
pub fn trace(graph: &IndexedGraph, memory_id: &str, config: &TraversalConfig) -> TraversalResult {
    let mut result = TraversalResult {
        origin_id: memory_id.to_string(),
        nodes: Vec::new(),
        max_depth_reached: 0,
    };

    let start_idx = match graph.get_node(memory_id) {
        Some(idx) => idx,
        None => return result,
    };

    let mut visited = HashSet::new();
    visited.insert(start_idx);

    let mut queue = VecDeque::new();
    queue.push_back((start_idx, 0, 1.0_f64));

    while let Some((current, depth, path_strength)) = queue.pop_front() {
        if depth >= config.max_depth || result.nodes.len() >= config.max_nodes {
            break;
        }

        // Follow outgoing edges (successors).
        for neighbor in graph.graph.neighbors_directed(current, Direction::Outgoing) {
            if result.nodes.len() >= config.max_nodes {
                break;
            }
            if visited.contains(&neighbor) {
                continue;
            }

            if let Some(edge_idx) = graph.graph.find_edge(current, neighbor) {
                if let Some(weight) = graph.graph.edge_weight(edge_idx) {
                    if weight.strength < config.min_strength {
                        continue;
                    }

                    let new_strength = path_strength * weight.strength;
                    visited.insert(neighbor);

                    if let Some(node) = graph.graph.node_weight(neighbor) {
                        let new_depth = depth + 1;
                        result.max_depth_reached = result.max_depth_reached.max(new_depth);
                        result.nodes.push(TraversalNode {
                            memory_id: node.memory_id.clone(),
                            depth: new_depth,
                            path_strength: new_strength,
                        });

                        if result.nodes.len() < config.max_nodes {
                            queue.push_back((neighbor, new_depth, new_strength));
                        }
                    }
                }
            }
        }
    }

    result
}
