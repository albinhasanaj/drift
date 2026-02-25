//! Direct neighbors (depth=1) — both incoming and outgoing.

use petgraph::Direction;

use crate::graph::stable_graph::IndexedGraph;

use super::{TraversalConfig, TraversalNode, TraversalResult};

/// Get direct neighbors of a memory node.
pub fn get(graph: &IndexedGraph, memory_id: &str, config: &TraversalConfig) -> TraversalResult {
    let mut result = TraversalResult {
        origin_id: memory_id.to_string(),
        nodes: Vec::new(),
        max_depth_reached: 0,
    };

    let idx = match graph.get_node(memory_id) {
        Some(idx) => idx,
        None => return result,
    };

    // Outgoing neighbors.
    for neighbor in graph.graph.neighbors_directed(idx, Direction::Outgoing) {
        if result.nodes.len() >= config.max_nodes {
            break;
        }
        if let Some(edge_idx) = graph.graph.find_edge(idx, neighbor) {
            if let (Some(weight), Some(node)) = (
                graph.graph.edge_weight(edge_idx),
                graph.graph.node_weight(neighbor),
            ) {
                if weight.strength >= config.min_strength {
                    result.nodes.push(TraversalNode {
                        memory_id: node.memory_id.clone(),
                        depth: 1,
                        path_strength: weight.strength,
                    });
                    result.max_depth_reached = 1;
                }
            }
        }
    }

    // Incoming neighbors.
    for neighbor in graph.graph.neighbors_directed(idx, Direction::Incoming) {
        if result.nodes.len() >= config.max_nodes {
            break;
        }
        if let Some(edge_idx) = graph.graph.find_edge(neighbor, idx) {
            if let (Some(weight), Some(node)) = (
                graph.graph.edge_weight(edge_idx),
                graph.graph.node_weight(neighbor),
            ) {
                if weight.strength >= config.min_strength {
                    // Avoid duplicates if there's a bidirectional edge.
                    if !result.nodes.iter().any(|n| n.memory_id == node.memory_id) {
                        result.nodes.push(TraversalNode {
                            memory_id: node.memory_id.clone(),
                            depth: 1,
                            path_strength: weight.strength,
                        });
                        result.max_depth_reached = 1;
                    }
                }
            }
        }
    }

    result
}
