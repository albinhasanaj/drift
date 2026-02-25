//! Graph-based confidence propagation via BFS — O(V+E).
//!
//! When a contradiction is detected, confidence changes ripple through
//! the relationship graph to connected memories.

use cortex_core::memory::RelationshipEdge;
use cortex_core::models::ContradictionType;
use std::collections::{HashMap, HashSet, VecDeque};

/// Confidence deltas per contradiction event type.
pub const DELTA_DIRECT: f64 = -0.3;
pub const DELTA_PARTIAL: f64 = -0.15;
pub const DELTA_SUPERSESSION: f64 = -0.5;
pub const DELTA_CONFIRMATION: f64 = 0.1;
pub const DELTA_CONSENSUS: f64 = 0.2;

/// Propagation factor: each hop reduces the delta by this multiplier.
pub const PROPAGATION_FACTOR: f64 = 0.5;

/// Maximum BFS depth for propagation.
const MAX_PROPAGATION_DEPTH: usize = 5;

/// A confidence adjustment to apply to a memory.
#[derive(Debug, Clone)]
pub struct ConfidenceAdjustment {
    pub memory_id: String,
    pub delta: f64,
    pub reason: String,
    /// How many hops from the source contradiction.
    pub depth: usize,
}

/// Get the base delta for a contradiction type.
pub fn base_delta(contradiction_type: ContradictionType) -> f64 {
    match contradiction_type {
        ContradictionType::Direct => DELTA_DIRECT,
        ContradictionType::Partial => DELTA_PARTIAL,
        ContradictionType::Supersession => DELTA_SUPERSESSION,
        ContradictionType::Temporal => DELTA_PARTIAL,
        ContradictionType::Semantic => DELTA_PARTIAL,
    }
}

/// Propagate confidence changes through the relationship graph using BFS.
///
/// Starting from `source_ids` (the memories directly involved in the contradiction),
/// ripple the confidence delta through connected memories, attenuating by
/// `PROPAGATION_FACTOR` at each hop.
///
/// Returns a map of memory_id → total confidence adjustment.
pub fn propagate(
    source_ids: &[String],
    contradiction_type: ContradictionType,
    edges: &[RelationshipEdge],
    max_depth: Option<usize>,
) -> Vec<ConfidenceAdjustment> {
    let max_depth = max_depth.unwrap_or(MAX_PROPAGATION_DEPTH);
    let initial_delta = base_delta(contradiction_type);

    // Build adjacency list.
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in edges {
        adjacency
            .entry(edge.source_id.as_str())
            .or_default()
            .push(edge.target_id.as_str());
        adjacency
            .entry(edge.target_id.as_str())
            .or_default()
            .push(edge.source_id.as_str());
    }

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize, f64)> = VecDeque::new();
    let mut adjustments = Vec::new();

    // Seed the BFS with source memories.
    for id in source_ids {
        visited.insert(id.clone());
        queue.push_back((id.clone(), 0, initial_delta));

        adjustments.push(ConfidenceAdjustment {
            memory_id: id.clone(),
            delta: initial_delta,
            reason: format!("Direct {:?} contradiction", contradiction_type),
            depth: 0,
        });
    }

    // BFS propagation.
    while let Some((current_id, depth, current_delta)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        let next_delta = current_delta * PROPAGATION_FACTOR;

        // Skip if the propagated delta is negligible.
        if next_delta.abs() < 0.01 {
            continue;
        }

        if let Some(neighbors) = adjacency.get(current_id.as_str()) {
            for &neighbor in neighbors {
                if visited.insert(neighbor.to_string()) {
                    adjustments.push(ConfidenceAdjustment {
                        memory_id: neighbor.to_string(),
                        delta: next_delta,
                        reason: format!(
                            "Propagated from {} (depth {}, factor {}×)",
                            current_id,
                            depth + 1,
                            PROPAGATION_FACTOR
                        ),
                        depth: depth + 1,
                    });

                    queue.push_back((neighbor.to_string(), depth + 1, next_delta));
                }
            }
        }
    }

    adjustments
}
