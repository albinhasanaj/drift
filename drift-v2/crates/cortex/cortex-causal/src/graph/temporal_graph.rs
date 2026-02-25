//! Historical graph reconstruction from temporal events.
//!
//! Reconstructs the causal graph as it existed at any past point in time
//! by replaying RelationshipAdded, RelationshipRemoved, and StrengthUpdated
//! events in event_id order.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use cortex_core::models::{CausalEdgeSnapshot, CausalGraphSnapshot, MemoryEvent, MemoryEventType};

use super::stable_graph::{CausalEdgeWeight, IndexedGraph};
use crate::relations::CausalRelation;
use crate::traversal::{TraversalConfig, TraversalEngine, TraversalResult};

/// An intermediate edge representation used during reconstruction.
#[derive(Debug, Clone)]
struct ReconstructedEdge {
    source: String,
    target: String,
    relation_type: String,
    strength: f64,
}

/// Reconstruct the causal graph as it existed at `as_of` from a set of
/// pre-fetched temporal events.
///
/// The caller is responsible for providing all RelationshipAdded,
/// RelationshipRemoved, and StrengthUpdated events with `recorded_at <= as_of`,
/// ordered by `event_id` ascending.
///
/// Algorithm:
/// 1. Process RelationshipAdded events → build edge set
/// 2. Process RelationshipRemoved events → delete edges
/// 3. Process StrengthUpdated events → update strengths (no-op if edge removed)
/// 4. Build IndexedGraph from surviving edges
pub fn reconstruct_graph_at(events: &[MemoryEvent], as_of: DateTime<Utc>) -> IndexedGraph {
    // Edge map keyed by (source, target)
    let mut edges: HashMap<(String, String), ReconstructedEdge> = HashMap::new();

    // Process events in order (caller must provide sorted by event_id)
    for event in events {
        // Skip events after as_of (defensive — caller should pre-filter)
        if event.recorded_at > as_of {
            continue;
        }

        match event.event_type {
            MemoryEventType::RelationshipAdded => {
                let source = event
                    .delta
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target = event
                    .delta
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let relation_type = event
                    .delta
                    .get("relation_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("supports")
                    .to_string();
                let strength = event
                    .delta
                    .get("strength")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5);

                if !source.is_empty() && !target.is_empty() {
                    edges.insert(
                        (source.clone(), target.clone()),
                        ReconstructedEdge {
                            source,
                            target,
                            relation_type,
                            strength,
                        },
                    );
                }
            }
            MemoryEventType::RelationshipRemoved => {
                let source = event
                    .delta
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target = event
                    .delta
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if !source.is_empty() && !target.is_empty() {
                    edges.remove(&(source, target));
                }
            }
            MemoryEventType::StrengthUpdated => {
                let source = event
                    .delta
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target = event
                    .delta
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let new_strength = event
                    .delta
                    .get("new_strength")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5);

                // Only update if edge still exists (removed edges are no-ops)
                if let Some(edge) = edges.get_mut(&(source, target)) {
                    edge.strength = new_strength;
                }
            }
            _ => {
                // Ignore non-relationship events
            }
        }
    }

    // Build IndexedGraph from surviving edges
    build_graph_from_edges(edges)
}

/// Build an IndexedGraph from a map of reconstructed edges.
fn build_graph_from_edges(edges: HashMap<(String, String), ReconstructedEdge>) -> IndexedGraph {
    let mut graph = IndexedGraph::new();

    for edge in edges.values() {
        let source_idx = graph.ensure_node(&edge.source, "unknown", "");
        let target_idx = graph.ensure_node(&edge.target, "unknown", "");

        let relation =
            CausalRelation::from_str_name(&edge.relation_type).unwrap_or(CausalRelation::Supports);

        let weight = CausalEdgeWeight {
            relation,
            strength: edge.strength,
            evidence: vec![],
            inferred: false,
        };

        graph.graph.add_edge(source_idx, target_idx, weight);
    }

    graph
}

/// Convert an IndexedGraph to a serializable CausalGraphSnapshot.
pub fn graph_to_snapshot(graph: &IndexedGraph) -> CausalGraphSnapshot {
    let nodes: Vec<String> = graph.node_index.keys().cloned().collect();

    let mut edges = Vec::new();
    for edge_idx in graph.graph.edge_indices() {
        if let (Some(source_idx), Some(target_idx)) = (
            graph.graph.edge_endpoints(edge_idx).map(|(s, _)| s),
            graph.graph.edge_endpoints(edge_idx).map(|(_, t)| t),
        ) {
            if let (Some(source_node), Some(target_node), Some(weight)) = (
                graph.graph.node_weight(source_idx),
                graph.graph.node_weight(target_idx),
                graph.graph.edge_weight(edge_idx),
            ) {
                edges.push(CausalEdgeSnapshot {
                    source: source_node.memory_id.clone(),
                    target: target_node.memory_id.clone(),
                    relation_type: weight.relation.as_str().to_string(),
                    strength: weight.strength,
                });
            }
        }
    }

    CausalGraphSnapshot { nodes, edges }
}

/// Perform a temporal traversal: reconstruct the graph at `as_of`, then
/// run the existing traversal engine on the historical graph.
///
/// This reuses cortex-causal's traversal logic on a reconstructed graph
/// instead of the current live graph.
pub fn temporal_traversal(
    events: &[MemoryEvent],
    memory_id: &str,
    as_of: DateTime<Utc>,
    direction: cortex_core::models::TraversalDirection,
    max_depth: usize,
) -> TraversalResult {
    let graph = reconstruct_graph_at(events, as_of);

    let config = TraversalConfig {
        max_depth,
        min_strength: 0.0, // Include all edges in temporal traversal
        max_nodes: 1000,
    };

    let engine = TraversalEngine::new(config);

    match direction {
        cortex_core::models::TraversalDirection::Forward => engine.trace_effects(&graph, memory_id),
        cortex_core::models::TraversalDirection::Backward => {
            engine.trace_origins(&graph, memory_id)
        }
        cortex_core::models::TraversalDirection::Both => engine.bidirectional(&graph, memory_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortex_core::models::{EventActor, MemoryEvent, MemoryEventType};

    fn make_relationship_event(
        event_id: u64,
        event_type: MemoryEventType,
        delta: serde_json::Value,
        recorded_at: DateTime<Utc>,
    ) -> MemoryEvent {
        MemoryEvent {
            event_id,
            memory_id: "graph".to_string(),
            recorded_at,
            event_type,
            delta,
            actor: EventActor::System("test".to_string()),
            caused_by: vec![],
            schema_version: 1,
        }
    }

    #[test]
    fn test_reconstruct_empty_events() {
        let graph = reconstruct_graph_at(&[], Utc::now());
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_reconstruct_single_edge() {
        let t1 = Utc::now();
        let events = vec![make_relationship_event(
            1,
            MemoryEventType::RelationshipAdded,
            serde_json::json!({
                "source": "mem-a",
                "target": "mem-b",
                "relation_type": "caused",
                "strength": 0.8
            }),
            t1,
        )];

        let graph = reconstruct_graph_at(&events, t1);
        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_reconstruct_edge_removal() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);
        let t3 = t2 + chrono::Duration::seconds(10);

        let events = vec![
            make_relationship_event(
                1,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "relation_type": "caused",
                    "strength": 0.8
                }),
                t1,
            ),
            make_relationship_event(
                2,
                MemoryEventType::RelationshipRemoved,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b"
                }),
                t2,
            ),
        ];

        // At t1, edge exists
        let graph_at_t1 = reconstruct_graph_at(&events[..1], t1);
        assert_eq!(graph_at_t1.edge_count(), 1);

        // At t3 (after removal), edge is gone
        let graph_at_t3 = reconstruct_graph_at(&events, t3);
        assert_eq!(graph_at_t3.edge_count(), 0);
        // Nodes may still exist (orphaned), that's fine
    }

    #[test]
    fn test_reconstruct_strength_update() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);

        let events = vec![
            make_relationship_event(
                1,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "relation_type": "supports",
                    "strength": 0.5
                }),
                t1,
            ),
            make_relationship_event(
                2,
                MemoryEventType::StrengthUpdated,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "old_strength": 0.5,
                    "new_strength": 0.9
                }),
                t2,
            ),
        ];

        // At t1, strength is 0.5
        let graph_at_t1 = reconstruct_graph_at(&events[..1], t1);
        let snapshot_t1 = graph_to_snapshot(&graph_at_t1);
        assert_eq!(snapshot_t1.edges.len(), 1);
        assert!((snapshot_t1.edges[0].strength - 0.5).abs() < 0.001);

        // At t2, strength is 0.9
        let graph_at_t2 = reconstruct_graph_at(&events, t2);
        let snapshot_t2 = graph_to_snapshot(&graph_at_t2);
        assert_eq!(snapshot_t2.edges.len(), 1);
        assert!((snapshot_t2.edges[0].strength - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_strength_update_on_removed_edge_is_noop() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);
        let t3 = t2 + chrono::Duration::seconds(10);

        let events = vec![
            make_relationship_event(
                1,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "relation_type": "supports",
                    "strength": 0.5
                }),
                t1,
            ),
            make_relationship_event(
                2,
                MemoryEventType::RelationshipRemoved,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b"
                }),
                t2,
            ),
            make_relationship_event(
                3,
                MemoryEventType::StrengthUpdated,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "old_strength": 0.5,
                    "new_strength": 0.9
                }),
                t3,
            ),
        ];

        // After all events, edge should still be removed
        let graph = reconstruct_graph_at(&events, t3);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_reconstruct_excludes_future_events() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);

        let events = vec![make_relationship_event(
            1,
            MemoryEventType::RelationshipAdded,
            serde_json::json!({
                "source": "mem-a",
                "target": "mem-b",
                "relation_type": "caused",
                "strength": 0.8
            }),
            t2, // Future event
        )];

        // At t1 (before the event), graph should be empty
        let graph = reconstruct_graph_at(&events, t1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_graph_to_snapshot() {
        let t1 = Utc::now();
        let events = vec![
            make_relationship_event(
                1,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "relation_type": "caused",
                    "strength": 0.8
                }),
                t1,
            ),
            make_relationship_event(
                2,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-b",
                    "target": "mem-c",
                    "relation_type": "supports",
                    "strength": 0.6
                }),
                t1,
            ),
        ];

        let graph = reconstruct_graph_at(&events, t1);
        let snapshot = graph_to_snapshot(&graph);

        assert_eq!(snapshot.nodes.len(), 3);
        assert_eq!(snapshot.edges.len(), 2);
    }

    #[test]
    fn test_temporal_traversal_forward() {
        let t1 = Utc::now();
        let events = vec![
            make_relationship_event(
                1,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-a",
                    "target": "mem-b",
                    "relation_type": "caused",
                    "strength": 0.8
                }),
                t1,
            ),
            make_relationship_event(
                2,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "mem-b",
                    "target": "mem-c",
                    "relation_type": "caused",
                    "strength": 0.7
                }),
                t1,
            ),
        ];

        let result = temporal_traversal(
            &events,
            "mem-a",
            t1,
            cortex_core::models::TraversalDirection::Forward,
            5,
        );

        assert_eq!(result.origin_id, "mem-a");
        assert!(!result.nodes.is_empty());
    }

    #[test]
    fn test_temporal_traversal_backward() {
        let t1 = Utc::now();
        let events = vec![make_relationship_event(
            1,
            MemoryEventType::RelationshipAdded,
            serde_json::json!({
                "source": "mem-a",
                "target": "mem-b",
                "relation_type": "caused",
                "strength": 0.8
            }),
            t1,
        )];

        let result = temporal_traversal(
            &events,
            "mem-b",
            t1,
            cortex_core::models::TraversalDirection::Backward,
            5,
        );

        assert_eq!(result.origin_id, "mem-b");
        assert!(!result.nodes.is_empty());
        assert_eq!(result.nodes[0].memory_id, "mem-a");
    }

    #[test]
    fn test_reconstruct_multiple_edges_complex() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(5);
        let t3 = t2 + chrono::Duration::seconds(5);
        let t4 = t3 + chrono::Duration::seconds(5);

        let events = vec![
            // Add A->B
            make_relationship_event(
                1,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "A", "target": "B",
                    "relation_type": "caused", "strength": 0.8
                }),
                t1,
            ),
            // Add B->C
            make_relationship_event(
                2,
                MemoryEventType::RelationshipAdded,
                serde_json::json!({
                    "source": "B", "target": "C",
                    "relation_type": "supports", "strength": 0.6
                }),
                t2,
            ),
            // Remove A->B
            make_relationship_event(
                3,
                MemoryEventType::RelationshipRemoved,
                serde_json::json!({ "source": "A", "target": "B" }),
                t3,
            ),
            // Update B->C strength
            make_relationship_event(
                4,
                MemoryEventType::StrengthUpdated,
                serde_json::json!({
                    "source": "B", "target": "C",
                    "old_strength": 0.6, "new_strength": 0.95
                }),
                t4,
            ),
        ];

        // At t2: both edges exist
        let g2 = reconstruct_graph_at(&events[..2], t2);
        assert_eq!(g2.edge_count(), 2);

        // At t3: A->B removed, B->C remains at 0.6
        let g3 = reconstruct_graph_at(&events[..3], t3);
        assert_eq!(g3.edge_count(), 1);
        let snap3 = graph_to_snapshot(&g3);
        assert!((snap3.edges[0].strength - 0.6).abs() < 0.001);

        // At t4: B->C at 0.95
        let g4 = reconstruct_graph_at(&events, t4);
        assert_eq!(g4.edge_count(), 1);
        let snap4 = graph_to_snapshot(&g4);
        assert!((snap4.edges[0].strength - 0.95).abs() < 0.001);
    }
}
