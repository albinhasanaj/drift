//! Field-level data flow tracking.
//!
//! Tracks how specific fields (e.g., `user.email`) flow through the call graph,
//! preserving field identity at each hop.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

use crate::call_graph::types::CallGraph;

/// A field being tracked through the call graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrackedField {
    /// The object/model the field belongs to (e.g., "user").
    pub object: String,
    /// The field name (e.g., "email").
    pub field: String,
}

impl TrackedField {
    pub fn new(object: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            object: object.into(),
            field: field.into(),
        }
    }

    /// Qualified name: "object.field".
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.object, self.field)
    }
}

impl std::fmt::Display for TrackedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.object, self.field)
    }
}

/// A hop in a field flow path.
#[derive(Debug, Clone)]
pub struct FieldFlowHop {
    /// The function node at this hop.
    pub node: NodeIndex,
    /// The field state at this hop (may be transformed).
    pub field: TrackedField,
    /// Whether the field was transformed at this hop.
    pub transformed: bool,
}

/// Result of field-level flow tracking.
#[derive(Debug, Clone)]
pub struct FieldFlowResult {
    /// The original field being tracked.
    pub origin: TrackedField,
    /// The complete flow path.
    pub path: Vec<FieldFlowHop>,
    /// All nodes where this field is accessed.
    pub access_points: FxHashSet<NodeIndex>,
}

/// Track a field through the call graph via forward BFS.
///
/// Starting from `origin_node`, follows outgoing edges and records
/// each hop where the field might be accessed or transformed.
pub fn track_field_flow(
    graph: &CallGraph,
    origin_node: NodeIndex,
    field: &TrackedField,
    max_depth: Option<u32>,
) -> FieldFlowResult {
    let max_d = max_depth.unwrap_or(20);
    let mut path = Vec::new();
    let mut access_points = FxHashSet::default();
    let mut visited = FxHashSet::default();
    let mut queue = std::collections::VecDeque::new();

    visited.insert(origin_node);
    queue.push_back((origin_node, field.clone(), 0u32));

    path.push(FieldFlowHop {
        node: origin_node,
        field: field.clone(),
        transformed: false,
    });
    access_points.insert(origin_node);

    while let Some((node, current_field, depth)) = queue.pop_front() {
        if depth >= max_d {
            continue;
        }

        for neighbor in graph.graph.neighbors_directed(node, petgraph::Direction::Outgoing) {
            if visited.insert(neighbor) {
                let (next_field, transformed) = check_field_transformation(
                    graph, neighbor, &current_field,
                );

                path.push(FieldFlowHop {
                    node: neighbor,
                    field: next_field.clone(),
                    transformed,
                });
                access_points.insert(neighbor);

                queue.push_back((neighbor, next_field, depth + 1));
            }
        }
    }

    FieldFlowResult {
        origin: field.clone(),
        path,
        access_points,
    }
}

/// Check if a field is transformed at a given node.
///
/// Heuristic: if the function name suggests transformation (map, transform, convert, etc.),
/// mark the field as transformed.
fn check_field_transformation(
    graph: &CallGraph,
    node: NodeIndex,
    field: &TrackedField,
) -> (TrackedField, bool) {
    if let Some(func_node) = graph.graph.node_weight(node) {
        let name_lower = func_node.name.to_lowercase();
        let is_transform = name_lower.contains("map")
            || name_lower.contains("transform")
            || name_lower.contains("convert")
            || name_lower.contains("serialize")
            || name_lower.contains("format")
            || name_lower.contains("encode")
            || name_lower.contains("decode")
            || name_lower.contains("parse");

        if is_transform {
            return (field.clone(), true);
        }
    }

    (field.clone(), false)
}

/// Track multiple fields simultaneously through the call graph.
pub fn track_multiple_fields(
    graph: &CallGraph,
    origin_node: NodeIndex,
    fields: &[TrackedField],
    max_depth: Option<u32>,
) -> Vec<FieldFlowResult> {
    fields
        .iter()
        .map(|field| track_field_flow(graph, origin_node, field, max_depth))
        .collect()
}
