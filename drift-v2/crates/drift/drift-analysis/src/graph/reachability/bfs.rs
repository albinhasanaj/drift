//! Forward/inverse BFS with auto-select engine.
//!
//! - <10K nodes → petgraph in-memory BFS
//! - ≥10K nodes → SQLite recursive CTE

use std::collections::VecDeque;

use drift_core::errors::CallGraphError;
use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;
use petgraph::Direction;
use rusqlite::Connection;

use crate::call_graph::cte_fallback;
use crate::call_graph::types::CallGraph;

use super::types::{ReachabilityEngine, ReachabilityResult, SensitivityCategory, TraversalDirection};

/// Threshold for auto-selecting between petgraph and SQLite CTE.
const AUTO_SELECT_THRESHOLD: usize = 10_000;

/// Determine which engine to use based on graph size.
pub fn auto_select_engine(node_count: usize) -> ReachabilityEngine {
    if node_count < AUTO_SELECT_THRESHOLD {
        ReachabilityEngine::Petgraph
    } else {
        ReachabilityEngine::SqliteCte
    }
}

/// Forward reachability: find all functions reachable from `start`.
pub fn reachability_forward(
    graph: &CallGraph,
    start: NodeIndex,
    max_depth: Option<u32>,
) -> ReachabilityResult {
    let reachable = bfs_collect(graph, start, Direction::Outgoing, max_depth);
    let max_d = compute_max_depth(graph, start, Direction::Outgoing, max_depth);
    ReachabilityResult {
        source: start,
        reachable,
        sensitivity: SensitivityCategory::Low, // caller classifies after
        max_depth: max_d,
        engine: ReachabilityEngine::Petgraph,
    }
}

/// Inverse reachability: find all callers that can reach `start`.
pub fn reachability_inverse(
    graph: &CallGraph,
    start: NodeIndex,
    max_depth: Option<u32>,
) -> ReachabilityResult {
    let reachable = bfs_collect(graph, start, Direction::Incoming, max_depth);
    let max_d = compute_max_depth(graph, start, Direction::Incoming, max_depth);
    ReachabilityResult {
        source: start,
        reachable,
        sensitivity: SensitivityCategory::Low,
        max_depth: max_d,
        engine: ReachabilityEngine::Petgraph,
    }
}

/// Forward reachability via SQLite CTE (for large graphs).
pub fn reachability_forward_cte(
    conn: &Connection,
    start_function_id: i64,
    max_depth: Option<u32>,
) -> Result<Vec<i64>, CallGraphError> {
    cte_fallback::cte_bfs_forward(conn, start_function_id, max_depth)
}

/// Inverse reachability via SQLite CTE (for large graphs).
pub fn reachability_inverse_cte(
    conn: &Connection,
    start_function_id: i64,
    max_depth: Option<u32>,
) -> Result<Vec<i64>, CallGraphError> {
    cte_fallback::cte_bfs_inverse(conn, start_function_id, max_depth)
}

/// Auto-select engine and run reachability.
pub fn reachability_auto(
    graph: &CallGraph,
    start: NodeIndex,
    direction: TraversalDirection,
    max_depth: Option<u32>,
    cte_conn: Option<&Connection>,
) -> Result<ReachabilityResult, CallGraphError> {
    let engine = auto_select_engine(graph.function_count());

    match engine {
        ReachabilityEngine::Petgraph => {
            let result = match direction {
                TraversalDirection::Forward => reachability_forward(graph, start, max_depth),
                TraversalDirection::Inverse => reachability_inverse(graph, start, max_depth),
            };
            Ok(result)
        }
        ReachabilityEngine::SqliteCte => {
            let conn = cte_conn.ok_or_else(|| CallGraphError::CteFallbackFailed {
                message: "SQLite connection required for CTE engine but not provided".into(),
            })?;
            // For CTE, we need a numeric function ID. Use the node index as a proxy.
            let func_id = start.index() as i64;
            let ids = match direction {
                TraversalDirection::Forward => cte_fallback::cte_bfs_forward(conn, func_id, max_depth)?,
                TraversalDirection::Inverse => cte_fallback::cte_bfs_inverse(conn, func_id, max_depth)?,
            };
            let reachable: FxHashSet<NodeIndex> = ids
                .into_iter()
                .map(|id| NodeIndex::new(id as usize))
                .collect();
            Ok(ReachabilityResult {
                source: start,
                reachable,
                sensitivity: SensitivityCategory::Low,
                max_depth: max_depth.unwrap_or(5),
                engine: ReachabilityEngine::SqliteCte,
            })
        }
    }
}

/// Core BFS that collects all reachable nodes into a FxHashSet.
fn bfs_collect(
    graph: &CallGraph,
    start: NodeIndex,
    direction: Direction,
    max_depth: Option<u32>,
) -> FxHashSet<NodeIndex> {
    let mut visited = FxHashSet::default();
    let mut queue = VecDeque::new();

    visited.insert(start);
    queue.push_back((start, 0u32));

    while let Some((node, depth)) = queue.pop_front() {
        if let Some(max) = max_depth {
            if depth >= max {
                continue;
            }
        }

        for neighbor in graph.graph.neighbors_directed(node, direction) {
            if visited.insert(neighbor) {
                queue.push_back((neighbor, depth + 1));
            }
        }
    }

    // Remove the start node from the result set
    visited.remove(&start);
    visited
}

/// Compute the maximum depth reached during BFS.
fn compute_max_depth(
    graph: &CallGraph,
    start: NodeIndex,
    direction: Direction,
    max_depth: Option<u32>,
) -> u32 {
    let mut visited = FxHashSet::default();
    let mut queue = VecDeque::new();
    let mut max_d = 0u32;

    visited.insert(start);
    queue.push_back((start, 0u32));

    while let Some((node, depth)) = queue.pop_front() {
        if node != start && depth > max_d {
            max_d = depth;
        }

        if let Some(max) = max_depth {
            if depth >= max {
                continue;
            }
        }

        for neighbor in graph.graph.neighbors_directed(node, direction) {
            if visited.insert(neighbor) {
                queue.push_back((neighbor, depth + 1));
            }
        }
    }

    max_d
}
