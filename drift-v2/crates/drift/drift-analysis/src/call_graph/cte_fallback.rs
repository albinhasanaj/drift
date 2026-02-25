//! SQLite recursive CTE fallback for graphs >500K functions.
//!
//! When the in-memory graph exceeds the threshold, BFS traversal
//! falls back to SQLite recursive CTEs with temp tables for the visited set.

use drift_core::errors::CallGraphError;
use rusqlite::Connection;

/// Maximum recursion depth for CTE traversal.
const MAX_DEPTH: u32 = 5;

/// Run a forward BFS using SQLite recursive CTE.
///
/// Requires the `call_edges` and `functions` tables to be populated.
pub fn cte_bfs_forward(
    conn: &Connection,
    start_function_id: i64,
    max_depth: Option<u32>,
) -> Result<Vec<i64>, CallGraphError> {
    let depth = max_depth.unwrap_or(MAX_DEPTH);

    let sql = format!(
        "WITH RECURSIVE reachable(id, depth) AS (
            SELECT ?1, 0
            UNION ALL
            SELECT ce.callee_id, r.depth + 1
            FROM call_edges ce
            JOIN reachable r ON ce.caller_id = r.id
            WHERE r.depth < {depth}
        )
        SELECT DISTINCT id FROM reachable WHERE id != ?1"
    );

    let mut stmt = conn.prepare(&sql).map_err(|e: rusqlite::Error| CallGraphError::CteFallbackFailed {
        message: e.to_string(),
    })?;

    let rows = stmt
        .query_map(rusqlite::params![start_function_id], |row: &rusqlite::Row| row.get::<_, i64>(0))
        .map_err(|e: rusqlite::Error| CallGraphError::CteFallbackFailed {
            message: e.to_string(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e: rusqlite::Error| CallGraphError::CteFallbackFailed {
            message: e.to_string(),
        })?);
    }

    Ok(result)
}

/// Run an inverse BFS using SQLite recursive CTE (find all callers).
pub fn cte_bfs_inverse(
    conn: &Connection,
    start_function_id: i64,
    max_depth: Option<u32>,
) -> Result<Vec<i64>, CallGraphError> {
    let depth = max_depth.unwrap_or(MAX_DEPTH);

    let sql = format!(
        "WITH RECURSIVE callers(id, depth) AS (
            SELECT ?1, 0
            UNION ALL
            SELECT ce.caller_id, c.depth + 1
            FROM call_edges ce
            JOIN callers c ON ce.callee_id = c.id
            WHERE c.depth < {depth}
        )
        SELECT DISTINCT id FROM callers WHERE id != ?1"
    );

    let mut stmt = conn.prepare(&sql).map_err(|e: rusqlite::Error| CallGraphError::CteFallbackFailed {
        message: e.to_string(),
    })?;

    let rows = stmt
        .query_map(rusqlite::params![start_function_id], |row: &rusqlite::Row| row.get::<_, i64>(0))
        .map_err(|e: rusqlite::Error| CallGraphError::CteFallbackFailed {
            message: e.to_string(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e: rusqlite::Error| CallGraphError::CteFallbackFailed {
            message: e.to_string(),
        })?);
    }

    Ok(result)
}

/// Check if the graph size exceeds the in-memory threshold.
pub fn should_use_cte(function_count: usize, threshold: usize) -> bool {
    function_count > threshold
}
