//! call_edges table queries.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A call edge record from the database.
#[derive(Debug, Clone)]
pub struct CallEdgeRecord {
    pub caller_id: i64,
    pub callee_id: i64,
    pub resolution: String,
    pub confidence: f64,
    pub call_site_line: i64,
}

/// Insert a batch of call edges.
pub fn insert_call_edges(
    conn: &Connection,
    edges: &[CallEdgeRecord],
) -> Result<usize, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR REPLACE INTO call_edges
             (caller_id, callee_id, resolution, confidence, call_site_line)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut count = 0;
    for edge in edges {
        stmt.execute(params![
            edge.caller_id,
            edge.callee_id,
            edge.resolution,
            edge.confidence,
            edge.call_site_line,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
        count += 1;
    }
    Ok(count)
}

/// Get all edges where the given function is the caller.
pub fn get_edges_by_caller(
    conn: &Connection,
    caller_id: i64,
) -> Result<Vec<CallEdgeRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT caller_id, callee_id, resolution, confidence, call_site_line
             FROM call_edges WHERE caller_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![caller_id], |row| {
            Ok(CallEdgeRecord {
                caller_id: row.get(0)?,
                callee_id: row.get(1)?,
                resolution: row.get(2)?,
                confidence: row.get(3)?,
                call_site_line: row.get(4)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Get all edges where the given function is the callee.
pub fn get_edges_by_callee(
    conn: &Connection,
    callee_id: i64,
) -> Result<Vec<CallEdgeRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT caller_id, callee_id, resolution, confidence, call_site_line
             FROM call_edges WHERE callee_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![callee_id], |row| {
            Ok(CallEdgeRecord {
                caller_id: row.get(0)?,
                callee_id: row.get(1)?,
                resolution: row.get(2)?,
                confidence: row.get(3)?,
                call_site_line: row.get(4)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Delete all edges involving functions from a given file.
pub fn delete_edges_by_file(
    conn: &Connection,
    file: &str,
) -> Result<usize, StorageError> {
    conn.execute(
        "DELETE FROM call_edges WHERE caller_id IN (SELECT id FROM functions WHERE file = ?1)
         OR callee_id IN (SELECT id FROM functions WHERE file = ?1)",
        params![file],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total call edges.
pub fn count_call_edges(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM call_edges", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count edges with non-fuzzy resolution (resolved by import, export, DI, method, or same-file).
pub fn count_resolved_edges(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row(
        "SELECT COUNT(*) FROM call_edges WHERE resolution != 'fuzzy' AND resolution != 'unresolved'",
        [],
        |row| row.get(0),
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}
