//! Memory version insert, query, rollback.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// A snapshot of a memory at a specific version.
#[derive(Debug, Clone)]
pub struct MemoryVersion {
    pub memory_id: String,
    pub version: i64,
    pub content: String,
    pub summary: String,
    pub confidence: f64,
    pub changed_by: String,
    pub reason: String,
    pub created_at: String,
}

/// Insert a new version snapshot for a memory.
/// Wrapped in a SAVEPOINT for atomicity: SELECT MAX(version) + INSERT are atomic (no TOCTOU).
pub fn insert_version(
    conn: &Connection,
    memory_id: &str,
    content: &str,
    summary: &str,
    confidence: f64,
    changed_by: &str,
    reason: &str,
) -> CortexResult<i64> {
    conn.execute_batch("SAVEPOINT insert_ver")
        .map_err(|e| to_storage_err(format!("insert_version savepoint: {e}")))?;

    match insert_version_inner(conn, memory_id, content, summary, confidence, changed_by, reason) {
        Ok(ver) => {
            conn.execute_batch("RELEASE insert_ver")
                .map_err(|e| to_storage_err(format!("insert_version release: {e}")))?;
            Ok(ver)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO insert_ver");
            let _ = conn.execute_batch("RELEASE insert_ver");
            Err(e)
        }
    }
}

/// Inner insert_version logic.
#[allow(clippy::too_many_arguments)]
fn insert_version_inner(
    conn: &Connection,
    memory_id: &str,
    content: &str,
    summary: &str,
    confidence: f64,
    changed_by: &str,
    reason: &str,
) -> CortexResult<i64> {
    // Get the next version number.
    let next_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM memory_versions WHERE memory_id = ?1",
            params![memory_id],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    conn.execute(
        "INSERT INTO memory_versions (memory_id, version, content, summary, confidence, changed_by, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![memory_id, next_version, content, summary, confidence, changed_by, reason],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // Emit ContentUpdated event for version tracking.
    let delta = serde_json::json!({
        "new_summary": summary,
        "version": next_version,
        "reason": reason,
    });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        memory_id,
        "content_updated",
        &delta,
        "system",
        "version_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit version event");
    }

    Ok(next_version)
}

/// Get version history for a memory, ordered newest first.
pub fn get_version_history(conn: &Connection, memory_id: &str) -> CortexResult<Vec<MemoryVersion>> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, version, content, summary, confidence, changed_by, reason, created_at
             FROM memory_versions WHERE memory_id = ?1
             ORDER BY version DESC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![memory_id], |row| {
            Ok(MemoryVersion {
                memory_id: row.get(0)?,
                version: row.get(1)?,
                content: row.get(2)?,
                summary: row.get(3)?,
                confidence: row.get(4)?,
                changed_by: row.get(5)?,
                reason: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}

/// Get a memory at a specific version.
pub fn get_at_version(
    conn: &Connection,
    memory_id: &str,
    version: i64,
) -> CortexResult<Option<MemoryVersion>> {
    let result = conn.query_row(
        "SELECT memory_id, version, content, summary, confidence, changed_by, reason, created_at
             FROM memory_versions WHERE memory_id = ?1 AND version = ?2",
        params![memory_id, version],
        |row| {
            Ok(MemoryVersion {
                memory_id: row.get(0)?,
                version: row.get(1)?,
                content: row.get(2)?,
                summary: row.get(3)?,
                confidence: row.get(4)?,
                changed_by: row.get(5)?,
                reason: row.get(6)?,
                created_at: row.get(7)?,
            })
        },
    );

    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(to_storage_err(e.to_string())),
    }
}

/// Count versions for a memory.
pub fn version_count(conn: &Connection, memory_id: &str) -> CortexResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM memory_versions WHERE memory_id = ?1",
        params![memory_id],
        |row| row.get(0),
    )
    .map_err(|e| to_storage_err(e.to_string()))
}

/// Enforce retention: keep only the latest `max_versions` versions.
pub fn enforce_retention(
    conn: &Connection,
    memory_id: &str,
    max_versions: i64,
) -> CortexResult<usize> {
    let deleted = conn
        .execute(
            "DELETE FROM memory_versions
             WHERE memory_id = ?1 AND version NOT IN (
                SELECT version FROM memory_versions
                WHERE memory_id = ?1
                ORDER BY version DESC
                LIMIT ?2
             )",
            params![memory_id, max_versions],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(deleted)
}
