//! Count by type, avg confidence, stale count, storage stats, growth rate.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::memory::MemoryType;

use crate::to_storage_err;

/// Count memories grouped by type.
pub fn count_by_type(conn: &Connection) -> CortexResult<Vec<(MemoryType, usize)>> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_type, COUNT(*) FROM memories
             WHERE archived = 0 GROUP BY memory_type",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let (type_str, count) = row.map_err(|e| to_storage_err(e.to_string()))?;
        if let Ok(mt) = serde_json::from_str::<MemoryType>(&format!("\"{type_str}\"")) {
            results.push((mt, count as usize));
        }
    }
    Ok(results)
}

/// Average confidence across all active memories.
pub fn average_confidence(conn: &Connection) -> CortexResult<f64> {
    conn.query_row(
        "SELECT COALESCE(AVG(confidence), 0.0) FROM memories WHERE archived = 0",
        [],
        |row| row.get(0),
    )
    .map_err(|e| to_storage_err(e.to_string()))
}

/// Count memories not accessed within `threshold_days`.
pub fn stale_count(conn: &Connection, threshold_days: u64) -> CortexResult<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories
             WHERE archived = 0
               AND julianday('now') - julianday(last_accessed) > ?1",
            params![threshold_days as f64],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(count as usize)
}

/// Storage statistics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_memories: usize,
    pub active_memories: usize,
    pub archived_memories: usize,
    pub total_embeddings: usize,
    pub total_relationships: usize,
    pub total_audit_entries: usize,
}

/// Get storage statistics.
pub fn storage_stats(conn: &Connection) -> CortexResult<StorageStats> {
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;
    let active: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE archived = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    let embeddings: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_embeddings", [], |row| {
            row.get(0)
        })
        .map_err(|e| to_storage_err(e.to_string()))?;
    let relationships: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_relationships", [], |row| {
            row.get(0)
        })
        .map_err(|e| to_storage_err(e.to_string()))?;
    let audit: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_audit_log", [], |row| {
            row.get(0)
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(StorageStats {
        total_memories: total as usize,
        active_memories: active as usize,
        archived_memories: (total - active) as usize,
        total_embeddings: embeddings as usize,
        total_relationships: relationships as usize,
        total_audit_entries: audit as usize,
    })
}
