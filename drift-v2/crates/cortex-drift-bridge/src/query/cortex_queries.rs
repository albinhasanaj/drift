//! Parameterized queries against cortex.db (via bridge_memories table).
//!
//! These queries read from the bridge's local copy of memories.
//! For full Cortex memory queries, use the cortex_writer module (Phase 1-03).

use rusqlite::Connection;

use crate::errors::BridgeResult;

/// Look up a memory by ID from bridge_memories.
pub fn get_memory_by_id(
    conn: &Connection,
    memory_id: &str,
) -> BridgeResult<Option<MemoryRow>> {
    let result = conn.query_row(
        "SELECT id, memory_type, content, summary, confidence, importance, tags, linked_patterns, created_at
         FROM bridge_memories WHERE id = ?1",
        rusqlite::params![memory_id],
        |row| {
            Ok(MemoryRow {
                id: row.get(0)?,
                memory_type: row.get(1)?,
                content: row.get(2)?,
                summary: row.get(3)?,
                confidence: row.get(4)?,
                importance: row.get(5)?,
                tags: row.get(6)?,
                linked_patterns: row.get(7)?,
                created_at: row.get(8)?,
            })
        },
    );
    match result {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Find memories by type.
pub fn get_memories_by_type(
    conn: &Connection,
    memory_type: &str,
    limit: usize,
) -> BridgeResult<Vec<MemoryRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, memory_type, content, summary, confidence, importance, tags, linked_patterns, created_at
         FROM bridge_memories WHERE memory_type = ?1 ORDER BY created_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![memory_type, limit as i64], |row| {
        Ok(MemoryRow {
            id: row.get(0)?,
            memory_type: row.get(1)?,
            content: row.get(2)?,
            summary: row.get(3)?,
            confidence: row.get(4)?,
            importance: row.get(5)?,
            tags: row.get(6)?,
            linked_patterns: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

/// Find memories by tag (substring match in JSON array).
///
/// Uses SQLite `ESCAPE` clause to prevent `%` and `_` in tag values from
/// being interpreted as LIKE wildcards (P1-6).
pub fn get_memories_by_tag(
    conn: &Connection,
    tag: &str,
    limit: usize,
) -> BridgeResult<Vec<MemoryRow>> {
    let escaped_tag = escape_like(tag);
    let pattern = format!("%\"{}\"%" , escaped_tag);
    let mut stmt = conn.prepare(
        "SELECT id, memory_type, content, summary, confidence, importance, tags, linked_patterns, created_at
         FROM bridge_memories WHERE tags LIKE ?1 ESCAPE '\\' ORDER BY created_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![pattern, limit as i64], |row| {
        Ok(MemoryRow {
            id: row.get(0)?,
            memory_type: row.get(1)?,
            content: row.get(2)?,
            summary: row.get(3)?,
            confidence: row.get(4)?,
            importance: row.get(5)?,
            tags: row.get(6)?,
            linked_patterns: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

/// Count total memories in bridge_memories.
pub fn count_memories(conn: &Connection) -> BridgeResult<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_memories",
        [],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// Count memories by type.
pub fn count_memories_by_type(conn: &Connection, memory_type: &str) -> BridgeResult<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bridge_memories WHERE memory_type = ?1",
        rusqlite::params![memory_type],
        |row| row.get(0),
    )?;
    Ok(count as u64)
}

/// Escape SQLite LIKE wildcards (`%`, `_`, `\`) in a string.
///
/// Used with `LIKE pattern ESCAPE '\'` to prevent user-supplied values
/// from being interpreted as wildcards.
pub(crate) fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("\\%"),
            '_' => out.push_str("\\_"),
            other => out.push(other),
        }
    }
    out
}

/// Raw row from bridge_memories table.
#[derive(Debug, Clone)]
pub struct MemoryRow {
    pub id: String,
    pub memory_type: String,
    pub content: String,
    pub summary: String,
    pub confidence: f64,
    pub importance: String,
    pub tags: String,
    pub linked_patterns: String,
    pub created_at: i64,
}
