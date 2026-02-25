//! FTS5 full-text search queries.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;

use super::memory_crud::parse_memory_row;
use crate::to_storage_err;

/// Search memories using FTS5 full-text search.
/// Returns memories ranked by BM25 relevance.
pub fn search_fts5(conn: &Connection, query: &str, limit: usize) -> CortexResult<Vec<BaseMemory>> {
    let mut stmt = conn
        .prepare(
            "SELECT m.id, m.memory_type, m.content, m.summary, m.transaction_time,
                    m.valid_time, m.valid_until, m.confidence, m.importance,
                    m.last_accessed, m.access_count, m.tags, m.archived,
                    m.superseded_by, m.supersedes, m.content_hash
             FROM memory_fts fts
             JOIN memories m ON m.rowid = fts.rowid
             WHERE memory_fts MATCH ?1 AND m.archived = 0
             ORDER BY rank
             LIMIT ?2",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![query, limit as i64], |row| {
            Ok(parse_memory_row(row))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
        results.push(memory);
    }
    Ok(results)
}
