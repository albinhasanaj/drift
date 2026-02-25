//! Rebuild FTS5 index from memory content (background).

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Rebuild the FTS5 index from scratch.
pub fn rebuild_fts5_index(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch("INSERT INTO memory_fts(memory_fts) VALUES('rebuild')")
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
