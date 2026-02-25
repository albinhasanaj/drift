//! Share embedding rows for identical content hashes.
//!
//! The dedup is handled at insert time via the UNIQUE constraint on
//! `memory_embeddings.content_hash`. This module provides a cleanup
//! function to remove orphaned embeddings.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Remove embedding rows not referenced by any memory.
pub fn cleanup_orphaned_embeddings(conn: &Connection) -> CortexResult<usize> {
    let deleted = conn
        .execute(
            "DELETE FROM memory_embeddings
             WHERE id NOT IN (SELECT embedding_id FROM memory_embedding_link)",
            [],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(deleted)
}
