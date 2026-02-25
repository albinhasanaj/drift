//! Version queries: get history, get at version, diff between versions.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::version_ops::{self, MemoryVersion};

/// Get the full version history for a memory.
pub fn get_history(conn: &Connection, memory_id: &str) -> CortexResult<Vec<MemoryVersion>> {
    version_ops::get_version_history(conn, memory_id)
}

/// Get a memory at a specific version.
pub fn get_at_version(
    conn: &Connection,
    memory_id: &str,
    version: i64,
) -> CortexResult<Option<MemoryVersion>> {
    version_ops::get_at_version(conn, memory_id, version)
}

/// Simple diff between two versions (returns both contents).
pub fn diff_versions(
    conn: &Connection,
    memory_id: &str,
    version_a: i64,
    version_b: i64,
) -> CortexResult<Option<(MemoryVersion, MemoryVersion)>> {
    let a = version_ops::get_at_version(conn, memory_id, version_a)?;
    let b = version_ops::get_at_version(conn, memory_id, version_b)?;
    match (a, b) {
        (Some(a), Some(b)) => Ok(Some((a, b))),
        _ => Ok(None),
    }
}
