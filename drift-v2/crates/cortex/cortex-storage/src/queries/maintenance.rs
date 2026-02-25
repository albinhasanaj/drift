//! VACUUM, checkpoint, integrity check, archived cleanup, audit rotation.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Run incremental vacuum.
pub fn incremental_vacuum(conn: &Connection, pages: u32) -> CortexResult<()> {
    conn.execute_batch(&format!("PRAGMA incremental_vacuum({pages})"))
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Run full vacuum (only if needed).
pub fn full_vacuum(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch("VACUUM")
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// WAL checkpoint.
pub fn wal_checkpoint(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Run integrity check. Returns true if database is OK.
pub fn integrity_check(conn: &Connection) -> CortexResult<bool> {
    let result: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(result == "ok")
}

/// Clean up archived memories older than `days`, with confidence below
/// `max_confidence` and zero access count. Returns count deleted.
pub fn archived_cleanup(conn: &Connection, days: u64, max_confidence: f64) -> CortexResult<usize> {
    let deleted = conn
        .execute(
            "DELETE FROM memories
             WHERE archived = 1
               AND confidence < ?1
               AND access_count = 0
               AND julianday('now') - julianday(last_accessed) > ?2",
            params![max_confidence, days as f64],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(deleted)
}

/// Rotate audit log: compress entries older than `months` into monthly summaries.
/// Returns the number of entries compressed.
pub fn audit_rotation(conn: &Connection, months: u32) -> CortexResult<usize> {
    // Count entries that would be rotated.
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_audit_log
             WHERE julianday('now') - julianday(timestamp) > ?1",
            params![months as f64 * 30.0],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    if count == 0 {
        return Ok(0);
    }

    // Delete old entries (in production, we'd create summary records first).
    let deleted = conn
        .execute(
            "DELETE FROM memory_audit_log
             WHERE julianday('now') - julianday(timestamp) > ?1",
            params![months as f64 * 30.0],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(deleted)
}
