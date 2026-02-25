//! Attempt WAL checkpoint recovery on corruption.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

/// Attempt to recover by forcing a WAL checkpoint.
pub fn attempt_wal_recovery(conn: &Connection) -> CortexResult<bool> {
    match conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)") {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::warn!("WAL checkpoint recovery failed: {e}");
            Ok(false)
        }
    }
}
