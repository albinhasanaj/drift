//! PRAGMA integrity_check, detect corruption early.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::maintenance;

/// Run integrity check. Returns true if database is healthy.
pub fn check_integrity(conn: &Connection) -> CortexResult<bool> {
    maintenance::integrity_check(conn)
}
