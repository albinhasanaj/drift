//! Monthly rotation: entries > 1 year compressed into monthly summaries.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::maintenance;

/// Rotate audit entries older than 12 months.
pub fn rotate_audit_log(conn: &Connection) -> CortexResult<usize> {
    maintenance::audit_rotation(conn, 12)
}
