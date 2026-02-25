//! Version retention policy: max 10 versions per memory.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::version_ops;

/// Maximum versions to retain per memory.
pub const MAX_VERSIONS: i64 = 10;

/// Enforce retention: delete versions beyond the limit.
pub fn enforce(conn: &Connection, memory_id: &str) -> CortexResult<usize> {
    version_ops::enforce_retention(conn, memory_id, MAX_VERSIONS)
}
