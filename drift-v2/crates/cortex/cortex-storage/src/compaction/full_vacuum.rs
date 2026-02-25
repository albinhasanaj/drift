//! Quarterly: only if fragmentation > 30%.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::maintenance;

/// Run full vacuum.
pub fn vacuum(conn: &Connection) -> CortexResult<()> {
    maintenance::full_vacuum(conn)
}
