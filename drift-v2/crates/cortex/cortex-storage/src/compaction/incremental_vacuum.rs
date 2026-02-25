//! Weekly: PRAGMA incremental_vacuum(1000).

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::maintenance;

/// Default pages to vacuum.
pub const DEFAULT_PAGES: u32 = 1000;

/// Run incremental vacuum.
pub fn vacuum(conn: &Connection) -> CortexResult<()> {
    maintenance::incremental_vacuum(conn, DEFAULT_PAGES)
}
