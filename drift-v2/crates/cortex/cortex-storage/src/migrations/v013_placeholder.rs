//! v013 placeholder migration — closes the v012→v014 gap.
//!
//! F-04: This version was inadvertently skipped during development.
//! Adding a no-op placeholder ensures version numbering is contiguous,
//! which prevents confusion in migration audits and tooling.

use cortex_core::errors::CortexResult;
use rusqlite::Connection;

pub fn migrate(_conn: &Connection) -> CortexResult<()> {
    // No-op: placeholder to close the v012→v014 numbering gap.
    Ok(())
}
