//! Memories archived > 90 days, confidence < 0.1, zero access → permanent delete (keep tombstone).

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::maintenance;

/// Default threshold: 90 days.
pub const DEFAULT_DAYS: u64 = 90;
/// Default max confidence for cleanup.
pub const DEFAULT_MAX_CONFIDENCE: f64 = 0.1;

/// Run archived cleanup with default thresholds.
pub fn cleanup(conn: &Connection) -> CortexResult<usize> {
    maintenance::archived_cleanup(conn, DEFAULT_DAYS, DEFAULT_MAX_CONFIDENCE)
}

/// Run archived cleanup with custom thresholds.
pub fn cleanup_with_thresholds(
    conn: &Connection,
    days: u64,
    max_confidence: f64,
) -> CortexResult<usize> {
    maintenance::archived_cleanup(conn, days, max_confidence)
}
