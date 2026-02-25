//! Materialized security view — aggregated security posture.

use rusqlite::Connection;
use drift_core::errors::StorageError;

/// Refresh the materialized security view.
pub fn refresh_security(conn: &Connection) -> Result<SecurityView, StorageError> {
    let critical: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM violations WHERE severity = 'error' AND cwe_id IS NOT NULL AND suppressed = 0",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let high: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM violations WHERE severity = 'warning' AND cwe_id IS NOT NULL AND suppressed = 0",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let total_security: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM violations WHERE cwe_id IS NOT NULL AND suppressed = 0",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(SecurityView {
        critical_count: critical,
        high_count: high,
        total_security_violations: total_security,
    })
}

#[derive(Debug, Clone, Default)]
pub struct SecurityView {
    pub critical_count: u32,
    pub high_count: u32,
    pub total_security_violations: u32,
}
