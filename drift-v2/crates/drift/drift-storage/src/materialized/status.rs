//! Materialized status view — aggregated project health status.

use rusqlite::Connection;
use drift_core::errors::StorageError;

/// Refresh the materialized_status view.
pub fn refresh_status(conn: &Connection) -> Result<StatusView, StorageError> {
    // Get latest audit snapshot
    let snapshot = conn
        .query_row(
            "SELECT health_score, avg_confidence, pattern_count, created_at
             FROM audit_snapshots ORDER BY created_at DESC LIMIT 1",
            [],
            |row| {
                Ok(StatusView {
                    health_score: row.get(0)?,
                    avg_confidence: row.get(1)?,
                    pattern_count: row.get(2)?,
                    violation_count: 0,
                    gate_pass_count: 0,
                    gate_fail_count: 0,
                    last_updated: row.get(3)?,
                })
            },
        )
        .unwrap_or_default();

    // Get violation count
    let violation_count: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM violations WHERE suppressed = 0",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Get latest gate results
    let gate_pass: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM gate_results WHERE passed = 1
             AND run_at = (SELECT MAX(run_at) FROM gate_results)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let gate_fail: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM gate_results WHERE passed = 0
             AND run_at = (SELECT MAX(run_at) FROM gate_results)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(StatusView {
        violation_count,
        gate_pass_count: gate_pass,
        gate_fail_count: gate_fail,
        ..snapshot
    })
}

#[derive(Debug, Clone, Default)]
pub struct StatusView {
    pub health_score: f64,
    pub avg_confidence: f64,
    pub pattern_count: u32,
    pub violation_count: u32,
    pub gate_pass_count: u32,
    pub gate_fail_count: u32,
    pub last_updated: u64,
}
