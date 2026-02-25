//! Data retention policies extracted from tables.rs.
//!
//! Retention periods:
//! - bridge_event_log: 30 days
//! - bridge_metrics: 7 days
//! - bridge_grounding_snapshots: 365 days
//! - bridge_grounding_results: 90 days (Community), unlimited (Enterprise)

use chrono::Utc;
use rusqlite::Connection;

use crate::errors::BridgeResult;

/// Retention periods in seconds.
pub const EVENT_LOG_RETENTION_DAYS: i64 = 30;
pub const METRICS_RETENTION_DAYS: i64 = 7;
pub const SNAPSHOT_RETENTION_DAYS: i64 = 365;
pub const GROUNDING_RESULTS_RETENTION_DAYS: i64 = 90;

/// Apply retention policy: delete old records based on license tier.
pub fn apply_retention(conn: &Connection, community_tier: bool) -> BridgeResult<()> {
    let now = Utc::now().timestamp();

    // bridge_event_log: 30 days
    conn.execute(
        "DELETE FROM bridge_event_log WHERE created_at < ?1",
        rusqlite::params![now - EVENT_LOG_RETENTION_DAYS * 86400],
    )?;

    // bridge_metrics: 7 days (exclude schema_version marker used by migrations)
    conn.execute(
        "DELETE FROM bridge_metrics WHERE recorded_at < ?1 AND metric_name != 'schema_version'",
        rusqlite::params![now - METRICS_RETENTION_DAYS * 86400],
    )?;

    // bridge_grounding_snapshots: 365 days
    conn.execute(
        "DELETE FROM bridge_grounding_snapshots WHERE created_at < ?1",
        rusqlite::params![now - SNAPSHOT_RETENTION_DAYS * 86400],
    )?;

    // bridge_grounding_results: 90 days for Community, unlimited for Enterprise
    if community_tier {
        conn.execute(
            "DELETE FROM bridge_grounding_results WHERE created_at < ?1",
            rusqlite::params![now - GROUNDING_RESULTS_RETENTION_DAYS * 86400],
        )?;
    }

    Ok(())
}
