//! Raw SQL operations for the drift_snapshots table.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Insert a drift snapshot (stored as JSON).
pub fn insert_drift_snapshot(
    conn: &Connection,
    timestamp: &str,
    window_seconds: i64,
    snapshot_json: &str,
) -> CortexResult<u64> {
    conn.execute(
        "INSERT INTO drift_snapshots (timestamp, window_seconds, metrics)
         VALUES (?1, ?2, ?3)",
        params![timestamp, window_seconds, snapshot_json],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let id = conn.last_insert_rowid() as u64;
    Ok(id)
}

/// Raw drift snapshot row from the database.
#[derive(Debug, Clone)]
pub struct RawDriftSnapshot {
    pub snapshot_id: u64,
    pub timestamp: String,
    pub metrics: String,
}

/// Get drift snapshots within a time range.
pub fn get_drift_snapshots(
    conn: &Connection,
    from: &str,
    to: &str,
) -> CortexResult<Vec<RawDriftSnapshot>> {
    let mut stmt = conn
        .prepare(
            "SELECT snapshot_id, timestamp, metrics
             FROM drift_snapshots
             WHERE timestamp >= ?1 AND timestamp <= ?2
             ORDER BY timestamp ASC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![from, to], |row| {
            Ok(RawDriftSnapshot {
                snapshot_id: row.get::<_, i64>(0)? as u64,
                timestamp: row.get(1)?,
                metrics: row.get(2)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut snapshots = Vec::new();
    for row in rows {
        snapshots.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(snapshots)
}

/// Get the most recent drift snapshot.
pub fn get_latest_drift_snapshot(conn: &Connection) -> CortexResult<Option<RawDriftSnapshot>> {
    let mut stmt = conn
        .prepare(
            "SELECT snapshot_id, timestamp, metrics
             FROM drift_snapshots
             ORDER BY timestamp DESC
             LIMIT 1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut rows = stmt
        .query_map([], |row| {
            Ok(RawDriftSnapshot {
                snapshot_id: row.get::<_, i64>(0)? as u64,
                timestamp: row.get(1)?,
                metrics: row.get(2)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    match rows.next() {
        Some(row) => Ok(Some(row.map_err(|e| to_storage_err(e.to_string()))?)),
        None => Ok(None),
    }
}
