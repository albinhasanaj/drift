//! Raw SQL operations for the memory_snapshots table.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Raw snapshot row from the database.
#[derive(Debug, Clone)]
pub struct RawSnapshot {
    pub snapshot_id: u64,
    pub memory_id: String,
    pub snapshot_at: String,
    pub state: Vec<u8>,
    pub event_id: u64,
    pub reason: String,
}

/// Insert a snapshot. Returns the assigned snapshot_id.
pub fn insert_snapshot(
    conn: &Connection,
    memory_id: &str,
    snapshot_at: &str,
    state: &[u8],
    event_id: u64,
    reason: &str,
) -> CortexResult<u64> {
    conn.execute(
        "INSERT INTO memory_snapshots (memory_id, snapshot_at, state, event_id, reason)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![memory_id, snapshot_at, state, event_id as i64, reason],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(conn.last_insert_rowid() as u64)
}

/// Get the nearest snapshot for a memory before a given time.
pub fn get_nearest_snapshot(
    conn: &Connection,
    memory_id: &str,
    before: &str,
) -> CortexResult<Option<RawSnapshot>> {
    let result = conn.query_row(
        "SELECT snapshot_id, memory_id, snapshot_at, state, event_id, reason
         FROM memory_snapshots
         WHERE memory_id = ?1 AND snapshot_at <= ?2
         ORDER BY snapshot_at DESC
         LIMIT 1",
        params![memory_id, before],
        row_to_raw_snapshot,
    );

    match result {
        Ok(s) => Ok(Some(s)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(to_storage_err(e.to_string())),
    }
}

/// Get all snapshots for a memory.
pub fn get_snapshots_for_memory(
    conn: &Connection,
    memory_id: &str,
) -> CortexResult<Vec<RawSnapshot>> {
    let mut stmt = conn
        .prepare(
            "SELECT snapshot_id, memory_id, snapshot_at, state, event_id, reason
             FROM memory_snapshots WHERE memory_id = ?1
             ORDER BY snapshot_at DESC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![memory_id], row_to_raw_snapshot)
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}

/// Delete snapshots older than a given date, keeping at most one per month.
/// Returns the number of snapshots deleted.
pub fn delete_old_snapshots(
    conn: &Connection,
    before_date: &str,
    keep_monthly: bool,
) -> CortexResult<u64> {
    if keep_monthly {
        // Keep the latest snapshot per memory per month, delete the rest.
        let deleted = conn
            .execute(
                "DELETE FROM memory_snapshots
                 WHERE snapshot_at < ?1
                 AND snapshot_id NOT IN (
                     SELECT MAX(snapshot_id)
                     FROM memory_snapshots
                     WHERE snapshot_at < ?1
                     GROUP BY memory_id, strftime('%Y-%m', snapshot_at)
                 )",
                params![before_date],
            )
            .map_err(|e| to_storage_err(e.to_string()))? as u64;
        Ok(deleted)
    } else {
        let deleted = conn
            .execute(
                "DELETE FROM memory_snapshots WHERE snapshot_at < ?1",
                params![before_date],
            )
            .map_err(|e| to_storage_err(e.to_string()))? as u64;
        Ok(deleted)
    }
}

fn row_to_raw_snapshot(row: &rusqlite::Row<'_>) -> Result<RawSnapshot, rusqlite::Error> {
    Ok(RawSnapshot {
        snapshot_id: row.get::<_, i64>(0)? as u64,
        memory_id: row.get(1)?,
        snapshot_at: row.get(2)?,
        state: row.get(3)?,
        event_id: row.get::<_, i64>(4)? as u64,
        reason: row.get(5)?,
    })
}
