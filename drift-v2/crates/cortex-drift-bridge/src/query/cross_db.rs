//! Cross-database queries using ATTACH.
//!
//! Pattern: ATTACH drift.db → read → DETACH → write locally.
//! Cross-DB writes are NOT atomic in WAL mode (documented caveat).

use rusqlite::Connection;

use super::attach::AttachGuard;
use crate::errors::BridgeResult;

/// Execute a read-only query against drift.db via ATTACH, returning results.
/// Automatically DETACHes drift.db after the query via RAII guard.
///
/// `query_fn` receives the connection with drift.db attached as "drift".
/// Tables in drift.db are accessible as `drift.<table_name>`.
pub fn with_drift_attached<F, T>(
    bridge_conn: &Connection,
    drift_db_path: &str,
    query_fn: F,
) -> BridgeResult<T>
where
    F: FnOnce(&Connection) -> BridgeResult<T>,
{
    let _guard = AttachGuard::attach(bridge_conn, drift_db_path, "drift")?;
    // Guard auto-DETACHes on drop
    query_fn(bridge_conn)
}

/// Count patterns in drift.db that match a linked pattern from a memory.
/// Requires drift.db to be ATTACHed as "drift".
///
/// Chunks queries into batches of 500 to stay within SQLite's
/// SQLITE_MAX_VARIABLE_NUMBER limit (default 999).
const CHUNK_SIZE: usize = 500;

pub fn count_matching_patterns(
    conn: &Connection,
    pattern_ids: &[String],
) -> BridgeResult<u64> {
    if pattern_ids.is_empty() {
        return Ok(0);
    }

    let mut total: u64 = 0;

    for chunk in pattern_ids.chunks(CHUNK_SIZE) {
        let placeholders: Vec<String> = (1..=chunk.len())
            .map(|i| format!("?{}", i))
            .collect();
        let sql = format!(
            "SELECT COUNT(*) FROM drift.pattern_confidence WHERE pattern_id IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();

        let count: i64 = stmt.query_row(params.as_slice(), |row| row.get(0))?;
        total += count as u64;
    }

    Ok(total)
}

/// Get the latest completed scan timestamp from drift.db.
/// Requires drift.db to be ATTACHed as "drift".
///
/// Queries `scan_history` (v001) for the most recent `completed_at` value
/// among scans with `status = 'completed'`.
pub fn latest_scan_timestamp(conn: &Connection) -> BridgeResult<Option<i64>> {
    let result = conn.query_row(
        "SELECT MAX(completed_at) FROM drift.scan_history WHERE status = 'completed'",
        [],
        |row| row.get::<_, Option<i64>>(0),
    );
    match result {
        Ok(ts) => Ok(ts),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        // Table might not exist — treat as no data
        Err(e) if e.to_string().contains("no such table") => Ok(None),
        Err(e) => Err(e.into()),
    }
}
