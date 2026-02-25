//! Raw SQL operations for the materialized_views table.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Raw materialized view row from the database.
#[derive(Debug, Clone)]
pub struct RawView {
    pub view_id: u64,
    pub label: String,
    pub timestamp: String,
    pub memory_count: usize,
    pub snapshot_ids: String,
    pub drift_snapshot_id: Option<u64>,
    pub created_by: String,
    pub auto_refresh: bool,
}

/// Parameters for inserting a materialized view.
pub struct InsertViewParams<'a> {
    pub label: &'a str,
    pub timestamp: &'a str,
    pub memory_count: usize,
    pub snapshot_ids_json: &'a str,
    pub drift_snapshot_id: Option<u64>,
    pub created_by_json: &'a str,
    pub auto_refresh: bool,
}

/// Insert a materialized view.
pub fn insert_materialized_view(
    conn: &Connection,
    params: &InsertViewParams<'_>,
) -> CortexResult<u64> {
    conn.execute(
        "INSERT INTO materialized_views \
         (label, timestamp, memory_count, snapshot_ids, drift_snapshot_id, created_by, auto_refresh) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            params.label,
            params.timestamp,
            params.memory_count as i64,
            params.snapshot_ids_json,
            params.drift_snapshot_id.map(|id| id as i64),
            params.created_by_json,
            params.auto_refresh as i32,
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let id = conn.last_insert_rowid() as u64;
    Ok(id)
}

/// Get a materialized view by label.
pub fn get_view_by_label(conn: &Connection, label: &str) -> CortexResult<Option<RawView>> {
    let mut stmt = conn
        .prepare(
            "SELECT view_id, label, timestamp, memory_count, snapshot_ids, \
                    drift_snapshot_id, created_by, auto_refresh \
             FROM materialized_views WHERE label = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut rows = stmt
        .query_map(params![label], |row| {
            Ok(RawView {
                view_id: row.get::<_, i64>(0)? as u64,
                label: row.get(1)?,
                timestamp: row.get(2)?,
                memory_count: row.get::<_, i64>(3)? as usize,
                snapshot_ids: row.get(4)?,
                drift_snapshot_id: row
                    .get::<_, Option<i64>>(5)?
                    .map(|id| id as u64),
                created_by: row.get(6)?,
                auto_refresh: row.get::<_, i32>(7)? != 0,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    match rows.next() {
        Some(row) => Ok(Some(row.map_err(|e| to_storage_err(e.to_string()))?)),
        None => Ok(None),
    }
}

/// List all materialized views, ordered by timestamp descending.
pub fn list_views(conn: &Connection) -> CortexResult<Vec<RawView>> {
    let mut stmt = conn
        .prepare(
            "SELECT view_id, label, timestamp, memory_count, snapshot_ids, \
                    drift_snapshot_id, created_by, auto_refresh \
             FROM materialized_views ORDER BY timestamp DESC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(RawView {
                view_id: row.get::<_, i64>(0)? as u64,
                label: row.get(1)?,
                timestamp: row.get(2)?,
                memory_count: row.get::<_, i64>(3)? as usize,
                snapshot_ids: row.get(4)?,
                drift_snapshot_id: row
                    .get::<_, Option<i64>>(5)?
                    .map(|id| id as u64),
                created_by: row.get(6)?,
                auto_refresh: row.get::<_, i32>(7)? != 0,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut views = Vec::new();
    for row in rows {
        views.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(views)
}

/// Delete a materialized view by label.
pub fn delete_view(conn: &Connection, label: &str) -> CortexResult<()> {
    conn.execute(
        "DELETE FROM materialized_views WHERE label = ?1",
        params![label],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
