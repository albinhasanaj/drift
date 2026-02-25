//! Queries for the scan_history table — append-only log of scan operations.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A scan history record.
#[derive(Debug, Clone)]
pub struct ScanHistoryRow {
    pub id: i64,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub root_path: String,
    pub total_files: Option<i64>,
    pub added_files: Option<i64>,
    pub modified_files: Option<i64>,
    pub removed_files: Option<i64>,
    pub unchanged_files: Option<i64>,
    pub duration_ms: Option<i64>,
    pub status: String,
    pub error: Option<String>,
}

/// Insert a new scan history record (status = 'running'). Returns the row id.
pub fn insert_scan_start(
    conn: &Connection,
    started_at: i64,
    root_path: &str,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO scan_history (started_at, root_path, status) VALUES (?1, ?2, 'running')",
        params![started_at, root_path],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

/// Update a scan history record with completion data.
#[allow(clippy::too_many_arguments)]
pub fn update_scan_complete(
    conn: &Connection,
    id: i64,
    completed_at: i64,
    total_files: i64,
    added_files: i64,
    modified_files: i64,
    removed_files: i64,
    unchanged_files: i64,
    duration_ms: i64,
    status: &str,
    error: Option<&str>,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE scan_history SET
            completed_at = ?1, total_files = ?2, added_files = ?3,
            modified_files = ?4, removed_files = ?5, unchanged_files = ?6,
            duration_ms = ?7, status = ?8, error = ?9
         WHERE id = ?10",
        params![
            completed_at, total_files, added_files, modified_files,
            removed_files, unchanged_files, duration_ms, status, error, id
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query recent scan history entries.
pub fn query_recent(conn: &Connection, limit: usize) -> Result<Vec<ScanHistoryRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, started_at, completed_at, root_path, total_files, added_files,
                    modified_files, removed_files, unchanged_files, duration_ms, status, error
             FROM scan_history ORDER BY started_at DESC LIMIT ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(ScanHistoryRow {
                id: row.get(0)?,
                started_at: row.get(1)?,
                completed_at: row.get(2)?,
                root_path: row.get(3)?,
                total_files: row.get(4)?,
                added_files: row.get(5)?,
                modified_files: row.get(6)?,
                removed_files: row.get(7)?,
                unchanged_files: row.get(8)?,
                duration_ms: row.get(9)?,
                status: row.get(10)?,
                error: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total scan history entries.
pub fn count(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM scan_history", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}
