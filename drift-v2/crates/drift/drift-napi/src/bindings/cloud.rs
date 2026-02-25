//! Cloud data reader bindings for the sync pipeline.
//!
//! Exposes: drift_cloud_read_rows(), drift_cloud_max_cursor()
//!
//! These are used by the TypeScript SyncClient to read rows from local
//! SQLite databases (drift.db, bridge.db) for upload to Supabase.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::conversions::error_codes;
use crate::runtime;

fn storage_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
}

/// Read rows from a local table for cloud sync.
///
/// Returns an array of JSON objects, one per row.
/// Supports delta sync via `after_cursor` (rowid filter).
///
/// @param table - Local table name (e.g. "violations", "bridge_memories")
/// @param db - Which database: "drift" or "bridge"
/// @param after_cursor - Only return rows with rowid > this value (0 for all)
/// @param limit - Max rows to return (default 5000)
#[napi(js_name = "driftCloudReadRows")]
pub fn drift_cloud_read_rows(
    table: String,
    db: String,
    after_cursor: Option<i64>,
    limit: Option<u32>,
) -> Result<serde_json::Value> {
    let rt = runtime::get()?;
    let cursor = after_cursor.unwrap_or(0);
    let row_limit = limit.unwrap_or(5000) as usize;

    // Validate table name to prevent SQL injection (only allow alphanumeric + underscore)
    if !table.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(napi::Error::from_reason(format!(
            "[{}] Invalid table name: {table}",
            error_codes::INVALID_FILTER
        )));
    }

    match db.as_str() {
        "drift" => {
            let rows = rt.storage.with_reader(|conn| {
                read_table_rows(conn, &table, cursor, row_limit)
            }).map_err(storage_err)?;
            Ok(serde_json::Value::Array(rows))
        }
        "bridge" => {
            let bridge = rt.bridge_store.as_ref().ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "[{}] Bridge not initialized",
                    error_codes::STORAGE_ERROR
                ))
            })?;
            let rows = bridge.with_reader(|conn| {
                read_table_rows(conn, &table, cursor, row_limit)
                    .map_err(|e| cortex_drift_bridge::errors::BridgeError::Config(e.to_string()))
            }).map_err(storage_err)?;
            Ok(serde_json::Value::Array(rows))
        }
        other => Err(napi::Error::from_reason(format!(
            "[{}] Unknown db '{other}'. Expected: drift, bridge",
            error_codes::INVALID_FILTER
        ))),
    }
}

/// Get the maximum rowid from a local database table set.
///
/// Returns the highest rowid across all syncable tables in the given DB,
/// which serves as the sync cursor for delta tracking.
///
/// @param db - Which database: "drift" or "bridge"
#[napi(js_name = "driftCloudMaxCursor")]
pub fn drift_cloud_max_cursor(db: String) -> Result<i64> {
    let rt = runtime::get()?;

    match db.as_str() {
        "drift" => {
            let max = rt.storage.with_reader(|conn| {
                max_rowid(conn)
            }).map_err(storage_err)?;
            Ok(max)
        }
        "bridge" => {
            let bridge = rt.bridge_store.as_ref().ok_or_else(|| {
                napi::Error::from_reason(format!(
                    "[{}] Bridge not initialized",
                    error_codes::STORAGE_ERROR
                ))
            })?;
            let max = bridge.with_reader(|conn| {
                max_rowid(conn)
                    .map_err(|e| cortex_drift_bridge::errors::BridgeError::Config(e.to_string()))
            }).map_err(storage_err)?;
            Ok(max)
        }
        other => Err(napi::Error::from_reason(format!(
            "[{}] Unknown db '{other}'. Expected: drift, bridge",
            error_codes::INVALID_FILTER
        ))),
    }
}

/// Read rows from a SQLite table as JSON objects.
///
/// Uses a generic approach: reads column names from the statement and
/// maps each row to a serde_json::Value::Object.
fn read_table_rows(
    conn: &rusqlite::Connection,
    table: &str,
    after_cursor: i64,
    limit: usize,
) -> std::result::Result<Vec<serde_json::Value>, drift_core::errors::StorageError> {
    let sql = format!(
        "SELECT *, rowid as _rowid FROM {} WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2",
        table
    );

    let mut stmt = conn.prepare(&sql).map_err(|e| {
        drift_core::errors::StorageError::SqliteError {
            message: format!("Failed to prepare query for {table}: {e}"),
        }
    })?;

    let column_names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|n| n.to_string())
        .collect();

    let rows = stmt
        .query_map(rusqlite::params![after_cursor, limit], |row| {
            let mut map = serde_json::Map::new();
            for (i, name) in column_names.iter().enumerate() {
                let value = row_value_to_json(row, i);
                map.insert(name.clone(), value);
            }
            Ok(serde_json::Value::Object(map))
        })
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: format!("Failed to query {table}: {e}"),
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

/// Convert a SQLite row value at a given index to a serde_json::Value.
fn row_value_to_json(row: &rusqlite::Row, idx: usize) -> serde_json::Value {
    // Try each SQLite type in order of likelihood
    if let Ok(v) = row.get::<_, i64>(idx) {
        return serde_json::Value::Number(serde_json::Number::from(v));
    }
    if let Ok(v) = row.get::<_, f64>(idx) {
        return serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.get::<_, String>(idx) {
        return serde_json::Value::String(v);
    }
    if let Ok(v) = row.get::<_, Vec<u8>>(idx) {
        // Encode BLOB as hex string (inline to avoid hex crate dependency)
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        return serde_json::Value::String(hex);
    }
    serde_json::Value::Null
}

/// Get the max rowid across key tables in a database.
fn max_rowid(
    conn: &rusqlite::Connection,
) -> std::result::Result<i64, drift_core::errors::StorageError> {
    // Use sqlite_sequence if available, otherwise fall back to max(rowid)
    let result: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(result)
}
