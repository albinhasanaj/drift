//! Queries for the data_access table — function → table access patterns.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A data access record.
#[derive(Debug, Clone)]
pub struct DataAccessRow {
    pub function_id: i64,
    pub table_name: String,
    pub operation: String,
    pub framework: Option<String>,
    pub line: i64,
    pub confidence: f64,
}

/// Insert a data access record.
pub fn insert(conn: &Connection, row: &DataAccessRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR IGNORE INTO data_access (function_id, table_name, operation, framework, line, confidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            row.function_id,
            row.table_name,
            row.operation,
            row.framework,
            row.line,
            row.confidence,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Insert a batch of data access records.
pub fn insert_batch(conn: &Connection, rows: &[DataAccessRow]) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO data_access (function_id, table_name, operation, framework, line, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(params![
            row.function_id,
            row.table_name,
            row.operation,
            row.framework,
            row.line,
            row.confidence,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

/// Query data access records by function_id.
pub fn query_by_function(
    conn: &Connection,
    function_id: i64,
) -> Result<Vec<DataAccessRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT function_id, table_name, operation, framework, line, confidence
             FROM data_access WHERE function_id = ?1 ORDER BY line ASC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![function_id], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query data access records by table name.
pub fn query_by_table(
    conn: &Connection,
    table_name: &str,
) -> Result<Vec<DataAccessRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT function_id, table_name, operation, framework, line, confidence
             FROM data_access WHERE table_name = ?1 ORDER BY function_id ASC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![table_name], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Delete data access records by function_id.
pub fn delete_by_function(conn: &Connection, function_id: i64) -> Result<usize, StorageError> {
    conn.execute(
        "DELETE FROM data_access WHERE function_id = ?1",
        params![function_id],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total data access records.
pub fn count(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM data_access", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<DataAccessRow> {
    Ok(DataAccessRow {
        function_id: row.get(0)?,
        table_name: row.get(1)?,
        operation: row.get(2)?,
        framework: row.get(3)?,
        line: row.get(4)?,
        confidence: row.get(5)?,
    })
}
