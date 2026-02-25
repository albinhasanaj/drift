//! Queries for the constants table — named constants and magic numbers.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A constant record.
#[derive(Debug, Clone)]
pub struct ConstantRow {
    pub id: i64,
    pub name: String,
    pub value: String,
    pub file: String,
    pub line: i64,
    pub is_used: bool,
    pub language: String,
    pub is_named: bool,
    pub created_at: i64,
}

/// Insert a constant record.
pub fn insert(conn: &Connection, row: &ConstantRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO constants (name, value, file, line, is_used, language, is_named)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.name,
            row.value,
            row.file,
            row.line,
            row.is_used as i32,
            row.language,
            row.is_named as i32,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Insert a batch of constant records.
pub fn insert_batch(conn: &Connection, rows: &[ConstantRow]) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO constants (name, value, file, line, is_used, language, is_named)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(params![
            row.name,
            row.value,
            row.file,
            row.line,
            row.is_used as i32,
            row.language,
            row.is_named as i32,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

/// Query constants by file.
pub fn query_by_file(conn: &Connection, file: &str) -> Result<Vec<ConstantRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, value, file, line, is_used, language, is_named, created_at
             FROM constants WHERE file = ?1 ORDER BY line ASC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query unused constants.
pub fn query_unused(conn: &Connection) -> Result<Vec<ConstantRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, value, file, line, is_used, language, is_named, created_at
             FROM constants WHERE is_used = 0 ORDER BY file, line",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query magic numbers (unnamed constants).
pub fn query_magic_numbers(conn: &Connection) -> Result<Vec<ConstantRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, value, file, line, is_used, language, is_named, created_at
             FROM constants WHERE is_named = 0 ORDER BY file, line",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Delete constants by file.
pub fn delete_by_file(conn: &Connection, file: &str) -> Result<usize, StorageError> {
    conn.execute("DELETE FROM constants WHERE file = ?1", params![file])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total constants.
pub fn count(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM constants", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<ConstantRow> {
    Ok(ConstantRow {
        id: row.get(0)?,
        name: row.get(1)?,
        value: row.get(2)?,
        file: row.get(3)?,
        line: row.get(4)?,
        is_used: row.get::<_, i32>(5)? != 0,
        language: row.get(6)?,
        is_named: row.get::<_, i32>(7)? != 0,
        created_at: row.get(8)?,
    })
}
