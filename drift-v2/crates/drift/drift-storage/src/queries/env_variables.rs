//! Queries for the env_variables table — environment variable usage tracking.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// An environment variable record.
#[derive(Debug, Clone)]
pub struct EnvVariableRow {
    pub id: i64,
    pub name: String,
    pub file: String,
    pub line: i64,
    pub access_method: String,
    pub has_default: bool,
    pub defined_in_env: bool,
    pub framework_prefix: Option<String>,
    pub created_at: i64,
}

/// Insert an environment variable record.
pub fn insert(conn: &Connection, row: &EnvVariableRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO env_variables (name, file, line, access_method, has_default, defined_in_env, framework_prefix)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.name,
            row.file,
            row.line,
            row.access_method,
            row.has_default as i32,
            row.defined_in_env as i32,
            row.framework_prefix,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Insert a batch of environment variable records.
pub fn insert_batch(conn: &Connection, rows: &[EnvVariableRow]) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO env_variables (name, file, line, access_method, has_default, defined_in_env, framework_prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    for row in rows {
        stmt.execute(params![
            row.name,
            row.file,
            row.line,
            row.access_method,
            row.has_default as i32,
            row.defined_in_env as i32,
            row.framework_prefix,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    }
    Ok(())
}

/// Query environment variables by name.
pub fn query_by_name(conn: &Connection, name: &str) -> Result<Vec<EnvVariableRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, file, line, access_method, has_default, defined_in_env, framework_prefix, created_at
             FROM env_variables WHERE name = ?1 ORDER BY file, line",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![name], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query environment variables by file.
pub fn query_by_file(conn: &Connection, file: &str) -> Result<Vec<EnvVariableRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, file, line, access_method, has_default, defined_in_env, framework_prefix, created_at
             FROM env_variables WHERE file = ?1 ORDER BY line ASC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query env variables that are missing from .env files (not defined_in_env and no default).
pub fn query_missing(conn: &Connection) -> Result<Vec<EnvVariableRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, file, line, access_method, has_default, defined_in_env, framework_prefix, created_at
             FROM env_variables WHERE defined_in_env = 0 AND has_default = 0 ORDER BY name, file",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], map_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Delete environment variable records by file.
pub fn delete_by_file(conn: &Connection, file: &str) -> Result<usize, StorageError> {
    conn.execute("DELETE FROM env_variables WHERE file = ?1", params![file])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total environment variable records.
pub fn count(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM env_variables", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<EnvVariableRow> {
    Ok(EnvVariableRow {
        id: row.get(0)?,
        name: row.get(1)?,
        file: row.get(2)?,
        line: row.get(3)?,
        access_method: row.get(4)?,
        has_default: row.get::<_, i32>(5)? != 0,
        defined_in_env: row.get::<_, i32>(6)? != 0,
        framework_prefix: row.get(7)?,
        created_at: row.get(8)?,
    })
}
