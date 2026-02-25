//! functions table queries.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A function record from the database.
#[derive(Debug, Clone)]
pub struct FunctionRecord {
    pub id: i64,
    pub file: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub language: String,
    pub line: i64,
    pub end_line: i64,
    pub parameter_count: i64,
    pub return_type: Option<String>,
    pub is_exported: bool,
    pub is_async: bool,
    pub body_hash: Option<Vec<u8>>,
    pub signature_hash: Option<Vec<u8>>,
}

/// Get all functions for a given file.
pub fn get_functions_by_file(
    conn: &Connection,
    file: &str,
) -> Result<Vec<FunctionRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, name, qualified_name, language, line, end_line,
                    parameter_count, return_type, is_exported, is_async,
                    body_hash, signature_hash
             FROM functions WHERE file = ?1 ORDER BY line",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(FunctionRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                name: row.get(2)?,
                qualified_name: row.get(3)?,
                language: row.get(4)?,
                line: row.get(5)?,
                end_line: row.get(6)?,
                parameter_count: row.get(7)?,
                return_type: row.get(8)?,
                is_exported: row.get(9)?,
                is_async: row.get(10)?,
                body_hash: row.get(11)?,
                signature_hash: row.get(12)?,
            })
        })
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?);
    }
    Ok(result)
}

/// Get a function by qualified name.
pub fn get_function_by_qualified_name(
    conn: &Connection,
    qualified_name: &str,
) -> Result<Option<FunctionRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, name, qualified_name, language, line, end_line,
                    parameter_count, return_type, is_exported, is_async,
                    body_hash, signature_hash
             FROM functions WHERE qualified_name = ?1",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let mut rows = stmt
        .query_map(params![qualified_name], |row| {
            Ok(FunctionRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                name: row.get(2)?,
                qualified_name: row.get(3)?,
                language: row.get(4)?,
                line: row.get(5)?,
                end_line: row.get(6)?,
                parameter_count: row.get(7)?,
                return_type: row.get(8)?,
                is_exported: row.get(9)?,
                is_async: row.get(10)?,
                body_hash: row.get(11)?,
                signature_hash: row.get(12)?,
            })
        })
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    match rows.next() {
        Some(Ok(record)) => Ok(Some(record)),
        Some(Err(e)) => Err(StorageError::SqliteError {
            message: e.to_string(),
        }),
        None => Ok(None),
    }
}

/// Delete all functions for a given file (used when file is re-parsed).
pub fn delete_functions_by_file(
    conn: &Connection,
    file: &str,
) -> Result<usize, StorageError> {
    conn.execute("DELETE FROM functions WHERE file = ?1", params![file])
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
}

/// Count total functions in the database.
pub fn count_functions(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
}

/// Count entry point functions — functions with zero incoming call edges.
pub fn count_entry_points(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row(
        "SELECT COUNT(*) FROM functions f
         WHERE f.id NOT IN (SELECT DISTINCT callee_id FROM call_edges)",
        [],
        |row| row.get(0),
    )
    .map_err(|e| StorageError::SqliteError {
        message: e.to_string(),
    })
}
