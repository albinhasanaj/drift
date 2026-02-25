//! boundaries table queries.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A boundary record from the database.
#[derive(Debug, Clone)]
pub struct BoundaryRecord {
    pub id: i64,
    pub file: String,
    pub framework: String,
    pub model_name: String,
    pub table_name: Option<String>,
    pub field_name: Option<String>,
    pub sensitivity: Option<String>,
    pub confidence: f64,
    pub created_at: i64,
}

/// Insert a batch of boundary records.
pub fn insert_boundaries(
    conn: &Connection,
    boundaries: &[BoundaryRecord],
) -> Result<usize, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO boundaries
             (file, framework, model_name, table_name, field_name, sensitivity, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut count = 0;
    for b in boundaries {
        stmt.execute(params![
            b.file, b.framework, b.model_name, b.table_name,
            b.field_name, b.sensitivity, b.confidence,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
        count += 1;
    }
    Ok(count)
}

/// Get all boundaries for a given file.
pub fn get_boundaries_by_file(
    conn: &Connection,
    file: &str,
) -> Result<Vec<BoundaryRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, framework, model_name, table_name, field_name,
                    sensitivity, confidence, created_at
             FROM boundaries WHERE file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(BoundaryRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                framework: row.get(2)?,
                model_name: row.get(3)?,
                table_name: row.get(4)?,
                field_name: row.get(5)?,
                sensitivity: row.get(6)?,
                confidence: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Get all boundaries by framework.
pub fn get_boundaries_by_framework(
    conn: &Connection,
    framework: &str,
) -> Result<Vec<BoundaryRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, framework, model_name, table_name, field_name,
                    sensitivity, confidence, created_at
             FROM boundaries WHERE framework = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![framework], |row| {
            Ok(BoundaryRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                framework: row.get(2)?,
                model_name: row.get(3)?,
                table_name: row.get(4)?,
                field_name: row.get(5)?,
                sensitivity: row.get(6)?,
                confidence: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Get all sensitive field boundaries.
pub fn get_sensitive_boundaries(
    conn: &Connection,
) -> Result<Vec<BoundaryRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, framework, model_name, table_name, field_name,
                    sensitivity, confidence, created_at
             FROM boundaries WHERE sensitivity IS NOT NULL ORDER BY confidence DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(BoundaryRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                framework: row.get(2)?,
                model_name: row.get(3)?,
                table_name: row.get(4)?,
                field_name: row.get(5)?,
                sensitivity: row.get(6)?,
                confidence: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Delete all boundaries for a given file.
pub fn delete_boundaries_by_file(
    conn: &Connection,
    file: &str,
) -> Result<usize, StorageError> {
    conn.execute("DELETE FROM boundaries WHERE file = ?1", params![file])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total boundaries.
pub fn count_boundaries(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM boundaries", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}
