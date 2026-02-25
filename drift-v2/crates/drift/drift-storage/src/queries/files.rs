//! file_metadata CRUD queries.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A file metadata record from the database.
#[derive(Debug, Clone)]
pub struct FileMetadataRecord {
    pub path: String,
    pub language: Option<String>,
    pub file_size: i64,
    pub content_hash: Vec<u8>,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub last_scanned_at: i64,
    pub scan_duration_us: Option<i64>,
    pub pattern_count: i64,
    pub function_count: i64,
    pub error_count: i64,
    pub error: Option<String>,
}

/// Load all file metadata (for incremental scan comparison).
pub fn load_all_file_metadata(
    conn: &Connection,
) -> Result<Vec<FileMetadataRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT path, language, file_size, content_hash, mtime_secs, mtime_nanos,
                    last_scanned_at, scan_duration_us, pattern_count, function_count,
                    error_count, error
             FROM file_metadata",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(FileMetadataRecord {
                path: row.get(0)?,
                language: row.get(1)?,
                file_size: row.get(2)?,
                content_hash: row.get(3)?,
                mtime_secs: row.get(4)?,
                mtime_nanos: row.get(5)?,
                last_scanned_at: row.get(6)?,
                scan_duration_us: row.get(7)?,
                pattern_count: row.get(8)?,
                function_count: row.get(9)?,
                error_count: row.get(10)?,
                error: row.get(11)?,
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

/// Get file metadata for a specific path.
pub fn get_file_metadata(
    conn: &Connection,
    path: &str,
) -> Result<Option<FileMetadataRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT path, language, file_size, content_hash, mtime_secs, mtime_nanos,
                    last_scanned_at, scan_duration_us, pattern_count, function_count,
                    error_count, error
             FROM file_metadata WHERE path = ?1",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let mut rows = stmt
        .query_map(params![path], |row| {
            Ok(FileMetadataRecord {
                path: row.get(0)?,
                language: row.get(1)?,
                file_size: row.get(2)?,
                content_hash: row.get(3)?,
                mtime_secs: row.get(4)?,
                mtime_nanos: row.get(5)?,
                last_scanned_at: row.get(6)?,
                scan_duration_us: row.get(7)?,
                pattern_count: row.get(8)?,
                function_count: row.get(9)?,
                error_count: row.get(10)?,
                error: row.get(11)?,
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

/// Update the function_count counter cache for a file.
pub fn update_function_count(
    conn: &Connection,
    path: &str,
    count: i64,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE file_metadata SET function_count = ?1 WHERE path = ?2",
        params![count, path],
    )
    .map_err(|e| StorageError::SqliteError {
        message: e.to_string(),
    })?;
    Ok(())
}

/// Update the error fields for a file.
pub fn update_file_error(
    conn: &Connection,
    path: &str,
    error_count: i64,
    error_msg: Option<&str>,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE file_metadata SET error_count = ?1, error = ?2 WHERE path = ?3",
        params![error_count, error_msg, path],
    )
    .map_err(|e| StorageError::SqliteError {
        message: e.to_string(),
    })?;
    Ok(())
}

/// Count total files in the database.
pub fn count_files(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
}
