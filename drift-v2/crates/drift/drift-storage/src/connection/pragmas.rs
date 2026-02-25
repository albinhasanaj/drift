//! PRAGMA configuration applied to every SQLite connection.
//!
//! WAL mode, NORMAL sync, 64MB page cache, 256MB mmap, 5s busy_timeout,
//! foreign_keys ON, incremental auto_vacuum, temp_store MEMORY.

use drift_core::errors::StorageError;
use rusqlite::Connection;

/// Apply all performance and safety pragmas to a connection.
pub fn apply_pragmas(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA cache_size = -64000;
        PRAGMA mmap_size = 268435456;
        PRAGMA busy_timeout = 5000;
        PRAGMA temp_store = MEMORY;
        ",
    )
    .map_err(|e| StorageError::SqliteError {
        message: format!("failed to apply pragmas: {e}"),
    })?;

    // auto_vacuum can only be set before any tables exist. On an existing DB
    // the pragma is read-only. If it's not INCREMENTAL (2), set it and VACUUM
    // to rewrite the file. This is a one-time migration cost per database.
    let current_av: i64 = conn
        .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
        .unwrap_or(0);
    if current_av != 2 {
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")
            .map_err(|e| StorageError::SqliteError {
                message: format!("failed to enable incremental auto_vacuum: {e}"),
            })?;
    }

    Ok(())
}

/// Apply read-only pragmas to a read connection.
pub fn apply_read_pragmas(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "
        PRAGMA query_only = ON;
        PRAGMA cache_size = -64000;
        PRAGMA mmap_size = 268435456;
        PRAGMA busy_timeout = 5000;
        PRAGMA temp_store = MEMORY;
        ",
    )
    .map_err(|e| StorageError::SqliteError {
        message: format!("failed to apply read pragmas: {e}"),
    })
}

/// Verify that WAL mode is active.
pub fn verify_wal_mode(conn: &Connection) -> Result<bool, StorageError> {
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;
    Ok(mode.eq_ignore_ascii_case("wal"))
}

/// Run optimize pragmas on connection close.
pub fn optimize_on_close(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "
        PRAGMA analysis_limit = 400;
        PRAGMA optimize;
        ",
    )
    .map_err(|e| StorageError::SqliteError {
        message: format!("failed to optimize: {e}"),
    })
}
