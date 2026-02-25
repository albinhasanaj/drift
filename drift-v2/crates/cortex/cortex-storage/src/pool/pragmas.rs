//! PRAGMA configuration applied to every SQLite connection.
//!
//! WAL mode, NORMAL sync, 256MB mmap, 64MB cache, 5s busy_timeout,
//! foreign_keys ON, incremental auto_vacuum.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Apply all performance and safety pragmas to a connection.
pub fn apply_pragmas(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA mmap_size = 268435456;
        PRAGMA cache_size = -64000;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // auto_vacuum can only be set before any tables exist. On an existing DB
    // the pragma is read-only. If it's not INCREMENTAL (2), set it and VACUUM
    // to rewrite the file. This is a one-time migration cost per database.
    let current_av: i64 = conn
        .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
        .unwrap_or(0);
    if current_av != 2 {
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")
            .map_err(|e| to_storage_err(e.to_string()))?;
    }

    Ok(())
}

/// Apply read-only pragmas to a read connection.
/// Skips write-side settings (journal_mode, auto_vacuum, synchronous).
pub fn apply_read_pragmas(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        PRAGMA query_only = ON;
        PRAGMA mmap_size = 268435456;
        PRAGMA cache_size = -64000;
        PRAGMA busy_timeout = 5000;
        PRAGMA temp_store = MEMORY;
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Verify that WAL mode is active on a connection.
pub fn verify_wal_mode(conn: &Connection) -> CortexResult<bool> {
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(mode.eq_ignore_ascii_case("wal"))
}
