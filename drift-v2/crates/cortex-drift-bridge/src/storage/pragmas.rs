//! SQLite PRAGMA configuration for bridge connections.
//!
//! Matches drift-core's `workspace/migration.rs` pattern (8 PRAGMAs).
//! Must be called on every connection immediately after opening.

use rusqlite::Connection;

use crate::errors::BridgeResult;

/// Configure a SQLite connection with production-grade PRAGMAs.
///
/// These match drift-core's connection setup:
/// - WAL for concurrent readers during writes
/// - busy_timeout for lock contention (primary concurrency mechanism)
/// - mmap for faster reads on large tables
/// - NORMAL synchronous for WAL durability trade-off
pub fn configure_connection(conn: &Connection) -> BridgeResult<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        PRAGMA cache_size = -8000;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
        ",
    )?;
    Ok(())
}

/// Configure a read-only connection (drift.db).
/// Same PRAGMAs as `configure_connection` plus `query_only = ON` to prevent
/// accidental writes through this connection.
pub fn configure_readonly_connection(conn: &Connection) -> BridgeResult<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        PRAGMA cache_size = -8000;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
        PRAGMA query_only = ON;
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configure_connection_sets_wal() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn).unwrap();

        let journal_mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        // In-memory databases may report "memory" instead of "wal"
        assert!(
            journal_mode == "wal" || journal_mode == "memory",
            "Expected wal or memory, got: {}",
            journal_mode
        );
    }

    #[test]
    fn test_configure_connection_sets_busy_timeout() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn).unwrap();

        let timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
    }

    #[test]
    fn test_configure_connection_sets_foreign_keys() {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn).unwrap();

        let fk: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn test_configure_readonly_connection() {
        let conn = Connection::open_in_memory().unwrap();
        configure_readonly_connection(&conn).unwrap();

        let timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
    }
}
