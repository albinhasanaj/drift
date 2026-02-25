//! Schema migration for workspace tables.
//! Uses PRAGMA user_version tracking.

use rusqlite::Connection;

use super::errors::WorkspaceError;

/// Workspace schema SQL — creates all workspace management tables.
pub const WORKSPACE_SCHEMA_SQL: &str = r#"
-- Workspace configuration (replaces .drift/config.json)
CREATE TABLE IF NOT EXISTS workspace_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Project registry (replaces ~/.drift/registry.json)
CREATE TABLE IF NOT EXISTS project_registry (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    root_path TEXT NOT NULL UNIQUE,
    drift_path TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_accessed_at TEXT NOT NULL DEFAULT (datetime('now')),
    health_status TEXT NOT NULL DEFAULT 'unknown',
    is_active INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Ensure only one active project
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_active
    ON project_registry(is_active) WHERE is_active = 1;

-- Backup registry (replaces .drift-backups/index.json)
CREATE TABLE IF NOT EXISTS backup_registry (
    id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    drift_db_size INTEGER NOT NULL,
    cortex_db_size INTEGER,
    schema_version INTEGER NOT NULL,
    drift_version TEXT NOT NULL,
    backup_path TEXT NOT NULL,
    integrity_verified INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    tier TEXT NOT NULL DEFAULT 'operational'
) STRICT;

CREATE INDEX IF NOT EXISTS idx_backup_created ON backup_registry(created_at);
CREATE INDEX IF NOT EXISTS idx_backup_tier ON backup_registry(tier);

-- Migration history (replaces .drift/migration-history.json)
CREATE TABLE IF NOT EXISTS migration_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_version INTEGER NOT NULL,
    to_version INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now')),
    duration_ms INTEGER NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT
) STRICT;

-- Workspace context (replaces .drift/.context-cache.json)
-- Materialized view refreshed after every scan
CREATE TABLE IF NOT EXISTS workspace_context (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Package registry for monorepo support
CREATE TABLE IF NOT EXISTS workspace_packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    language TEXT,
    framework TEXT,
    dependencies TEXT,  -- JSON array of package IDs
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_package_path ON workspace_packages(path);

-- Workspace events log (for audit trail)
CREATE TABLE IF NOT EXISTS workspace_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_events_type ON workspace_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created ON workspace_events(created_at);
"#;

/// Initialize a database connection with PRAGMAs and workspace tables.
/// Called on every workspace access — idempotent.
pub fn initialize_workspace_db(conn: &Connection) -> Result<(), WorkspaceError> {
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

    // auto_vacuum can only be set before any tables exist. On an existing DB
    // the pragma is read-only. If it's not INCREMENTAL (2), set it and VACUUM
    // to rewrite the file. This is a one-time migration cost per database.
    let current_av: i64 = conn
        .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
        .unwrap_or(0);
    if current_av != 2 {
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
    }

    conn.execute_batch(WORKSPACE_SCHEMA_SQL)?;

    Ok(())
}

/// Record a migration event in the migration_history table.
pub fn record_migration(
    conn: &Connection,
    from_version: u32,
    to_version: u32,
    duration_ms: u64,
    success: bool,
    error: Option<&str>,
) -> Result<(), WorkspaceError> {
    conn.execute(
        "INSERT INTO migration_history (from_version, to_version, duration_ms, success, error_message)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![from_version, to_version, duration_ms as i64, success as i32, error],
    )?;
    Ok(())
}

/// Get the current schema version via PRAGMA user_version.
pub fn get_schema_version(conn: &Connection) -> Result<u32, WorkspaceError> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_schema_valid() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_workspace_db(&conn).unwrap();

        // Verify all tables exist
        let tables = [
            "workspace_config",
            "project_registry",
            "backup_registry",
            "migration_history",
            "workspace_context",
            "workspace_packages",
            "workspace_events",
        ];
        for table in &tables {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {}", table),
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| panic!("Table {} should exist", table));
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn record_migration_works() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_workspace_db(&conn).unwrap();
        record_migration(&conn, 0, 1, 100, true, None).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM migration_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }
}
