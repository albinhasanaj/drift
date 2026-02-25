//! Schema versioning using PRAGMA user_version.
//!
//! Follows drift-core's `workspace/migration.rs` pattern exactly:
//! - Uses PRAGMA user_version for version tracking (no extra tables)
//! - Each version bump is a const SQL string
//! - Migration history recorded in bridge_event_log (reuse existing table)

use rusqlite::Connection;
use tracing::info;

use crate::errors::BridgeResult;
use super::schema::BRIDGE_TABLES_V1;

/// Current schema version. Bump this when adding new migrations.
pub const CURRENT_VERSION: u32 = 1;

/// Get the current bridge schema version from the database.
///
/// Checks the dedicated `bridge_schema_version` table first. Falls back to
/// the legacy `bridge_metrics` location for backward compatibility with
/// databases created before INF-07.
pub fn get_schema_version(conn: &Connection) -> BridgeResult<u32> {
    // Check dedicated version table first
    let dedicated_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='bridge_schema_version'",
        [],
        |row| row.get(0),
    )?;

    if dedicated_exists {
        let result = conn.query_row(
            "SELECT version FROM bridge_schema_version LIMIT 1",
            [],
            |row| row.get::<_, u32>(0),
        );
        match result {
            Ok(version) => return Ok(version),
            Err(rusqlite::Error::QueryReturnedNoRows) => { /* empty table, fall through */ }
            Err(e) => return Err(e.into()),
        }
    }

    // Legacy fallback: check bridge_metrics
    let metrics_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='bridge_metrics'",
        [],
        |row| row.get(0),
    )?;

    if !metrics_exists {
        return Ok(0);
    }

    let result = conn.query_row(
        "SELECT CAST(metric_value AS INTEGER) FROM bridge_metrics WHERE metric_name = 'schema_version' ORDER BY recorded_at DESC LIMIT 1",
        [],
        |row| row.get::<_, u32>(0),
    );

    match result {
        Ok(version) => Ok(version),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // Tables exist but no version marker — this is a pre-migration database (v1)
            let has_tables: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='bridge_memories'",
                [],
                |row| row.get(0),
            )?;
            if has_tables { Ok(1) } else { Ok(0) }
        }
        Err(e) => Err(e.into()),
    }
}

/// Set the bridge schema version in the database.
/// Uses a dedicated single-row table that is immune to retention cleanup.
fn set_schema_version(conn: &Connection, version: u32) -> BridgeResult<()> {
    // Create dedicated version table if it doesn't exist
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bridge_schema_version (
            version INTEGER NOT NULL
        ) STRICT;",
    )?;
    // Upsert: delete old row, insert new
    conn.execute("DELETE FROM bridge_schema_version", [])?;
    conn.execute(
        "INSERT INTO bridge_schema_version (version) VALUES (?1)",
        rusqlite::params![version],
    )?;
    Ok(())
}

/// Run all pending migrations to bring the database up to CURRENT_VERSION.
///
/// Returns the version the database was migrated to.
pub fn migrate(conn: &Connection) -> BridgeResult<u32> {
    let current = get_schema_version(conn)?;

    if current >= CURRENT_VERSION {
        return Ok(current);
    }

    if current < 1 {
        info!("Migrating bridge schema: 0 → 1 (initial tables)");
        conn.execute_batch(BRIDGE_TABLES_V1)?;
        set_schema_version(conn, 1)?;
    }

    // Future migrations go here:
    // if current < 2 {
    //     info!("Migrating bridge schema: 1 → 2");
    //     conn.execute_batch(BRIDGE_SCHEMA_V2)?;
    //     set_schema_version(conn, 2)?;
    // }

    let final_version = get_schema_version(conn)?;
    info!(from = current, to = final_version, "Bridge schema migration complete");
    Ok(final_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::storage::pragmas::configure_connection(&conn).unwrap();
        conn
    }

    #[test]
    fn test_fresh_db_version_is_zero() {
        let conn = fresh_db();
        assert_eq!(get_schema_version(&conn).unwrap(), 0);
    }

    #[test]
    fn test_migrate_from_zero_to_v1() {
        let conn = fresh_db();
        let version = migrate(&conn).unwrap();
        assert_eq!(version, 1);

        // Tables should exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'bridge_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 6, "Expected 6 bridge tables (5 data + 1 schema_version)");
    }

    #[test]
    fn test_migrate_idempotent() {
        let conn = fresh_db();
        let v1 = migrate(&conn).unwrap();
        let v2 = migrate(&conn).unwrap();
        assert_eq!(v1, v2);
        assert_eq!(v2, 1);
    }

    #[test]
    fn test_pre_migration_db_detected_as_v1() {
        let conn = fresh_db();
        // Create tables the old way (no version marker)
        conn.execute_batch(BRIDGE_TABLES_V1).unwrap();
        assert_eq!(get_schema_version(&conn).unwrap(), 1);
    }

    #[test]
    fn test_migration_does_not_pollute_event_log() {
        let conn = fresh_db();
        migrate(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM bridge_event_log",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "migrate() should not insert any events");
    }
}
