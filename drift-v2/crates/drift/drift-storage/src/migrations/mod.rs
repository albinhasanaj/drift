//! Schema migrations using PRAGMA user_version.

pub mod v001_initial;
pub mod v002_analysis;
pub mod v003_patterns;
pub mod v004_graph;
pub mod v005_structural;
pub mod v006_enforcement;
pub mod v007_advanced;
pub mod v008_enforcement_fixes;
pub mod v009_pattern_status;

use drift_core::errors::StorageError;
use rusqlite::Connection;

/// Run all pending migrations.
pub fn run_migrations(conn: &Connection) -> Result<(), StorageError> {
    let current_version: u32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| StorageError::MigrationFailed {
            version: 0,
            message: e.to_string(),
        })?;

    let migrations: &[(&str, u32)] = &[
        (v001_initial::MIGRATION_SQL, 1),
        (v002_analysis::MIGRATION_SQL, 2),
        (v003_patterns::MIGRATION_SQL, 3),
        (v004_graph::MIGRATION_SQL, 4),
        (v005_structural::MIGRATION_SQL, 5),
        (v006_enforcement::MIGRATION_SQL, 6),
        (v007_advanced::MIGRATION_SQL, 7),
        (v008_enforcement_fixes::MIGRATION_SQL, 8),
        (v009_pattern_status::MIGRATION_SQL, 9),
    ];

    for (sql, version) in migrations {
        if current_version < *version {
            conn.execute_batch(sql).map_err(|e| StorageError::MigrationFailed {
                version: *version,
                message: e.to_string(),
            })?;

            // Run part 2 for v006
            if *version == 6 {
                conn.execute_batch(v006_enforcement::MIGRATION_SQL_PART2)
                    .map_err(|e| StorageError::MigrationFailed {
                        version: *version,
                        message: e.to_string(),
                    })?;
            }

            conn.pragma_update(None, "user_version", version)
                .map_err(|e| StorageError::MigrationFailed {
                    version: *version,
                    message: e.to_string(),
                })?;
            tracing::info!(version = version, "applied migration");
        }
    }

    Ok(())
}

/// Get the current schema version.
pub fn current_version(conn: &Connection) -> Result<u32, StorageError> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
}
