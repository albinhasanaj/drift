//! Migration runner — version tracking, forward-only, transactional per migration.

mod v001_initial_schema;
mod v002_vector_tables;
mod v003_fts5_index;
mod v004_causal_tables;
mod v005_session_tables;
mod v006_audit_tables;
mod v007_validation_tables;
mod v008_versioning_tables;
mod v009_embedding_migration;
mod v010_cloud_sync;
mod v011_reclassification;
mod v012_observability;
mod v013_placeholder;
mod v014_temporal_tables;
mod v015_multiagent_tables;

use rusqlite::Connection;
use tracing::{debug, info, warn};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Total number of migrations.
pub const LATEST_VERSION: u32 = 15;

/// All migrations in order. Index 0 = v001, etc.
type MigrationFn = fn(&Connection) -> CortexResult<()>;

const MIGRATIONS: [(u32, &str, MigrationFn); 15] = [
    (1, "initial_schema", v001_initial_schema::migrate),
    (2, "vector_tables", v002_vector_tables::migrate),
    (3, "fts5_index", v003_fts5_index::migrate),
    (4, "causal_tables", v004_causal_tables::migrate),
    (5, "session_tables", v005_session_tables::migrate),
    (6, "audit_tables", v006_audit_tables::migrate),
    (7, "validation_tables", v007_validation_tables::migrate),
    (8, "versioning_tables", v008_versioning_tables::migrate),
    (9, "embedding_migration", v009_embedding_migration::migrate),
    (10, "cloud_sync", v010_cloud_sync::migrate),
    (11, "reclassification", v011_reclassification::migrate),
    (12, "observability", v012_observability::migrate),
    (13, "placeholder", v013_placeholder::migrate),
    (14, "temporal_tables", v014_temporal_tables::migrate),
    (15, "multiagent_tables", v015_multiagent_tables::migrate),
];

/// Get the current schema version from the database.
/// Returns 0 if the schema_version table doesn't exist yet.
pub fn current_version(conn: &Connection) -> CortexResult<u32> {
    // Check if schema_version table exists.
    let exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'")
        .and_then(|mut stmt| stmt.exists([]))
        .map_err(|e| to_storage_err(e.to_string()))?;

    if !exists {
        return Ok(0);
    }

    let version: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(version)
}

/// Run all pending migrations. Forward-only, each wrapped in a transaction.
pub fn run_migrations(conn: &Connection) -> CortexResult<u32> {
    let current = current_version(conn)?;
    let mut applied = 0;

    if current >= LATEST_VERSION {
        debug!("database schema is up to date (v{current})");
        return Ok(0);
    }

    info!("running migrations: v{} → v{}", current, LATEST_VERSION);

    for &(version, name, migrate_fn) in &MIGRATIONS {
        if version <= current {
            continue;
        }

        debug!("applying migration v{version:03}: {name}");

        // Each migration runs in its own transaction.
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| to_storage_err(format!("begin transaction for v{version:03}: {e}")))?;

        match migrate_fn(conn) {
            Ok(()) => {
                // Record the version.
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    [version],
                )
                .map_err(|e| to_storage_err(format!("record version v{version:03}: {e}")))?;

                conn.execute_batch("COMMIT")
                    .map_err(|e| to_storage_err(format!("commit v{version:03}: {e}")))?;

                info!("applied migration v{version:03}: {name}");
                applied += 1;
            }
            Err(e) => {
                warn!("migration v{version:03} failed: {e}, rolling back");
                let _ = conn.execute_batch("ROLLBACK");
                return Err(cortex_core::CortexError::StorageError(
                    cortex_core::errors::StorageError::MigrationFailed {
                        version,
                        reason: e.to_string(),
                    },
                ));
            }
        }
    }

    info!("applied {applied} migration(s), now at v{LATEST_VERSION}");
    Ok(applied)
}
