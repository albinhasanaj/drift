//! v009: embedding_model_info, model_version column on embedding_link.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS embedding_model_info (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name  TEXT NOT NULL UNIQUE,
            dimensions  INTEGER NOT NULL,
            status      TEXT NOT NULL DEFAULT 'active',
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        -- Add model_version to embedding link for migration tracking.
        ALTER TABLE memory_embedding_link ADD COLUMN model_version TEXT DEFAULT NULL;
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
