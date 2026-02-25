//! v008: memory_versions — content evolution tracking.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS memory_versions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id   TEXT NOT NULL,
            version     INTEGER NOT NULL,
            content     TEXT NOT NULL,
            summary     TEXT NOT NULL DEFAULT '',
            confidence  REAL NOT NULL,
            changed_by  TEXT NOT NULL DEFAULT 'system',
            reason      TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE,
            UNIQUE(memory_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_versions_memory ON memory_versions(memory_id);
        CREATE INDEX IF NOT EXISTS idx_versions_memory_version ON memory_versions(memory_id, version);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
