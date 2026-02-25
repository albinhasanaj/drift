//! v010: sync_log, sync_state, conflict_log.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_state (
            id              INTEGER PRIMARY KEY CHECK (id = 1),
            last_sync_at    TEXT,
            last_sync_token TEXT,
            status          TEXT NOT NULL DEFAULT 'idle',
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        INSERT OR IGNORE INTO sync_state (id) VALUES (1);

        CREATE TABLE IF NOT EXISTS sync_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            direction   TEXT NOT NULL,
            memory_id   TEXT NOT NULL,
            operation   TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            details     TEXT NOT NULL DEFAULT '{}',
            timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_sync_log_status ON sync_log(status);

        CREATE TABLE IF NOT EXISTS conflict_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id       TEXT NOT NULL,
            local_version   TEXT NOT NULL,
            remote_version  TEXT NOT NULL,
            resolution      TEXT NOT NULL DEFAULT 'pending',
            resolved_at     TEXT,
            timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
