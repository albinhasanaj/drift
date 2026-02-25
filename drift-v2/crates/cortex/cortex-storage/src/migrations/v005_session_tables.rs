//! v005: session_contexts, session_analytics.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS session_contexts (
            id              TEXT PRIMARY KEY,
            started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            ended_at        TEXT,
            loaded_memories TEXT NOT NULL DEFAULT '[]',
            tokens_used     INTEGER NOT NULL DEFAULT 0,
            tokens_budget   INTEGER NOT NULL DEFAULT 2000,
            metadata        TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS session_analytics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            event_data      TEXT NOT NULL DEFAULT '{}',
            timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (session_id) REFERENCES session_contexts(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_session_analytics_session ON session_analytics(session_id);
        CREATE INDEX IF NOT EXISTS idx_session_analytics_type ON session_analytics(event_type);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
