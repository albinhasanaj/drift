//! v011: reclassification_history, reclassification_signals.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS reclassification_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id       TEXT NOT NULL,
            old_type        TEXT NOT NULL,
            new_type        TEXT NOT NULL,
            reason          TEXT NOT NULL DEFAULT '',
            confidence      REAL NOT NULL DEFAULT 1.0,
            reclassified_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_reclass_memory ON reclassification_history(memory_id);

        CREATE TABLE IF NOT EXISTS reclassification_signals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id   TEXT NOT NULL,
            signal_type TEXT NOT NULL,
            signal_data TEXT NOT NULL DEFAULT '{}',
            strength    REAL NOT NULL DEFAULT 0.5,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_reclass_signals_memory ON reclassification_signals(memory_id);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
