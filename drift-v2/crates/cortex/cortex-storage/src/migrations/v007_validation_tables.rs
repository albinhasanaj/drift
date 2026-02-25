//! v007: memory_validation_history, memory_contradictions.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS memory_validation_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id       TEXT NOT NULL,
            dimension       TEXT NOT NULL,
            score           REAL NOT NULL,
            healing_action  TEXT,
            validated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_validation_memory ON memory_validation_history(memory_id);

        CREATE TABLE IF NOT EXISTS memory_contradictions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id_a     TEXT NOT NULL,
            memory_id_b     TEXT NOT NULL,
            contradiction_type TEXT NOT NULL,
            confidence_delta   REAL NOT NULL DEFAULT 0.0,
            resolved        INTEGER NOT NULL DEFAULT 0,
            detected_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            resolved_at     TEXT,
            FOREIGN KEY (memory_id_a) REFERENCES memories(id) ON DELETE CASCADE,
            FOREIGN KEY (memory_id_b) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_contradictions_a ON memory_contradictions(memory_id_a);
        CREATE INDEX IF NOT EXISTS idx_contradictions_b ON memory_contradictions(memory_id_b);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
