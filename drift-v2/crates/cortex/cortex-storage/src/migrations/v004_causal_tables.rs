//! v004: causal_edges, causal_evidence.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS causal_edges (
            source_id   TEXT NOT NULL,
            target_id   TEXT NOT NULL,
            relation    TEXT NOT NULL,
            strength    REAL NOT NULL DEFAULT 1.0,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (source_id, target_id)
        );

        CREATE INDEX IF NOT EXISTS idx_causal_source ON causal_edges(source_id);
        CREATE INDEX IF NOT EXISTS idx_causal_target ON causal_edges(target_id);

        CREATE TABLE IF NOT EXISTS causal_evidence (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id   TEXT NOT NULL,
            target_id   TEXT NOT NULL,
            description TEXT NOT NULL,
            source      TEXT NOT NULL DEFAULT 'system',
            timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (source_id, target_id) REFERENCES causal_edges(source_id, target_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_edge ON causal_evidence(source_id, target_id);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
