//! v006: memory_audit_log, consolidation_metrics, degradation_log.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS memory_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id   TEXT NOT NULL,
            operation   TEXT NOT NULL,
            details     TEXT NOT NULL DEFAULT '{}',
            actor       TEXT NOT NULL DEFAULT 'system',
            timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_audit_memory ON memory_audit_log(memory_id);
        CREATE INDEX IF NOT EXISTS idx_audit_operation ON memory_audit_log(operation);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON memory_audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON memory_audit_log(actor);

        CREATE TABLE IF NOT EXISTS consolidation_metrics (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id            TEXT NOT NULL,
            precision_score   REAL,
            compression_ratio REAL,
            lift              REAL,
            stability         REAL,
            memories_created  INTEGER NOT NULL DEFAULT 0,
            memories_archived INTEGER NOT NULL DEFAULT 0,
            timestamp         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS degradation_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            component   TEXT NOT NULL,
            failure     TEXT NOT NULL,
            fallback    TEXT NOT NULL,
            details     TEXT NOT NULL DEFAULT '{}',
            timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_degradation_component ON degradation_log(component);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
