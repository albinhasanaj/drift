//! v014: temporal event store, snapshots, drift snapshots, materialized views.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS memory_events (
            event_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id      TEXT NOT NULL,
            recorded_at    TEXT NOT NULL,
            event_type     TEXT NOT NULL,
            delta          TEXT NOT NULL,
            actor_type     TEXT NOT NULL,
            actor_id       TEXT NOT NULL,
            caused_by      TEXT,
            schema_version INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_events_memory_time
            ON memory_events(memory_id, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_events_time
            ON memory_events(recorded_at);
        CREATE INDEX IF NOT EXISTS idx_events_type
            ON memory_events(event_type);

        CREATE TABLE IF NOT EXISTS memory_events_archive (
            event_id       INTEGER PRIMARY KEY,
            memory_id      TEXT NOT NULL,
            recorded_at    TEXT NOT NULL,
            event_type     TEXT NOT NULL,
            delta          TEXT NOT NULL,
            actor_type     TEXT NOT NULL,
            actor_id       TEXT NOT NULL,
            caused_by      TEXT,
            schema_version INTEGER NOT NULL DEFAULT 1,
            archived_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS memory_snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id   TEXT NOT NULL,
            snapshot_at TEXT NOT NULL,
            state       BLOB NOT NULL,
            event_id    INTEGER NOT NULL,
            reason      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_snapshots_memory_time
            ON memory_snapshots(memory_id, snapshot_at);

        CREATE TABLE IF NOT EXISTS drift_snapshots (
            snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT NOT NULL,
            window_seconds INTEGER NOT NULL,
            metrics        TEXT NOT NULL,
            UNIQUE(timestamp, window_seconds)
        );

        CREATE INDEX IF NOT EXISTS idx_drift_time
            ON drift_snapshots(timestamp);

        CREATE TABLE IF NOT EXISTS materialized_views (
            view_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            label             TEXT NOT NULL UNIQUE,
            timestamp         TEXT NOT NULL,
            memory_count      INTEGER NOT NULL,
            snapshot_ids      TEXT NOT NULL,
            drift_snapshot_id INTEGER,
            created_by        TEXT NOT NULL,
            auto_refresh      INTEGER DEFAULT 0,
            FOREIGN KEY (drift_snapshot_id) REFERENCES drift_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_memories_valid_range
            ON memories(valid_time, valid_until) WHERE archived = 0;
        CREATE INDEX IF NOT EXISTS idx_memories_transaction_range
            ON memories(transaction_time);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
