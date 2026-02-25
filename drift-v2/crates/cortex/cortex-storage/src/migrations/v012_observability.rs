//! v012: metric_snapshots, query_performance_log.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS metric_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name     TEXT NOT NULL,
            metric_value    REAL NOT NULL,
            labels          TEXT NOT NULL DEFAULT '{}',
            timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_metrics_name ON metric_snapshots(metric_name);
        CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metric_snapshots(timestamp);

        CREATE TABLE IF NOT EXISTS query_performance_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            query_type      TEXT NOT NULL,
            duration_ms     REAL NOT NULL,
            result_count    INTEGER NOT NULL DEFAULT 0,
            parameters      TEXT NOT NULL DEFAULT '{}',
            timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_query_perf_type ON query_performance_log(query_type);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
