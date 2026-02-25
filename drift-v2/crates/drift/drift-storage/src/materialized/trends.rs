//! Materialized trends view — health score trends over time.

use rusqlite::{params, Connection};
use drift_core::errors::StorageError;

/// Query health score trend data.
pub fn query_health_trend(
    conn: &Connection,
    days: u32,
) -> Result<Vec<TrendPoint>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT metric_value, recorded_at FROM health_trends
             WHERE metric_name = 'health_score'
             AND recorded_at >= unixepoch() - (?1 * 86400)
             ORDER BY recorded_at ASC",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let rows = stmt
        .query_map(params![days], |row| {
            Ok(TrendPoint {
                value: row.get(0)?,
                timestamp: row.get(1)?,
            })
        })
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
}

#[derive(Debug, Clone)]
pub struct TrendPoint {
    pub value: f64,
    pub timestamp: u64,
}
