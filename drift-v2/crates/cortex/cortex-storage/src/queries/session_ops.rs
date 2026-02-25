//! Session CRUD, analytics aggregation.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Create a new session.
pub fn create_session(conn: &Connection, session_id: &str, tokens_budget: i64) -> CortexResult<()> {
    conn.execute(
        "INSERT INTO session_contexts (id, tokens_budget) VALUES (?1, ?2)",
        params![session_id, tokens_budget],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// End a session.
pub fn end_session(conn: &Connection, session_id: &str) -> CortexResult<()> {
    conn.execute(
        "UPDATE session_contexts SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1",
        params![session_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Update tokens used in a session.
pub fn update_tokens_used(
    conn: &Connection,
    session_id: &str,
    tokens_used: i64,
) -> CortexResult<()> {
    conn.execute(
        "UPDATE session_contexts SET tokens_used = ?2 WHERE id = ?1",
        params![session_id, tokens_used],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Record a session analytics event.
pub fn record_analytics_event(
    conn: &Connection,
    session_id: &str,
    event_type: &str,
    event_data: &serde_json::Value,
) -> CortexResult<()> {
    conn.execute(
        "INSERT INTO session_analytics (session_id, event_type, event_data)
         VALUES (?1, ?2, ?3)",
        params![session_id, event_type, event_data.to_string()],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Count analytics events by type for a session.
pub fn count_events_by_type(
    conn: &Connection,
    session_id: &str,
) -> CortexResult<Vec<(String, i64)>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_type, COUNT(*) FROM session_analytics
             WHERE session_id = ?1 GROUP BY event_type",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![session_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}
