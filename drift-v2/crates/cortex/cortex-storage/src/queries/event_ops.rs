//! Raw SQL operations for the memory_events table.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Raw event row from the database.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub event_id: u64,
    pub memory_id: String,
    pub recorded_at: String,
    pub event_type: String,
    pub delta: String,
    pub actor_type: String,
    pub actor_id: String,
    pub caused_by: Option<String>,
    pub schema_version: u16,
}

/// Event parameters for batch insertion.
pub type EventParams<'a> = (
    &'a str,         // memory_id
    &'a str,         // recorded_at
    &'a str,         // event_type
    &'a str,         // delta
    &'a str,         // actor_type
    &'a str,         // actor_id
    Option<&'a str>, // caused_by
    u16,             // schema_version
);

/// Insert a single event. Returns the assigned event_id.
#[allow(clippy::too_many_arguments)]
pub fn insert_event(
    conn: &Connection,
    memory_id: &str,
    recorded_at: &str,
    event_type: &str,
    delta: &str,
    actor_type: &str,
    actor_id: &str,
    caused_by: Option<&str>,
    schema_version: u16,
) -> CortexResult<u64> {
    conn.execute(
        "INSERT INTO memory_events
            (memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            memory_id,
            recorded_at,
            event_type,
            delta,
            actor_type,
            actor_id,
            caused_by,
            schema_version as i64,
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let event_id = conn.last_insert_rowid() as u64;
    Ok(event_id)
}

/// Insert a batch of events in a single transaction. Returns assigned event_ids.
pub fn insert_event_batch(conn: &Connection, events: &[EventParams<'_>]) -> CortexResult<Vec<u64>> {
    let mut ids = Vec::with_capacity(events.len());
    for &(memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, sv) in events
    {
        let id = insert_event(
            conn,
            memory_id,
            recorded_at,
            event_type,
            delta,
            actor_type,
            actor_id,
            caused_by,
            sv,
        )?;
        ids.push(id);
    }
    Ok(ids)
}

/// Get events for a memory, optionally before a timestamp.
pub fn get_events_for_memory(
    conn: &Connection,
    memory_id: &str,
    before: Option<&str>,
) -> CortexResult<Vec<RawEvent>> {
    let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match before {
        Some(ts) => (
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE memory_id = ?1 AND recorded_at <= ?2
             ORDER BY event_id ASC".to_string(),
            vec![
                Box::new(memory_id.to_string()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(ts.to_string()),
            ],
        ),
        None => (
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE memory_id = ?1
             ORDER BY event_id ASC".to_string(),
            vec![Box::new(memory_id.to_string()) as Box<dyn rusqlite::types::ToSql>],
        ),
    };

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_refs.as_slice(), row_to_raw_event)
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}

/// Get events in a time range across all memories.
pub fn get_events_in_range(conn: &Connection, from: &str, to: &str) -> CortexResult<Vec<RawEvent>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE recorded_at >= ?1 AND recorded_at <= ?2
             ORDER BY event_id ASC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![from, to], row_to_raw_event)
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}

/// Get events by type, optionally before a timestamp.
pub fn get_events_by_type(
    conn: &Connection,
    event_type: &str,
    before: Option<&str>,
) -> CortexResult<Vec<RawEvent>> {
    let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match before {
        Some(ts) => (
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE event_type = ?1 AND recorded_at <= ?2
             ORDER BY event_id ASC".to_string(),
            vec![
                Box::new(event_type.to_string()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(ts.to_string()),
            ],
        ),
        None => (
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE event_type = ?1
             ORDER BY event_id ASC".to_string(),
            vec![Box::new(event_type.to_string()) as Box<dyn rusqlite::types::ToSql>],
        ),
    };

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_refs.as_slice(), row_to_raw_event)
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}

/// Get event count for a memory.
pub fn get_event_count(conn: &Connection, memory_id: &str) -> CortexResult<u64> {
    conn.query_row(
        "SELECT COUNT(*) FROM memory_events WHERE memory_id = ?1",
        params![memory_id],
        |row| row.get::<_, i64>(0),
    )
    .map(|c| c as u64)
    .map_err(|e| to_storage_err(e.to_string()))
}

/// Get events for a memory after a specific event_id and before a timestamp.
pub fn get_events_after_id(
    conn: &Connection,
    memory_id: &str,
    after_event_id: u64,
    before: Option<&str>,
) -> CortexResult<Vec<RawEvent>> {
    let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match before {
        Some(ts) => (
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE memory_id = ?1 AND event_id > ?2 AND recorded_at <= ?3
             ORDER BY event_id ASC".to_string(),
            vec![
                Box::new(memory_id.to_string()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(after_event_id as i64),
                Box::new(ts.to_string()),
            ],
        ),
        None => (
            "SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events WHERE memory_id = ?1 AND event_id > ?2
             ORDER BY event_id ASC".to_string(),
            vec![
                Box::new(memory_id.to_string()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(after_event_id as i64),
            ],
        ),
    };

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_refs.as_slice(), row_to_raw_event)
        .map_err(|e| to_storage_err(e.to_string()))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| to_storage_err(e.to_string()))
}

/// Move events older than a date to the archive table.
/// Only moves events that have a verified snapshot after them.
pub fn move_events_to_archive(
    conn: &Connection,
    before_date: &str,
    verified_snapshot_event_id: u64,
) -> CortexResult<u64> {
    // Insert into archive
    let moved = conn
        .execute(
            "INSERT INTO memory_events_archive
                (event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version)
             SELECT event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, caused_by, schema_version
             FROM memory_events
             WHERE recorded_at < ?1 AND event_id <= ?2",
            params![before_date, verified_snapshot_event_id as i64],
        )
        .map_err(|e| to_storage_err(e.to_string()))? as u64;

    // Delete from main table
    conn.execute(
        "DELETE FROM memory_events WHERE recorded_at < ?1 AND event_id <= ?2",
        params![before_date, verified_snapshot_event_id as i64],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(moved)
}

fn row_to_raw_event(row: &rusqlite::Row<'_>) -> Result<RawEvent, rusqlite::Error> {
    Ok(RawEvent {
        event_id: row.get::<_, i64>(0)? as u64,
        memory_id: row.get(1)?,
        recorded_at: row.get(2)?,
        event_type: row.get(3)?,
        delta: row.get(4)?,
        actor_type: row.get(5)?,
        actor_id: row.get(6)?,
        caused_by: row.get(7)?,
        schema_version: row.get::<_, i64>(8)? as u16,
    })
}
