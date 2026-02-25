//! Raw SQL operations for temporal queries.
//!
//! These functions use the temporal indexes created in v014_temporal_tables migration.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::TemporalRangeMode;

use crate::to_storage_err;

use super::memory_crud::parse_memory_row;

/// Get memories that were valid at a specific point in time.
///
/// Bitemporal filter:
/// - transaction_time <= system_time (recorded by then)
/// - valid_time <= valid_time_query (started being true by then)
/// - valid_until > valid_time_query OR valid_until IS NULL (still true then)
pub fn get_memories_valid_at(
    conn: &Connection,
    valid_time: DateTime<Utc>,
    system_time: DateTime<Utc>,
) -> CortexResult<Vec<BaseMemory>> {
    let valid_time_str = valid_time.to_rfc3339();
    let system_time_str = system_time.to_rfc3339();

    let mut stmt = conn
        .prepare(
            "SELECT id, memory_type, content, summary, transaction_time, valid_time, valid_until,
                confidence, importance, last_accessed, access_count,
                tags, archived, superseded_by, supersedes, content_hash
         FROM memories
         WHERE transaction_time <= ?1
           AND valid_time <= ?2
           AND (valid_until IS NULL OR valid_until > ?2)
           AND archived = 0",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![system_time_str, valid_time_str], |row| {
            Ok(parse_memory_row(row))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
        results.push(memory);
    }

    Ok(results)
}

/// Get memories whose validity period relates to a time range according to the specified mode.
///
/// Uses Allen's interval algebra:
/// - Overlaps: memory was valid at any point in [from, to]
/// - Contains: memory was valid for the entire [from, to]
/// - StartedDuring: memory became valid during [from, to]
/// - EndedDuring: memory stopped being valid during [from, to]
pub fn get_memories_in_range(
    conn: &Connection,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    mode: TemporalRangeMode,
) -> CortexResult<Vec<BaseMemory>> {
    let from_str = from.to_rfc3339();
    let to_str = to.to_rfc3339();

    let where_clause = match mode {
        TemporalRangeMode::Overlaps => {
            // Memory overlaps [from, to] if:
            // valid_time < to AND (valid_until IS NULL OR valid_until > from)
            "valid_time < ?2 AND (valid_until IS NULL OR valid_until > ?1)"
        }
        TemporalRangeMode::Contains => {
            // Memory contains [from, to] if:
            // valid_time <= from AND (valid_until IS NULL OR valid_until >= to)
            "valid_time <= ?1 AND (valid_until IS NULL OR valid_until >= ?2)"
        }
        TemporalRangeMode::StartedDuring => {
            // Memory started during [from, to] if:
            // valid_time >= from AND valid_time < to
            "valid_time >= ?1 AND valid_time < ?2"
        }
        TemporalRangeMode::EndedDuring => {
            // Memory ended during [from, to] if:
            // valid_until >= from AND valid_until < to
            "valid_until IS NOT NULL AND valid_until >= ?1 AND valid_until < ?2"
        }
    };

    let query = format!(
        "SELECT id, memory_type, content, summary, transaction_time, valid_time, valid_until,
                confidence, importance, last_accessed, access_count,
                tags, archived, superseded_by, supersedes, content_hash
         FROM memories
         WHERE {}
           AND archived = 0",
        where_clause
    );

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![from_str, to_str], |row| Ok(parse_memory_row(row)))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
        results.push(memory);
    }

    Ok(results)
}

/// Get memory IDs that were modified between two time points.
///
/// This is used for event-range optimization in temporal diff.
/// Returns memory_ids that have events in the range (time_a, time_b].
pub fn get_memories_modified_between(
    conn: &Connection,
    time_a: DateTime<Utc>,
    time_b: DateTime<Utc>,
) -> CortexResult<Vec<String>> {
    let time_a_str = time_a.to_rfc3339();
    let time_b_str = time_b.to_rfc3339();

    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT memory_id
         FROM memory_events
         WHERE recorded_at > ?1 AND recorded_at <= ?2
         ORDER BY memory_id",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![time_a_str, time_b_str], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory_id = row.map_err(|e| to_storage_err(e.to_string()))?;
        results.push(memory_id);
    }

    Ok(results)
}

/// Get all active memories created (transaction_time) after a given time.
///
/// Used by decision replay to find memories that didn't exist at decision time
/// for hindsight computation.
pub fn get_memories_created_after(conn: &Connection, after: &str) -> CortexResult<Vec<BaseMemory>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, memory_type, content, summary, transaction_time, valid_time, valid_until,
                confidence, importance, last_accessed, access_count,
                tags, archived, superseded_by, supersedes, content_hash
         FROM memories
         WHERE transaction_time > ?1
           AND archived = 0",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![after], |row| Ok(parse_memory_row(row)))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
        results.push(memory);
    }

    Ok(results)
}
