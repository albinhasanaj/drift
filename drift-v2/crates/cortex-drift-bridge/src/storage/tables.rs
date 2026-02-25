//! Bridge-specific SQLite tables and CRUD operations.
//!
//! Tables (5 total, defined in schema.rs):
//! - bridge_grounding_results (90 days Community, unlimited Enterprise)
//! - bridge_grounding_snapshots (365 days)
//! - bridge_event_log (30 days)
//! - bridge_metrics (7 days)
//! - bridge_memories

use rusqlite::{params, Connection};

use crate::errors::{BridgeError, BridgeResult};
use crate::grounding::{GroundingResult, GroundingSnapshot};
use super::schema::BRIDGE_TABLES_V1;

/// Create all 5 bridge-specific tables using the single source of truth in schema.rs.
pub fn create_bridge_tables(conn: &Connection) -> BridgeResult<()> {
    conn.execute_batch(BRIDGE_TABLES_V1)?;
    Ok(())
}

/// Store a memory in the bridge_memories table.
/// Deduplicates by (summary, memory_type) — if a memory with the same summary
/// and type already exists, the insert is skipped to prevent bloat on re-analyze.
pub fn store_memory(conn: &Connection, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()> {
    let memory_type_str = format!("{:?}", memory.memory_type);

    // Cross-process dedup: skip if same summary+type already exists
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM bridge_memories WHERE summary = ?1 AND memory_type = ?2)",
        params![memory.summary, memory_type_str],
        |row| row.get(0),
    ).unwrap_or(false);

    if exists {
        tracing::debug!(
            summary = %memory.summary,
            memory_type = %memory_type_str,
            "Skipping duplicate memory — same summary+type already exists"
        );
        return Ok(());
    }

    let content_json = serde_json::to_string(&memory.content)?;
    let tags_json = serde_json::to_string(&memory.tags)?;
    let patterns_json = serde_json::to_string(&memory.linked_patterns)?;

    conn.execute(
        "INSERT INTO bridge_memories (id, memory_type, content, summary, confidence, importance, tags, linked_patterns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            memory.id,
            memory_type_str,
            content_json,
            memory.summary,
            memory.confidence.value(),
            format!("{:?}", memory.importance),
            tags_json,
            patterns_json,
        ],
    )?;
    Ok(())
}

/// Log an event in the bridge_event_log table.
pub fn log_event(
    conn: &Connection,
    event_type: &str,
    memory_type: Option<&str>,
    memory_id: Option<&str>,
    confidence: Option<f64>,
) -> BridgeResult<()> {
    conn.execute(
        "INSERT INTO bridge_event_log (event_type, memory_type, memory_id, confidence) VALUES (?1, ?2, ?3, ?4)",
        params![event_type, memory_type, memory_id, confidence],
    )?;
    Ok(())
}

/// Record a grounding result.
pub fn record_grounding_result(conn: &Connection, result: &GroundingResult) -> BridgeResult<()> {
    let evidence_json = serde_json::to_string(&result.evidence)?;
    conn.execute(
        "INSERT INTO bridge_grounding_results (memory_id, grounding_score, classification, evidence)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            result.memory_id,
            result.grounding_score,
            format!("{:?}", result.verdict),
            evidence_json,
        ],
    )?;
    Ok(())
}

/// Record a grounding snapshot.
pub fn record_grounding_snapshot(conn: &Connection, snapshot: &GroundingSnapshot) -> BridgeResult<()> {
    conn.execute(
        "INSERT INTO bridge_grounding_snapshots
         (total_memories, grounded_count, validated_count, partial_count, weak_count, invalidated_count, avg_score, error_count, trigger_type)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            snapshot.total_checked,
            snapshot.validated + snapshot.partial + snapshot.weak + snapshot.invalidated,
            snapshot.validated,
            snapshot.partial,
            snapshot.weak,
            snapshot.invalidated,
            snapshot.avg_grounding_score,
            snapshot.error_count,
            snapshot.trigger_type,
        ],
    )?;
    Ok(())
}

/// Record a metric.
pub fn record_metric(conn: &Connection, name: &str, value: f64) -> BridgeResult<()> {
    conn.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value) VALUES (?1, ?2)",
        params![name, value],
    )?;
    Ok(())
}

/// Update a memory's confidence in bridge_memories after grounding adjustment.
/// Clamps to [0.0, 1.0] range.
pub fn update_memory_confidence(conn: &Connection, memory_id: &str, delta: f64) -> BridgeResult<()> {
    conn.execute(
        "UPDATE bridge_memories SET confidence = MIN(MAX(confidence + ?1, 0.0), 1.0) WHERE id = ?2",
        params![delta, memory_id],
    )?;
    Ok(())
}

/// ATTACH cortex.db for cross-DB queries. Returns Ok(true) if successful.
/// Uses parameterized query to prevent SQL injection via malicious paths.
pub fn attach_cortex_db(conn: &Connection, cortex_path: &str) -> BridgeResult<bool> {
    match conn.execute("ATTACH DATABASE ?1 AS cortex", params![cortex_path]) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!(error = %e, path = cortex_path, "Failed to ATTACH cortex.db");
            Err(BridgeError::AttachFailed {
                db_path: cortex_path.to_string(),
                source: e,
            })
        }
    }
}

/// Detach cortex.db after cross-DB queries.
pub fn detach_cortex_db(conn: &Connection) -> BridgeResult<()> {
    conn.execute_batch("DETACH DATABASE cortex")?;
    Ok(())
}

/// Get the previous grounding score for a memory.
pub fn get_previous_grounding_score(conn: &Connection, memory_id: &str) -> BridgeResult<Option<f64>> {
    let mut stmt = conn.prepare(
        "SELECT grounding_score FROM bridge_grounding_results
         WHERE memory_id = ?1 ORDER BY created_at DESC LIMIT 1",
    )?;
    let result = stmt.query_row(params![memory_id], |row| row.get::<_, f64>(0));
    match result {
        Ok(score) => Ok(Some(score)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Get grounding history for a memory.
pub fn get_grounding_history(
    conn: &Connection,
    memory_id: &str,
    limit: usize,
) -> BridgeResult<Vec<(f64, String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT grounding_score, classification, created_at FROM bridge_grounding_results
         WHERE memory_id = ?1 ORDER BY created_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![memory_id, limit as i64], |row| {
        Ok((
            row.get::<_, f64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

