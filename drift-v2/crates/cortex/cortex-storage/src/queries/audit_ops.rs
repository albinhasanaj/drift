//! Audit log insert, query by memory/time/actor.

use rusqlite::{params, Connection};

use chrono::{DateTime, Utc};
use cortex_core::errors::CortexResult;
use cortex_core::models::{AuditActor, AuditEntry, AuditOperation};

use crate::to_storage_err;

/// Insert an audit log entry.
pub fn insert_audit_entry(conn: &Connection, entry: &AuditEntry) -> CortexResult<()> {
    let operation_str =
        serde_json::to_string(&entry.operation).map_err(|e| to_storage_err(e.to_string()))?;
    let actor_str =
        serde_json::to_string(&entry.actor).map_err(|e| to_storage_err(e.to_string()))?;
    let details_str = entry.details.to_string();

    conn.execute(
        "INSERT INTO memory_audit_log (memory_id, operation, details, actor, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            entry.memory_id,
            operation_str.trim_matches('"'),
            details_str,
            actor_str.trim_matches('"'),
            entry.timestamp.to_rfc3339(),
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // Emit temporal event alongside audit record (CR3 — same transaction).
    let delta = serde_json::json!({
        "operation": operation_str.trim_matches('"'),
        "details": entry.details,
    });
    let actor_id = actor_str.trim_matches('"').to_string();
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        &entry.memory_id,
        operation_str.trim_matches('"'),
        &delta,
        "audit",
        &actor_id,
    ) {
        tracing::warn!(memory_id = %entry.memory_id, error = %e, "failed to emit audit event");
    }

    Ok(())
}

/// Query audit entries for a specific memory.
pub fn query_by_memory(conn: &Connection, memory_id: &str) -> CortexResult<Vec<AuditEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, operation, details, actor, timestamp
             FROM memory_audit_log WHERE memory_id = ?1
             ORDER BY timestamp DESC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    collect_audit_entries(&mut stmt, params![memory_id])
}

/// Query audit entries within a time range.
pub fn query_by_time_range(
    conn: &Connection,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> CortexResult<Vec<AuditEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, operation, details, actor, timestamp
             FROM memory_audit_log WHERE timestamp >= ?1 AND timestamp <= ?2
             ORDER BY timestamp DESC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    collect_audit_entries(&mut stmt, params![from.to_rfc3339(), to.to_rfc3339()])
}

/// Query audit entries by actor.
pub fn query_by_actor(conn: &Connection, actor: &AuditActor) -> CortexResult<Vec<AuditEntry>> {
    let actor_str = serde_json::to_string(actor).map_err(|e| to_storage_err(e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT memory_id, operation, details, actor, timestamp
             FROM memory_audit_log WHERE actor = ?1
             ORDER BY timestamp DESC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    collect_audit_entries(&mut stmt, params![actor_str.trim_matches('"')])
}

fn collect_audit_entries(
    stmt: &mut rusqlite::Statement<'_>,
    params: impl rusqlite::Params,
) -> CortexResult<Vec<AuditEntry>> {
    let rows = stmt
        .query_map(params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut entries = Vec::new();
    for row in rows {
        let (memory_id, op_str, details_str, actor_str, ts_str) =
            row.map_err(|e| to_storage_err(e.to_string()))?;

        let operation: AuditOperation = serde_json::from_str(&format!("\"{op_str}\""))
            .map_err(|e| to_storage_err(format!("parse audit operation: {e}")))?;
        let actor: AuditActor = serde_json::from_str(&format!("\"{actor_str}\""))
            .map_err(|e| to_storage_err(format!("parse audit actor: {e}")))?;
        let details: serde_json::Value = serde_json::from_str(&details_str)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        entries.push(AuditEntry {
            memory_id,
            operation,
            details,
            actor,
            timestamp,
        });
    }
    Ok(entries)
}
