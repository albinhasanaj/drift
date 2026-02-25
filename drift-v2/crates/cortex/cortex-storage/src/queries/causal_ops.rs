//! Causal edge CRUD, evidence management.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::traits::{CausalEdge, CausalEvidence};

use crate::to_storage_err;

/// Add a causal edge.
/// Wrapped in a SAVEPOINT for atomicity: edge + event + evidence are all-or-nothing.
pub fn add_edge(conn: &Connection, edge: &CausalEdge) -> CortexResult<()> {
    conn.execute_batch("SAVEPOINT add_edge_sp")
        .map_err(|e| to_storage_err(format!("add_edge savepoint: {e}")))?;

    match add_edge_inner(conn, edge) {
        Ok(()) => {
            conn.execute_batch("RELEASE add_edge_sp")
                .map_err(|e| to_storage_err(format!("add_edge release: {e}")))?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO add_edge_sp");
            let _ = conn.execute_batch("RELEASE add_edge_sp");
            Err(e)
        }
    }
}

/// Inner add_edge logic.
fn add_edge_inner(conn: &Connection, edge: &CausalEdge) -> CortexResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO causal_edges (source_id, target_id, relation, strength)
         VALUES (?1, ?2, ?3, ?4)",
        params![edge.source_id, edge.target_id, edge.relation, edge.strength],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // Emit RelationshipAdded temporal event (CR3).
    let delta = serde_json::json!({
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relation": edge.relation,
        "strength": edge.strength,
    });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        &edge.source_id,
        "relationship_added",
        &delta,
        "system",
        "causal_ops",
    ) {
        tracing::warn!(source_id = %edge.source_id, error = %e, "failed to emit relationship_added event");
    }

    // Insert evidence.
    for ev in &edge.evidence {
        add_evidence_row(conn, &edge.source_id, &edge.target_id, ev)?;
    }

    Ok(())
}

/// Get all edges for a node (as source or target).
pub fn get_edges(conn: &Connection, node_id: &str) -> CortexResult<Vec<CausalEdge>> {
    let mut stmt = conn
        .prepare(
            "SELECT source_id, target_id, relation, strength
             FROM causal_edges
             WHERE source_id = ?1 OR target_id = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![node_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, f64>(3)?,
            ))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut edges = Vec::new();
    for row in rows {
        let (source_id, target_id, relation, strength) =
            row.map_err(|e| to_storage_err(e.to_string()))?;
        let evidence = get_evidence(conn, &source_id, &target_id)?;
        edges.push(CausalEdge {
            source_id,
            target_id,
            relation,
            strength,
            evidence,
            source_agent: None,
        });
    }
    Ok(edges)
}

/// Remove a causal edge.
pub fn remove_edge(conn: &Connection, source_id: &str, target_id: &str) -> CortexResult<()> {
    // Emit RelationshipRemoved temporal event BEFORE deletion (CR3).
    let delta = serde_json::json!({
        "source_id": source_id,
        "target_id": target_id,
    });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        source_id,
        "relationship_removed",
        &delta,
        "system",
        "causal_ops",
    ) {
        tracing::warn!(source_id = %source_id, error = %e, "failed to emit relationship_removed event");
    }

    // Evidence is cascade-deleted.
    conn.execute(
        "DELETE FROM causal_edges WHERE source_id = ?1 AND target_id = ?2",
        params![source_id, target_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Update edge strength.
pub fn update_strength(
    conn: &Connection,
    source_id: &str,
    target_id: &str,
    strength: f64,
) -> CortexResult<()> {
    conn.execute(
        "UPDATE causal_edges SET strength = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE source_id = ?1 AND target_id = ?2",
        params![source_id, target_id, strength],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // Emit StrengthUpdated temporal event (CR3).
    let delta = serde_json::json!({
        "source_id": source_id,
        "target_id": target_id,
        "new_strength": strength,
    });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        source_id,
        "strength_updated",
        &delta,
        "system",
        "causal_ops",
    ) {
        tracing::warn!(source_id = %source_id, error = %e, "failed to emit strength_updated event");
    }

    Ok(())
}

/// Add evidence to an existing edge.
pub fn add_evidence(
    conn: &Connection,
    source_id: &str,
    target_id: &str,
    evidence: &CausalEvidence,
) -> CortexResult<()> {
    add_evidence_row(conn, source_id, target_id, evidence)
}

fn add_evidence_row(
    conn: &Connection,
    source_id: &str,
    target_id: &str,
    evidence: &CausalEvidence,
) -> CortexResult<()> {
    conn.execute(
        "INSERT INTO causal_evidence (source_id, target_id, description, source, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            source_id,
            target_id,
            evidence.description,
            evidence.source,
            evidence.timestamp.to_rfc3339(),
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

fn get_evidence(
    conn: &Connection,
    source_id: &str,
    target_id: &str,
) -> CortexResult<Vec<CausalEvidence>> {
    let mut stmt = conn
        .prepare(
            "SELECT description, source, timestamp FROM causal_evidence
             WHERE source_id = ?1 AND target_id = ?2
             ORDER BY timestamp",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![source_id, target_id], |row| {
            let ts_str: String = row.get(2)?;
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, ts_str))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut evidence = Vec::new();
    for row in rows {
        let (description, source, ts_str) = row.map_err(|e| to_storage_err(e.to_string()))?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        evidence.push(CausalEvidence {
            description,
            source,
            timestamp,
        });
    }
    Ok(evidence)
}

/// Check if adding an edge would create a cycle (simple BFS from target to source).
pub fn has_cycle(conn: &Connection, source_id: &str, target_id: &str) -> CortexResult<bool> {
    // BFS from target_id: can we reach source_id?
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(target_id.to_string());

    while let Some(current) = queue.pop_front() {
        if current == source_id {
            return Ok(true);
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        let mut stmt = conn
            .prepare("SELECT target_id FROM causal_edges WHERE source_id = ?1")
            .map_err(|e| to_storage_err(e.to_string()))?;
        let rows = stmt
            .query_map(params![current], |row| row.get::<_, String>(0))
            .map_err(|e| to_storage_err(e.to_string()))?;
        for row in rows {
            let next = row.map_err(|e| to_storage_err(e.to_string()))?;
            if !visited.contains(&next) {
                queue.push_back(next);
            }
        }
    }
    Ok(false)
}

/// Count total edges.
pub fn edge_count(conn: &Connection) -> CortexResult<usize> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM causal_edges", [], |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(count as usize)
}

/// Count distinct nodes (appearing in any edge).
pub fn node_count(conn: &Connection) -> CortexResult<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT id) FROM (
                SELECT source_id AS id FROM causal_edges
                UNION
                SELECT target_id AS id FROM causal_edges
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(count as usize)
}

/// List all distinct node IDs appearing in any causal edge.
pub fn list_all_node_ids(conn: &Connection) -> CortexResult<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT id FROM (
                SELECT source_id AS id FROM causal_edges
                UNION
                SELECT target_id AS id FROM causal_edges
            ) ORDER BY id",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(ids)
}

/// Remove edges where neither source nor target exists in the memories table.
pub fn remove_orphaned_edges(conn: &Connection) -> CortexResult<usize> {
    let count = conn
        .execute(
            "DELETE FROM causal_edges
             WHERE source_id NOT IN (SELECT id FROM memories)
                OR target_id NOT IN (SELECT id FROM memories)",
            [],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(count)
}
