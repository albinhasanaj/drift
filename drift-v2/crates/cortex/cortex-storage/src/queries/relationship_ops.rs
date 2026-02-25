//! Relationship CRUD, strength updates.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::memory::{RelationshipEdge, RelationshipType};

use crate::to_storage_err;

/// Add a relationship edge between two memories.
pub fn add_relationship(conn: &Connection, edge: &RelationshipEdge) -> CortexResult<()> {
    let rel_type_str = serde_json::to_string(&edge.relationship_type)
        .map_err(|e| to_storage_err(e.to_string()))?;
    let evidence_json =
        serde_json::to_string(&edge.evidence).map_err(|e| to_storage_err(e.to_string()))?;

    conn.execute(
        "INSERT OR REPLACE INTO memory_relationships
            (source_id, target_id, relationship_type, strength, evidence)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            edge.source_id,
            edge.target_id,
            rel_type_str.trim_matches('"'),
            edge.strength,
            evidence_json,
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get relationships for a memory, optionally filtered by type.
pub fn get_relationships(
    conn: &Connection,
    memory_id: &str,
    rel_type: Option<RelationshipType>,
) -> CortexResult<Vec<RelationshipEdge>> {
    let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match rel_type {
        Some(rt) => {
            let rt_str = serde_json::to_string(&rt).map_err(|e| to_storage_err(e.to_string()))?;
            (
                "SELECT source_id, target_id, relationship_type, strength, evidence
                 FROM memory_relationships
                 WHERE (source_id = ?1 OR target_id = ?1) AND relationship_type = ?2"
                    .to_string(),
                vec![
                    Box::new(memory_id.to_string()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(rt_str.trim_matches('"').to_string()),
                ],
            )
        }
        None => (
            "SELECT source_id, target_id, relationship_type, strength, evidence
             FROM memory_relationships
             WHERE source_id = ?1 OR target_id = ?1"
                .to_string(),
            vec![Box::new(memory_id.to_string()) as Box<dyn rusqlite::types::ToSql>],
        ),
    };

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            let rel_type_str: String = row.get(2)?;
            let evidence_json: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                rel_type_str,
                row.get::<_, f64>(3)?,
                evidence_json,
            ))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let (source_id, target_id, rel_type_str, strength, evidence_json) =
            row.map_err(|e| to_storage_err(e.to_string()))?;

        let relationship_type: RelationshipType =
            serde_json::from_str(&format!("\"{rel_type_str}\""))
                .map_err(|e| to_storage_err(format!("parse relationship type: {e}")))?;
        let evidence: Vec<String> = serde_json::from_str(&evidence_json)
            .map_err(|e| to_storage_err(format!("parse evidence: {e}")))?;

        results.push(RelationshipEdge {
            source_id,
            target_id,
            relationship_type,
            strength,
            evidence,
            cross_agent_relation: None,
        });
    }
    Ok(results)
}

/// Remove a relationship between two memories.
pub fn remove_relationship(
    conn: &Connection,
    source_id: &str,
    target_id: &str,
) -> CortexResult<()> {
    conn.execute(
        "DELETE FROM memory_relationships WHERE source_id = ?1 AND target_id = ?2",
        params![source_id, target_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}
