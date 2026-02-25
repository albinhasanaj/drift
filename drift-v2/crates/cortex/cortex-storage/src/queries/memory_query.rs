//! Query memories by type, importance, confidence range, date range, tags.
//! Supports optional namespace filtering for multi-agent isolation.

use rusqlite::Connection;

use chrono::{DateTime, Utc};
use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, Importance, MemoryType};
use cortex_core::models::namespace::NamespaceId;

use super::memory_crud::parse_memory_row;
use crate::to_storage_err;

/// The base SELECT columns for all memory queries (18 columns, indices 0-17).
const MEMORY_COLUMNS: &str =
    "id, memory_type, content, summary, transaction_time, valid_time,
     valid_until, confidence, importance, last_accessed, access_count,
     tags, archived, superseded_by, supersedes, content_hash,
     namespace_id, source_agent";

/// Query memories by type, with optional namespace filter.
pub fn query_by_type(
    conn: &Connection,
    memory_type: MemoryType,
    namespace_filter: Option<&NamespaceId>,
) -> CortexResult<Vec<BaseMemory>> {
    let type_str =
        serde_json::to_string(&memory_type).map_err(|e| to_storage_err(e.to_string()))?;
    let type_str = type_str.trim_matches('"');

    let (sql, dyn_params) = match namespace_filter {
        Some(ns) => (
            format!(
                "SELECT {MEMORY_COLUMNS} FROM memories WHERE memory_type = ?1 AND archived = 0 AND namespace_id = ?2"
            ),
            vec![
                Box::new(type_str.to_string()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(ns.to_uri()) as Box<dyn rusqlite::types::ToSql>,
            ],
        ),
        None => (
            format!(
                "SELECT {MEMORY_COLUMNS} FROM memories WHERE memory_type = ?1 AND archived = 0"
            ),
            vec![Box::new(type_str.to_string()) as Box<dyn rusqlite::types::ToSql>],
        ),
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> = dyn_params.iter().map(|p| p.as_ref()).collect();
    collect_memories_dyn(&mut stmt, params_refs.as_slice())
}

/// Query memories with importance >= min, with optional namespace filter.
pub fn query_by_importance(
    conn: &Connection,
    min: Importance,
    namespace_filter: Option<&NamespaceId>,
) -> CortexResult<Vec<BaseMemory>> {
    let importance_values = match min {
        Importance::Low => vec!["low", "normal", "high", "critical"],
        Importance::Normal => vec!["normal", "high", "critical"],
        Importance::High => vec!["high", "critical"],
        Importance::Critical => vec!["critical"],
    };

    let placeholders: Vec<String> = importance_values
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();

    let ns_clause = if namespace_filter.is_some() {
        let idx = importance_values.len() + 1;
        format!(" AND namespace_id = ?{idx}")
    } else {
        String::new()
    };

    let imp_placeholders = &placeholders[..importance_values.len()];
    let sql = format!(
        "SELECT {MEMORY_COLUMNS} FROM memories WHERE importance IN ({}) AND archived = 0{ns_clause}",
        imp_placeholders.join(", ")
    );

    let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = importance_values
        .iter()
        .map(|v| Box::new(v.to_string()) as Box<dyn rusqlite::types::ToSql>)
        .collect();
    if let Some(ns) = namespace_filter {
        params.push(Box::new(ns.to_uri()));
    }
    let params_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| Ok(parse_memory_row(row)))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
        results.push(memory);
    }
    Ok(results)
}

/// Query memories within a confidence range, with optional namespace filter.
pub fn query_by_confidence_range(
    conn: &Connection,
    min: f64,
    max: f64,
    namespace_filter: Option<&NamespaceId>,
) -> CortexResult<Vec<BaseMemory>> {
    let (sql, dyn_params) = match namespace_filter {
        Some(ns) => (
            format!(
                "SELECT {MEMORY_COLUMNS} FROM memories WHERE confidence >= ?1 AND confidence <= ?2 AND archived = 0 AND namespace_id = ?3"
            ),
            vec![
                Box::new(min) as Box<dyn rusqlite::types::ToSql>,
                Box::new(max) as Box<dyn rusqlite::types::ToSql>,
                Box::new(ns.to_uri()) as Box<dyn rusqlite::types::ToSql>,
            ],
        ),
        None => (
            format!(
                "SELECT {MEMORY_COLUMNS} FROM memories WHERE confidence >= ?1 AND confidence <= ?2 AND archived = 0"
            ),
            vec![
                Box::new(min) as Box<dyn rusqlite::types::ToSql>,
                Box::new(max) as Box<dyn rusqlite::types::ToSql>,
            ],
        ),
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> = dyn_params.iter().map(|p| p.as_ref()).collect();
    collect_memories_dyn(&mut stmt, params_refs.as_slice())
}

/// Query memories within a date range (by transaction_time), with optional namespace filter.
pub fn query_by_date_range(
    conn: &Connection,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    namespace_filter: Option<&NamespaceId>,
) -> CortexResult<Vec<BaseMemory>> {
    let (sql, dyn_params) = match namespace_filter {
        Some(ns) => (
            format!(
                "SELECT {MEMORY_COLUMNS} FROM memories WHERE transaction_time >= ?1 AND transaction_time <= ?2 AND archived = 0 AND namespace_id = ?3"
            ),
            vec![
                Box::new(from.to_rfc3339()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(to.to_rfc3339()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(ns.to_uri()) as Box<dyn rusqlite::types::ToSql>,
            ],
        ),
        None => (
            format!(
                "SELECT {MEMORY_COLUMNS} FROM memories WHERE transaction_time >= ?1 AND transaction_time <= ?2 AND archived = 0"
            ),
            vec![
                Box::new(from.to_rfc3339()) as Box<dyn rusqlite::types::ToSql>,
                Box::new(to.to_rfc3339()) as Box<dyn rusqlite::types::ToSql>,
            ],
        ),
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> = dyn_params.iter().map(|p| p.as_ref()).collect();
    collect_memories_dyn(&mut stmt, params_refs.as_slice())
}

/// Query memories by tags (any match), with optional namespace filter.
pub fn query_by_tags(
    conn: &Connection,
    tags: &[String],
    namespace_filter: Option<&NamespaceId>,
) -> CortexResult<Vec<BaseMemory>> {
    let mut results = Vec::new();
    for tag in tags {
        let pattern = format!("%\"{tag}\"%");
        let (sql, dyn_params) = match namespace_filter {
            Some(ns) => (
                format!(
                    "SELECT {MEMORY_COLUMNS} FROM memories WHERE tags LIKE ?1 AND archived = 0 AND namespace_id = ?2"
                ),
                vec![
                    Box::new(pattern.clone()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(ns.to_uri()) as Box<dyn rusqlite::types::ToSql>,
                ],
            ),
            None => (
                format!(
                    "SELECT {MEMORY_COLUMNS} FROM memories WHERE tags LIKE ?1 AND archived = 0"
                ),
                vec![Box::new(pattern.clone()) as Box<dyn rusqlite::types::ToSql>],
            ),
        };

        let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = dyn_params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| Ok(parse_memory_row(row)))
            .map_err(|e| to_storage_err(e.to_string()))?;

        for row in rows {
            let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
            if !results.iter().any(|m: &BaseMemory| m.id == memory.id) {
                results.push(memory);
            }
        }
    }
    Ok(results)
}

/// Helper: collect memories from a prepared statement with dynamic params.
fn collect_memories_dyn(
    stmt: &mut rusqlite::Statement<'_>,
    params: &[&dyn rusqlite::types::ToSql],
) -> CortexResult<Vec<BaseMemory>> {
    let rows = stmt
        .query_map(params, |row| Ok(parse_memory_row(row)))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        let memory = row.map_err(|e| to_storage_err(e.to_string()))??;
        results.push(memory);
    }
    Ok(results)
}
