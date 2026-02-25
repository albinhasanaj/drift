//! Pattern/constraint/file/function link CRUD.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::memory::{ConstraintLink, FileLink, FunctionLink, PatternLink};

use crate::to_storage_err;

pub fn add_pattern_link(
    conn: &Connection,
    memory_id: &str,
    link: &PatternLink,
) -> CortexResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO memory_patterns (memory_id, pattern_id, pattern_name)
         VALUES (?1, ?2, ?3)",
        params![memory_id, link.pattern_id, link.pattern_name],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "pattern", "target": link.pattern_id });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        memory_id,
        "link_added",
        &delta,
        "system",
        "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_added event");
    }
    Ok(())
}

pub fn add_constraint_link(
    conn: &Connection,
    memory_id: &str,
    link: &ConstraintLink,
) -> CortexResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO memory_constraints (memory_id, constraint_id, constraint_name)
         VALUES (?1, ?2, ?3)",
        params![memory_id, link.constraint_id, link.constraint_name],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "constraint", "target": link.constraint_id });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        memory_id,
        "link_added",
        &delta,
        "system",
        "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_added event");
    }
    Ok(())
}

pub fn add_file_link(conn: &Connection, memory_id: &str, link: &FileLink) -> CortexResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO memory_files (memory_id, file_path, line_start, line_end, content_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            memory_id,
            link.file_path,
            link.line_start,
            link.line_end,
            link.content_hash,
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "file", "target": link.file_path });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        memory_id,
        "link_added",
        &delta,
        "system",
        "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_added event");
    }
    Ok(())
}

pub fn add_function_link(
    conn: &Connection,
    memory_id: &str,
    link: &FunctionLink,
) -> CortexResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO memory_functions (memory_id, function_name, file_path, signature)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            memory_id,
            link.function_name,
            link.file_path,
            link.signature,
        ],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "function", "target": link.function_name });
    if let Err(e) = crate::temporal_events::emit_event(
        conn,
        memory_id,
        "link_added",
        &delta,
        "system",
        "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_added event");
    }
    Ok(())
}

// ─── E-04: Atomic remove operations (avoids read-modify-write race) ─────────

pub fn remove_pattern_link(
    conn: &Connection,
    memory_id: &str,
    pattern_id: &str,
) -> CortexResult<()> {
    conn.execute(
        "DELETE FROM memory_patterns WHERE memory_id = ?1 AND pattern_id = ?2",
        params![memory_id, pattern_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "pattern", "target": pattern_id });
    if let Err(e) = crate::temporal_events::emit_event(
        conn, memory_id, "link_removed", &delta, "system", "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_removed event");
    }
    Ok(())
}

pub fn remove_constraint_link(
    conn: &Connection,
    memory_id: &str,
    constraint_id: &str,
) -> CortexResult<()> {
    conn.execute(
        "DELETE FROM memory_constraints WHERE memory_id = ?1 AND constraint_id = ?2",
        params![memory_id, constraint_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "constraint", "target": constraint_id });
    if let Err(e) = crate::temporal_events::emit_event(
        conn, memory_id, "link_removed", &delta, "system", "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_removed event");
    }
    Ok(())
}

pub fn remove_file_link(
    conn: &Connection,
    memory_id: &str,
    file_path: &str,
) -> CortexResult<()> {
    conn.execute(
        "DELETE FROM memory_files WHERE memory_id = ?1 AND file_path = ?2",
        params![memory_id, file_path],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "file", "target": file_path });
    if let Err(e) = crate::temporal_events::emit_event(
        conn, memory_id, "link_removed", &delta, "system", "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_removed event");
    }
    Ok(())
}

pub fn remove_function_link(
    conn: &Connection,
    memory_id: &str,
    function_name: &str,
) -> CortexResult<()> {
    conn.execute(
        "DELETE FROM memory_functions WHERE memory_id = ?1 AND function_name = ?2",
        params![memory_id, function_name],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    let delta = serde_json::json!({ "link_type": "function", "target": function_name });
    if let Err(e) = crate::temporal_events::emit_event(
        conn, memory_id, "link_removed", &delta, "system", "link_ops",
    ) {
        tracing::warn!(memory_id = %memory_id, error = %e, "failed to emit link_removed event");
    }
    Ok(())
}
