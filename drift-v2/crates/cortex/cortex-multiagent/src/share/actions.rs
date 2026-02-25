//! Share, promote, and retract operations.
//!
//! - **Share** = copy memory to target namespace with provenance hop (SharedTo).
//! - **Promote** = move memory to target namespace, update namespace field (ProjectedTo).
//! - **Retract** = tombstone memory in target namespace, preserve in source.
//!
//! All operations check permissions BEFORE executing.

use chrono::Utc;
use rusqlite::Connection;
use tracing::info;

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespacePermission};

use cortex_storage::queries::{memory_crud, multiagent_ops};

use crate::namespace::permissions::NamespacePermissionManager;

/// Helper to insert a provenance hop using the param struct.
fn record_provenance(conn: &Connection, p: &multiagent_ops::InsertProvenanceHopParams<'_>) -> CortexResult<()> {
    multiagent_ops::insert_provenance_hop(conn, p)
}

/// Share a memory: copy to target namespace with provenance hop.
pub fn share(
    conn: &Connection,
    memory_id: &str,
    target_namespace: &NamespaceId,
    agent_id: &AgentId,
) -> CortexResult<()> {
    // Permission check BEFORE operation.
    if !NamespacePermissionManager::check(conn, target_namespace, agent_id, NamespacePermission::Write)? {
        return Err(MultiAgentError::PermissionDenied {
            agent: agent_id.0.clone(),
            namespace: target_namespace.to_uri(),
            permission: "write".to_string(),
        }
        .into());
    }

    // Verify memory exists.
    let memory = memory_crud::get_memory(conn, memory_id)?
        .ok_or_else(|| cortex_core::CortexError::MemoryNotFound { id: memory_id.to_string() })?;

    let chain = multiagent_ops::get_provenance_chain(conn, memory_id)?;
    let now_str = Utc::now().to_rfc3339();

    // Record provenance hop on the original.
    let details_json = serde_json::json!({ "target": target_namespace.to_uri() }).to_string();
    record_provenance(conn, &multiagent_ops::InsertProvenanceHopParams {
        memory_id, hop_index: chain.len() as i32, agent_id: &agent_id.0,
        action: "shared_to", timestamp: &now_str, confidence_delta: 0.0, details: Some(&details_json),
    })?;

    // Create a copy in the target namespace with a new ID.
    let new_id = uuid::Uuid::new_v4().to_string();
    let target_uri = target_namespace.to_uri();

    conn.execute(
        "INSERT INTO memories (id, memory_type, content, summary, transaction_time, valid_time,
            valid_until, confidence, importance, last_accessed, access_count,
            tags, archived, superseded_by, supersedes, content_hash, namespace_id, source_agent)
         SELECT ?1, memory_type, content, summary, transaction_time, valid_time,
            valid_until, confidence, importance, last_accessed, access_count,
            tags, archived, superseded_by, supersedes, content_hash, ?2, ?3
         FROM memories WHERE id = ?4",
        rusqlite::params![new_id, target_uri, agent_id.0, memory_id],
    )
    .map_err(|e| cortex_storage::to_storage_err(e.to_string()))?;

    // Record provenance for the copy.
    let copy_details = serde_json::json!({
        "source_memory": memory_id,
        "source_namespace": memory.namespace.to_uri(),
        "target_namespace": target_uri,
    })
    .to_string();
    record_provenance(conn, &multiagent_ops::InsertProvenanceHopParams {
        memory_id: &new_id, hop_index: 0, agent_id: &agent_id.0,
        action: "shared_to", timestamp: &now_str, confidence_delta: 0.0, details: Some(&copy_details),
    })?;

    info!(memory_id, new_id = %new_id, target = %target_uri, agent = %agent_id, "memory shared");
    Ok(())
}

/// Promote a memory: move to target namespace, update namespace field.
pub fn promote(
    conn: &Connection,
    memory_id: &str,
    target_namespace: &NamespaceId,
    agent_id: &AgentId,
) -> CortexResult<()> {
    if !NamespacePermissionManager::check(conn, target_namespace, agent_id, NamespacePermission::Write)? {
        return Err(MultiAgentError::PermissionDenied {
            agent: agent_id.0.clone(),
            namespace: target_namespace.to_uri(),
            permission: "write".to_string(),
        }
        .into());
    }

    memory_crud::get_memory(conn, memory_id)?
        .ok_or_else(|| cortex_core::CortexError::MemoryNotFound { id: memory_id.to_string() })?;

    let target_uri = target_namespace.to_uri();
    multiagent_ops::update_memory_namespace(conn, memory_id, &target_uri)?;

    let chain = multiagent_ops::get_provenance_chain(conn, memory_id)?;
    let now_str = Utc::now().to_rfc3339();
    let details = serde_json::json!({ "target": target_uri }).to_string();
    record_provenance(conn, &multiagent_ops::InsertProvenanceHopParams {
        memory_id, hop_index: chain.len() as i32, agent_id: &agent_id.0,
        action: "projected_to", timestamp: &now_str, confidence_delta: 0.0, details: Some(&details),
    })?;

    info!(memory_id, target = %target_uri, agent = %agent_id, "memory promoted");
    Ok(())
}

/// Retract a memory: tombstone (archive) in target namespace.
pub fn retract(
    conn: &Connection,
    memory_id: &str,
    _namespace: &NamespaceId,
    agent_id: &AgentId,
) -> CortexResult<()> {
    memory_crud::get_memory(conn, memory_id)?
        .ok_or_else(|| cortex_core::CortexError::MemoryNotFound { id: memory_id.to_string() })?;

    multiagent_ops::archive_memory(conn, memory_id)?;

    let chain = multiagent_ops::get_provenance_chain(conn, memory_id)?;
    let now_str = Utc::now().to_rfc3339();
    record_provenance(conn, &multiagent_ops::InsertProvenanceHopParams {
        memory_id, hop_index: chain.len() as i32, agent_id: &agent_id.0,
        action: "retracted", timestamp: &now_str, confidence_delta: 0.0, details: None,
    })?;

    info!(memory_id, agent = %agent_id, "memory retracted");
    Ok(())
}
