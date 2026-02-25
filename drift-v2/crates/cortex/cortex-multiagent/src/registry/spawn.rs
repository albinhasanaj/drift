//! Spawned agent creation and deregistration with optional memory promotion.

use chrono::Utc;
use rusqlite::Connection;
use tracing::info;

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::{AgentId, AgentRegistration, AgentStatus, SpawnConfig};

use cortex_storage::queries::multiagent_ops;

/// Spawn a sub-agent with a parent reference.
pub fn spawn_agent(
    conn: &Connection,
    config: &SpawnConfig,
    name: &str,
    capabilities: Vec<String>,
) -> CortexResult<AgentRegistration> {
    // Validate parent exists.
    let _parent = multiagent_ops::get_agent(conn, &config.parent_agent.0)?
        .ok_or_else(|| MultiAgentError::AgentNotFound(config.parent_agent.0.clone()))?;

    // Validate agent name.
    if name.is_empty() {
        return Err(MultiAgentError::InvalidNamespaceUri(
            "agent name cannot be empty".to_string(),
        )
        .into());
    }
    if name.len() > 256 {
        return Err(MultiAgentError::InvalidNamespaceUri(
            format!("agent name too long ({} chars, max 256)", name.len()),
        )
        .into());
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err(MultiAgentError::InvalidNamespaceUri(
            "agent name contains invalid characters (allowed: alphanumeric, -, _, .)".to_string(),
        )
        .into());
    }

    let agent_id = AgentId::new();
    let namespace_uri = format!("agent://{}/", agent_id.0);
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let caps_json = serde_json::to_string(&capabilities)
        .map_err(cortex_core::CortexError::SerializationError)?;

    // Insert agent with parent reference.
    multiagent_ops::insert_agent(
        conn,
        &multiagent_ops::InsertAgentParams {
            agent_id: &agent_id.0,
            name,
            namespace_id: &namespace_uri,
            capabilities_json: &caps_json,
            parent_agent: Some(&config.parent_agent.0),
            registered_at: &now_str,
            status: "active",
        },
    )?;

    // Create default namespace.
    multiagent_ops::insert_namespace(conn, &namespace_uri, "agent", Some(&agent_id.0), &now_str)?;

    // Grant all permissions on own namespace.
    let all_perms = serde_json::to_string(&["read", "write", "share", "admin"])
        .map_err(cortex_core::CortexError::SerializationError)?;
    multiagent_ops::insert_permission(
        conn,
        &namespace_uri,
        &agent_id.0,
        &all_perms,
        &config.parent_agent.0,
        &now_str,
    )?;

    info!(
        agent_id = %agent_id,
        parent = %config.parent_agent,
        name,
        "spawned agent registered"
    );

    // Bootstrap trust inheritance from parent.
    // For each agent that trusts the parent, create a discounted trust
    // record for the child. Uses the simpler approach: bootstrap from
    // the parent's own trust record with the configured discount.
    let parent_trust_rows = multiagent_ops::list_trust_for_agent(conn, &config.parent_agent.0)?;
    for row in &parent_trust_rows {
        let observer = AgentId::from(row.agent_id.as_str());
        let parent_trust = cortex_core::models::cross_agent::AgentTrust {
            agent_id: observer.clone(),
            target_agent: config.parent_agent.clone(),
            overall_trust: row.overall_trust,
            domain_trust: row
                .domain_trust
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default(),
            evidence: cortex_core::models::cross_agent::TrustEvidence::default(),
            last_updated: now,
        };
        let child_trust =
            crate::trust::bootstrap::bootstrap_from_parent(&parent_trust, &agent_id, config.trust_discount);
        crate::trust::scorer::TrustScorer::update_trust(conn, &child_trust)?;
    }

    Ok(AgentRegistration {
        agent_id,
        name: name.to_string(),
        namespace: namespace_uri,
        capabilities,
        parent_agent: Some(config.parent_agent.clone()),
        registered_at: now,
        last_active: now,
        status: AgentStatus::Active,
    })
}

/// Deregister a spawned agent. If `auto_promote` is true, promotes all
/// memories from the sub-agent's namespace to the parent's namespace.
pub fn deregister_spawned(
    conn: &Connection,
    agent_id: &AgentId,
    auto_promote: bool,
) -> CortexResult<()> {
    let agent = multiagent_ops::get_agent(conn, &agent_id.0)?
        .ok_or_else(|| MultiAgentError::AgentNotFound(agent_id.0.clone()))?;

    let parent_id = agent
        .parent_agent
        .as_deref()
        .ok_or_else(|| MultiAgentError::AgentNotFound("agent has no parent".to_string()))?;

    if auto_promote {
        // Get parent's namespace.
        let parent = multiagent_ops::get_agent(conn, parent_id)?
            .ok_or_else(|| MultiAgentError::AgentNotFound(parent_id.to_string()))?;

        // Move all memories from child namespace to parent namespace.
        let memory_ids = multiagent_ops::get_memories_by_namespace(conn, &agent.namespace_id)?;
        for mid in &memory_ids {
            multiagent_ops::update_memory_namespace(conn, mid, &parent.namespace_id)?;
        }
        info!(
            agent_id = %agent_id,
            parent = parent_id,
            promoted = memory_ids.len(),
            "promoted memories to parent namespace"
        );
    }

    // Deregister.
    let now_str = Utc::now().to_rfc3339();
    multiagent_ops::update_agent_status(conn, &agent_id.0, &format!("deregistered:{now_str}"))?;

    info!(agent_id = %agent_id, "spawned agent deregistered");
    Ok(())
}
