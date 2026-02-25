//! Agent registration, deregistration, and lifecycle management.

use chrono::Utc;
use rusqlite::Connection;
use tracing::info;

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::{AgentId, AgentRegistration, AgentStatus};

use cortex_storage::queries::multiagent_ops;

/// Manages agent lifecycle: register, deregister, status transitions.
pub struct AgentRegistry;

impl AgentRegistry {
    /// Register a new agent. Creates the agent record and its default namespace.
    /// Returns the full `AgentRegistration`.
    pub fn register(
        conn: &Connection,
        name: &str,
        capabilities: Vec<String>,
    ) -> CortexResult<AgentRegistration> {
        if name.is_empty() {
            return Err(MultiAgentError::InvalidNamespaceUri(
                "agent name cannot be empty".to_string(),
            )
            .into());
        }

        // Validate agent name length and characters.
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

        // Check for duplicate (shouldn't happen with UUID, but be safe).
        if multiagent_ops::get_agent(conn, &agent_id.0)?.is_some() {
            return Err(MultiAgentError::AgentAlreadyRegistered(agent_id.0.clone()).into());
        }

        // Insert agent.
        multiagent_ops::insert_agent(
            conn,
            &multiagent_ops::InsertAgentParams {
                agent_id: &agent_id.0,
                name,
                namespace_id: &namespace_uri,
                capabilities_json: &caps_json,
                parent_agent: None,
                registered_at: &now_str,
                status: "active",
            },
        )?;

        // Create default namespace for this agent.
        multiagent_ops::insert_namespace(conn, &namespace_uri, "agent", Some(&agent_id.0), &now_str)?;

        // Grant all permissions to the agent on its own namespace.
        let all_perms = serde_json::to_string(&["read", "write", "share", "admin"])
            .map_err(cortex_core::CortexError::SerializationError)?;
        multiagent_ops::insert_permission(
            conn,
            &namespace_uri,
            &agent_id.0,
            &all_perms,
            &agent_id.0,
            &now_str,
        )?;

        info!(agent_id = %agent_id, name, "agent registered");

        Ok(AgentRegistration {
            agent_id,
            name: name.to_string(),
            namespace: namespace_uri,
            capabilities,
            parent_agent: None,
            registered_at: now,
            last_active: now,
            status: AgentStatus::Active,
        })
    }

    /// Deregister an agent. Sets status to Deregistered, preserves provenance.
    pub fn deregister(conn: &Connection, agent_id: &AgentId) -> CortexResult<()> {
        let agent = multiagent_ops::get_agent(conn, &agent_id.0)?
            .ok_or_else(|| MultiAgentError::AgentNotFound(agent_id.0.clone()))?;

        if agent.status.starts_with("deregistered") {
            return Err(MultiAgentError::AgentNotFound(format!(
                "{} is already deregistered",
                agent_id.0
            ))
            .into());
        }

        let now_str = Utc::now().to_rfc3339();
        // Update status — provenance is preserved (append-only, never deleted).
        multiagent_ops::update_agent_status(conn, &agent_id.0, &format!("deregistered:{now_str}"))?;

        info!(agent_id = %agent_id, "agent deregistered");
        Ok(())
    }

    /// Look up an agent by ID.
    pub fn get_agent(
        conn: &Connection,
        agent_id: &AgentId,
    ) -> CortexResult<Option<AgentRegistration>> {
        let row = multiagent_ops::get_agent(conn, &agent_id.0)?;
        match row {
            Some(r) => Ok(Some(row_to_registration(r)?)),
            None => Ok(None),
        }
    }

    /// List agents, optionally filtered by status.
    pub fn list_agents(
        conn: &Connection,
        filter: Option<&AgentStatus>,
    ) -> CortexResult<Vec<AgentRegistration>> {
        let status_str = filter.map(|s| match s {
            AgentStatus::Active => "active".to_string(),
            AgentStatus::Idle { .. } => "idle".to_string(),
            AgentStatus::Deregistered { .. } => "deregistered".to_string(),
        });
        let rows = multiagent_ops::list_agents(conn, status_str.as_deref())?;
        rows.into_iter().map(row_to_registration).collect()
    }

    /// Update the last_active timestamp (heartbeat).
    pub fn update_last_active(conn: &Connection, agent_id: &AgentId) -> CortexResult<()> {
        let now_str = Utc::now().to_rfc3339();
        multiagent_ops::update_last_active(conn, &agent_id.0, &now_str)?;
        Ok(())
    }

    /// Mark an agent as idle.
    pub fn mark_idle(conn: &Connection, agent_id: &AgentId) -> CortexResult<()> {
        let now_str = Utc::now().to_rfc3339();
        multiagent_ops::update_agent_status(conn, &agent_id.0, &format!("idle:{now_str}"))?;
        info!(agent_id = %agent_id, "agent marked idle");
        Ok(())
    }
}

/// Convert a raw DB row to an `AgentRegistration`.
fn row_to_registration(row: multiagent_ops::AgentRow) -> CortexResult<AgentRegistration> {
    let parse_dt = |s: &str| -> CortexResult<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| {
                cortex_storage::to_storage_err(format!("parse datetime '{s}': {e}"))
            })
    };

    let status = parse_agent_status(&row.status)?;
    let capabilities: Vec<String> = row
        .capabilities
        .as_deref()
        .map(|c| serde_json::from_str(c).unwrap_or_default())
        .unwrap_or_default();

    Ok(AgentRegistration {
        agent_id: AgentId::from(row.agent_id.as_str()),
        name: row.name,
        namespace: row.namespace_id,
        capabilities,
        parent_agent: row.parent_agent.map(|p| AgentId::from(p.as_str())),
        registered_at: parse_dt(&row.registered_at)?,
        last_active: parse_dt(&row.last_active)?,
        status,
    })
}

/// Parse a status string from the DB into an `AgentStatus`.
fn parse_agent_status(s: &str) -> CortexResult<AgentStatus> {
    if s == "active" {
        return Ok(AgentStatus::Active);
    }
    if let Some(since_str) = s.strip_prefix("idle:") {
        let since = chrono::DateTime::parse_from_rfc3339(since_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| cortex_storage::to_storage_err(format!("parse idle timestamp: {e}")))?;
        return Ok(AgentStatus::Idle { since });
    }
    if let Some(at_str) = s.strip_prefix("deregistered:") {
        let at = chrono::DateTime::parse_from_rfc3339(at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| {
                cortex_storage::to_storage_err(format!("parse deregistered timestamp: {e}"))
            })?;
        return Ok(AgentStatus::Deregistered { at });
    }
    // Fallback for simple "deregistered" without timestamp.
    if s.starts_with("deregistered") {
        return Ok(AgentStatus::Deregistered { at: Utc::now() });
    }
    Ok(AgentStatus::Active)
}
