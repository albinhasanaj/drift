//! Namespace permission management — grant, revoke, check, get ACL.

use chrono::Utc;
use rusqlite::Connection;
use tracing::{info, warn};

use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespacePermission};

use cortex_storage::queries::multiagent_ops;

/// Manages namespace access control lists.
pub struct NamespacePermissionManager;

impl NamespacePermissionManager {
    /// Grant permissions to an agent on a namespace.
    pub fn grant(
        conn: &Connection,
        namespace_id: &NamespaceId,
        agent_id: &AgentId,
        permissions: &[NamespacePermission],
        granted_by: &AgentId,
    ) -> CortexResult<()> {
        // Authorization guard: granter must have Admin permission OR be the namespace owner.
        if !Self::is_owner_or_admin(conn, namespace_id, granted_by)? {
            return Err(cortex_core::errors::MultiAgentError::PermissionDenied {
                agent: granted_by.0.clone(),
                namespace: namespace_id.to_uri(),
                permission: "admin".to_string(),
            }
            .into());
        }

        let uri = namespace_id.to_uri();
        let now_str = Utc::now().to_rfc3339();

        // Merge with existing permissions.
        let mut current = Self::get_permission_set(conn, namespace_id, agent_id)?;
        for p in permissions {
            current.push(permission_to_str(p).to_string());
        }
        current.sort();
        current.dedup();

        let perms_json = serde_json::to_string(&current)
            .map_err(cortex_core::CortexError::SerializationError)?;
        multiagent_ops::insert_permission(
            conn,
            &uri,
            &agent_id.0,
            &perms_json,
            &granted_by.0,
            &now_str,
        )?;

        info!(
            namespace = %uri,
            agent = %agent_id,
            permissions = ?permissions,
            "permissions granted"
        );
        Ok(())
    }

    /// Revoke specific permissions from an agent on a namespace.
    pub fn revoke(
        conn: &Connection,
        namespace_id: &NamespaceId,
        agent_id: &AgentId,
        permissions: &[NamespacePermission],
        revoked_by: &AgentId,
    ) -> CortexResult<()> {
        // Authorization guard: revoker must have Admin permission OR be the namespace owner.
        if !Self::is_owner_or_admin(conn, namespace_id, revoked_by)? {
            return Err(cortex_core::errors::MultiAgentError::PermissionDenied {
                agent: revoked_by.0.clone(),
                namespace: namespace_id.to_uri(),
                permission: "admin".to_string(),
            }
            .into());
        }

        let uri = namespace_id.to_uri();
        let now_str = Utc::now().to_rfc3339();

        let mut current = Self::get_permission_set(conn, namespace_id, agent_id)?;
        let to_remove: Vec<String> = permissions.iter().map(|p| permission_to_str(p).to_string()).collect();
        current.retain(|p| !to_remove.contains(p));

        if current.is_empty() {
            multiagent_ops::delete_permission(conn, &uri, &agent_id.0)?;
        } else {
            let perms_json = serde_json::to_string(&current)
                .map_err(cortex_core::CortexError::SerializationError)?;
            multiagent_ops::insert_permission(
                conn,
                &uri,
                &agent_id.0,
                &perms_json,
                &agent_id.0,
                &now_str,
            )?;
        }

        info!(
            namespace = %uri,
            agent = %agent_id,
            revoked = ?permissions,
            "permissions revoked"
        );
        Ok(())
    }

    /// Check if an agent has a specific permission on a namespace.
    /// Namespace owners always have implicit Admin (and therefore all) permissions.
    pub fn check(
        conn: &Connection,
        namespace_id: &NamespaceId,
        agent_id: &AgentId,
        permission: NamespacePermission,
    ) -> CortexResult<bool> {
        let uri = namespace_id.to_uri();
        let perm_str = permission_to_str(&permission);

        // Check explicit ACL first.
        let result = multiagent_ops::check_permission(conn, &uri, &agent_id.0, perm_str)?;
        if result {
            return Ok(true);
        }

        // Namespace owners have implicit admin (and therefore all permissions).
        if let Some(row) = multiagent_ops::get_namespace(conn, &uri)? {
            if row.owner_agent.as_deref() == Some(&agent_id.0) {
                return Ok(true);
            }
        }

        warn!(
            namespace = %uri,
            agent = %agent_id,
            permission = perm_str,
            "permission check failed"
        );
        Ok(false)
    }

    /// Get the full ACL for a namespace.
    pub fn get_acl(
        conn: &Connection,
        namespace_id: &NamespaceId,
    ) -> CortexResult<Vec<(AgentId, Vec<NamespacePermission>)>> {
        let uri = namespace_id.to_uri();
        let rows = multiagent_ops::get_acl(conn, &uri)?;
        let mut result = Vec::new();
        for (agent_str, perms_json) in rows {
            let perms: Vec<String> = serde_json::from_str(&perms_json).unwrap_or_default();
            let permissions: Vec<NamespacePermission> = perms
                .iter()
                .filter_map(|p| str_to_permission(p))
                .collect();
            result.push((AgentId::from(agent_str.as_str()), permissions));
        }
        Ok(result)
    }

    /// Check if an agent is the namespace owner or has Admin permission.
    /// Delegates to `check(Admin)` which already handles implicit owner admin.
    fn is_owner_or_admin(
        conn: &Connection,
        namespace_id: &NamespaceId,
        agent_id: &AgentId,
    ) -> CortexResult<bool> {
        Self::check(conn, namespace_id, agent_id, NamespacePermission::Admin)
    }

    /// Internal: get the current permission strings for an agent on a namespace.
    fn get_permission_set(
        conn: &Connection,
        namespace_id: &NamespaceId,
        agent_id: &AgentId,
    ) -> CortexResult<Vec<String>> {
        let uri = namespace_id.to_uri();
        match multiagent_ops::get_permissions(conn, &uri, &agent_id.0)? {
            Some(json) => Ok(serde_json::from_str(&json).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }
}

fn permission_to_str(p: &NamespacePermission) -> &'static str {
    match p {
        NamespacePermission::Read => "read",
        NamespacePermission::Write => "write",
        NamespacePermission::Share => "share",
        NamespacePermission::Admin => "admin",
    }
}

fn str_to_permission(s: &str) -> Option<NamespacePermission> {
    match s {
        "read" => Some(NamespacePermission::Read),
        "write" => Some(NamespacePermission::Write),
        "share" => Some(NamespacePermission::Share),
        "admin" => Some(NamespacePermission::Admin),
        _ => None,
    }
}
