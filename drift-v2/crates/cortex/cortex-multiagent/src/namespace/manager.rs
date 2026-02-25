//! Namespace CRUD operations.

use chrono::Utc;
use rusqlite::Connection;
use tracing::info;

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespaceScope};

use cortex_storage::queries::multiagent_ops;

/// Manages namespace creation, retrieval, listing, and deletion.
pub struct NamespaceManager;

impl NamespaceManager {
    /// Create a new namespace. Grants default permissions based on scope.
    pub fn create_namespace(
        conn: &Connection,
        namespace: &NamespaceId,
        owner: &AgentId,
    ) -> CortexResult<NamespaceId> {
        let uri = namespace.to_uri();
        let scope_str = match &namespace.scope {
            NamespaceScope::Agent(_) => "agent",
            NamespaceScope::Team(_) => "team",
            NamespaceScope::Project(_) => "project",
        };
        let now_str = Utc::now().to_rfc3339();

        // Check if namespace already exists.
        if multiagent_ops::get_namespace(conn, &uri)?.is_some() {
            return Err(MultiAgentError::InvalidNamespaceUri(format!(
                "namespace already exists: {uri}"
            ))
            .into());
        }

        multiagent_ops::insert_namespace(conn, &uri, scope_str, Some(&owner.0), &now_str)?;

        // Grant default permissions based on scope.
        // Agent scope: owner gets full control (all 4).
        // Team scope: owner gets read + write (collaborate, but not admin others).
        // Project scope: owner gets read only (broad visibility, controlled writes).
        let default_perms = match &namespace.scope {
            NamespaceScope::Agent(_) => vec!["read", "write", "share", "admin"],
            NamespaceScope::Team(_) => vec!["read", "write"],
            NamespaceScope::Project(_) => vec!["read"],
        };
        let perms_json = serde_json::to_string(&default_perms)
            .map_err(cortex_core::CortexError::SerializationError)?;
        multiagent_ops::insert_permission(conn, &uri, &owner.0, &perms_json, &owner.0, &now_str)?;

        info!(namespace = %uri, scope = scope_str, owner = %owner, "namespace created");
        Ok(namespace.clone())
    }

    /// Get a namespace by ID.
    pub fn get_namespace(
        conn: &Connection,
        namespace_id: &NamespaceId,
    ) -> CortexResult<Option<multiagent_ops::NamespaceRow>> {
        let uri = namespace_id.to_uri();
        multiagent_ops::get_namespace(conn, &uri)
    }

    /// List namespaces, optionally filtered by scope.
    pub fn list_namespaces(
        conn: &Connection,
        scope_filter: Option<&NamespaceScope>,
    ) -> CortexResult<Vec<multiagent_ops::NamespaceRow>> {
        let scope_str = scope_filter.map(|s| match s {
            NamespaceScope::Agent(_) => "agent".to_string(),
            NamespaceScope::Team(_) => "team".to_string(),
            NamespaceScope::Project(_) => "project".to_string(),
        });
        multiagent_ops::list_namespaces(conn, scope_str.as_deref())
    }

    /// Delete a namespace.
    pub fn delete_namespace(conn: &Connection, namespace_id: &NamespaceId) -> CortexResult<()> {
        let uri = namespace_id.to_uri();
        // Verify it exists.
        multiagent_ops::get_namespace(conn, &uri)?
            .ok_or_else(|| MultiAgentError::NamespaceNotFound(uri.clone()))?;

        // Check for dependent projections before deleting.
        let projections = multiagent_ops::list_projections(conn, &uri)?;
        if !projections.is_empty() {
            return Err(MultiAgentError::InvalidNamespaceUri(format!(
                "cannot delete namespace {uri}: {} dependent projection(s) exist",
                projections.len()
            ))
            .into());
        }

        multiagent_ops::delete_namespace(conn, &uri)?;
        info!(namespace = %uri, "namespace deleted");
        Ok(())
    }
}
