//! Namespace URI parsing and formatting utilities.
//!
//! URI format: `{scope}://{name}/`
//! - Parsing is case-insensitive for scope, case-preserving for name.
//! - Invalid URIs return `MultiAgentError::InvalidNamespaceUri`.

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespaceScope};

/// Parse a namespace URI string into a `NamespaceId`.
///
/// Accepted formats: `agent://name/`, `team://name/`, `project://name/`.
/// Case-insensitive for scope prefix, case-preserving for name.
pub fn parse(uri: &str) -> CortexResult<NamespaceId> {
    let trimmed = uri.trim_end_matches('/');
    let parts: Vec<&str> = trimmed.splitn(2, "://").collect();
    if parts.len() != 2 {
        return Err(MultiAgentError::InvalidNamespaceUri(uri.to_string()).into());
    }
    let (scope_str, name) = (parts[0].to_lowercase(), parts[1].to_string());
    if name.is_empty() {
        return Err(MultiAgentError::InvalidNamespaceUri(format!(
            "namespace name cannot be empty: {uri}"
        ))
        .into());
    }

    // Validate namespace name length and characters.
    if name.len() > 256 {
        return Err(MultiAgentError::InvalidNamespaceUri(format!(
            "namespace name too long ({} chars, max 256): {uri}",
            name.len()
        ))
        .into());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err(MultiAgentError::InvalidNamespaceUri(format!(
            "namespace name contains invalid characters (allowed: alphanumeric, -, _, .): {uri}"
        ))
        .into());
    }
    let scope = match scope_str.as_str() {
        "agent" => NamespaceScope::Agent(AgentId::from(name.as_str())),
        "team" => NamespaceScope::Team(name.clone()),
        "project" => NamespaceScope::Project(name.clone()),
        _ => {
            return Err(MultiAgentError::InvalidNamespaceUri(format!(
                "unknown scope '{scope_str}' in URI: {uri}"
            ))
            .into())
        }
    };
    Ok(NamespaceId { scope, name })
}

/// Format a `NamespaceId` back to its URI string.
pub fn to_uri(ns: &NamespaceId) -> String {
    ns.to_uri()
}

/// The default namespace for backward compatibility.
pub fn default_namespace() -> NamespaceId {
    NamespaceId::default_namespace()
}

/// Whether a namespace is agent-scoped.
pub fn is_agent(ns: &NamespaceId) -> bool {
    ns.is_agent()
}

/// Whether a namespace is team-scoped.
pub fn is_team(ns: &NamespaceId) -> bool {
    ns.is_team()
}

/// Whether a namespace is project-scoped.
pub fn is_project(ns: &NamespaceId) -> bool {
    ns.is_project()
}

/// Whether a namespace is shared (team or project).
pub fn is_shared(ns: &NamespaceId) -> bool {
    ns.is_shared()
}
