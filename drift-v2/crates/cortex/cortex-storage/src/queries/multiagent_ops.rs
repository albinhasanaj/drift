//! Raw SQL operations for multi-agent tables. No business logic — just persistence.

use rusqlite::{params, Connection};
use tracing::debug;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

// ── Agent Registry ──────────────────────────────────────────────────────────

/// Parameters for inserting an agent.
pub struct InsertAgentParams<'a> {
    pub agent_id: &'a str,
    pub name: &'a str,
    pub namespace_id: &'a str,
    pub capabilities_json: &'a str,
    pub parent_agent: Option<&'a str>,
    pub registered_at: &'a str,
    pub status: &'a str,
}

/// Insert a new agent into the registry.
pub fn insert_agent(conn: &Connection, p: &InsertAgentParams<'_>) -> CortexResult<()> {
    debug!(agent_id = p.agent_id, name = p.name, "inserting agent");
    conn.execute(
        "INSERT INTO agent_registry (agent_id, name, namespace_id, capabilities, parent_agent, registered_at, last_active, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
        params![p.agent_id, p.name, p.namespace_id, p.capabilities_json, p.parent_agent, p.registered_at, p.status],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get an agent by ID. Returns (agent_id, name, namespace_id, capabilities, parent_agent, registered_at, last_active, status).
pub fn get_agent(conn: &Connection, agent_id: &str) -> CortexResult<Option<AgentRow>> {
    debug!(agent_id, "getting agent");
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, name, namespace_id, capabilities, parent_agent, registered_at, last_active, status
             FROM agent_registry WHERE agent_id = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![agent_id], |row| {
            Ok(AgentRow {
                agent_id: row.get(0)?,
                name: row.get(1)?,
                namespace_id: row.get(2)?,
                capabilities: row.get(3)?,
                parent_agent: row.get(4)?,
                registered_at: row.get(5)?,
                last_active: row.get(6)?,
                status: row.get(7)?,
            })
        })
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

/// List agents, optionally filtered by status.
pub fn list_agents(conn: &Connection, status_filter: Option<&str>) -> CortexResult<Vec<AgentRow>> {
    debug!(status_filter, "listing agents");
    let (sql, filter_params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match status_filter {
        Some(status) => (
            "SELECT agent_id, name, namespace_id, capabilities, parent_agent, registered_at, last_active, status
             FROM agent_registry WHERE status = ?1".to_string(),
            vec![Box::new(status.to_string()) as Box<dyn rusqlite::types::ToSql>],
        ),
        None => (
            "SELECT agent_id, name, namespace_id, capabilities, parent_agent, registered_at, last_active, status
             FROM agent_registry".to_string(),
            vec![],
        ),
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> = filter_params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            Ok(AgentRow {
                agent_id: row.get(0)?,
                name: row.get(1)?,
                namespace_id: row.get(2)?,
                capabilities: row.get(3)?,
                parent_agent: row.get(4)?,
                registered_at: row.get(5)?,
                last_active: row.get(6)?,
                status: row.get(7)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Update an agent's status.
pub fn update_agent_status(conn: &Connection, agent_id: &str, status: &str) -> CortexResult<()> {
    debug!(agent_id, status, "updating agent status");
    conn.execute(
        "UPDATE agent_registry SET status = ?2 WHERE agent_id = ?1",
        params![agent_id, status],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Update an agent's last_active timestamp.
pub fn update_last_active(conn: &Connection, agent_id: &str, timestamp: &str) -> CortexResult<()> {
    debug!(agent_id, "updating last_active");
    conn.execute(
        "UPDATE agent_registry SET last_active = ?2 WHERE agent_id = ?1",
        params![agent_id, timestamp],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Delete an agent from the registry.
pub fn delete_agent(conn: &Connection, agent_id: &str) -> CortexResult<()> {
    debug!(agent_id, "deleting agent");
    conn.execute(
        "DELETE FROM agent_registry WHERE agent_id = ?1",
        params![agent_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

// ── Namespaces ──────────────────────────────────────────────────────────────

/// Insert a new namespace.
pub fn insert_namespace(
    conn: &Connection,
    namespace_id: &str,
    scope: &str,
    owner_agent: Option<&str>,
    created_at: &str,
) -> CortexResult<()> {
    debug!(namespace_id, scope, "inserting namespace");
    conn.execute(
        "INSERT INTO memory_namespaces (namespace_id, scope, owner_agent, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![namespace_id, scope, owner_agent, created_at],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get a namespace by ID.
pub fn get_namespace(conn: &Connection, namespace_id: &str) -> CortexResult<Option<NamespaceRow>> {
    debug!(namespace_id, "getting namespace");
    let mut stmt = conn
        .prepare(
            "SELECT namespace_id, scope, owner_agent, created_at, metadata
             FROM memory_namespaces WHERE namespace_id = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![namespace_id], |row| {
            Ok(NamespaceRow {
                namespace_id: row.get(0)?,
                scope: row.get(1)?,
                owner_agent: row.get(2)?,
                created_at: row.get(3)?,
                metadata: row.get(4)?,
            })
        })
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

/// List namespaces, optionally filtered by scope.
pub fn list_namespaces(conn: &Connection, scope_filter: Option<&str>) -> CortexResult<Vec<NamespaceRow>> {
    debug!(scope_filter, "listing namespaces");
    let (sql, filter_params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match scope_filter {
        Some(scope) => (
            "SELECT namespace_id, scope, owner_agent, created_at, metadata
             FROM memory_namespaces WHERE scope = ?1".to_string(),
            vec![Box::new(scope.to_string()) as Box<dyn rusqlite::types::ToSql>],
        ),
        None => (
            "SELECT namespace_id, scope, owner_agent, created_at, metadata
             FROM memory_namespaces".to_string(),
            vec![],
        ),
    };

    let mut stmt = conn.prepare(&sql).map_err(|e| to_storage_err(e.to_string()))?;
    let params_refs: Vec<&dyn rusqlite::types::ToSql> = filter_params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            Ok(NamespaceRow {
                namespace_id: row.get(0)?,
                scope: row.get(1)?,
                owner_agent: row.get(2)?,
                created_at: row.get(3)?,
                metadata: row.get(4)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Delete a namespace.
pub fn delete_namespace(conn: &Connection, namespace_id: &str) -> CortexResult<()> {
    debug!(namespace_id, "deleting namespace");
    conn.execute(
        "DELETE FROM memory_namespaces WHERE namespace_id = ?1",
        params![namespace_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

// ── Permissions ─────────────────────────────────────────────────────────────

/// Insert or replace a permission grant.
pub fn insert_permission(
    conn: &Connection,
    namespace_id: &str,
    agent_id: &str,
    permissions_json: &str,
    granted_by: &str,
    granted_at: &str,
) -> CortexResult<()> {
    debug!(namespace_id, agent_id, "granting permissions");
    conn.execute(
        "INSERT OR REPLACE INTO namespace_permissions (namespace_id, agent_id, permissions, granted_by, granted_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![namespace_id, agent_id, permissions_json, granted_by, granted_at],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get permissions for an agent on a namespace.
pub fn get_permissions(conn: &Connection, namespace_id: &str, agent_id: &str) -> CortexResult<Option<String>> {
    debug!(namespace_id, agent_id, "getting permissions");
    let mut stmt = conn
        .prepare(
            "SELECT permissions FROM namespace_permissions
             WHERE namespace_id = ?1 AND agent_id = ?2",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![namespace_id, agent_id], |row| row.get::<_, String>(0))
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

/// Check if an agent has a specific permission on a namespace.
pub fn check_permission(
    conn: &Connection,
    namespace_id: &str,
    agent_id: &str,
    permission: &str,
) -> CortexResult<bool> {
    debug!(namespace_id, agent_id, permission, "checking permission");
    match get_permissions(conn, namespace_id, agent_id)? {
        Some(perms_json) => {
            let perms: Vec<String> =
                serde_json::from_str(&perms_json).unwrap_or_default();
            Ok(perms.iter().any(|p| p == permission || p == "admin"))
        }
        None => Ok(false),
    }
}

/// Delete a permission grant.
pub fn delete_permission(conn: &Connection, namespace_id: &str, agent_id: &str) -> CortexResult<()> {
    debug!(namespace_id, agent_id, "deleting permission");
    conn.execute(
        "DELETE FROM namespace_permissions WHERE namespace_id = ?1 AND agent_id = ?2",
        params![namespace_id, agent_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get the full ACL for a namespace.
pub fn get_acl(conn: &Connection, namespace_id: &str) -> CortexResult<Vec<(String, String)>> {
    debug!(namespace_id, "getting ACL");
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, permissions FROM namespace_permissions WHERE namespace_id = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![namespace_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

// ── Projections ─────────────────────────────────────────────────────────────

/// Parameters for inserting a projection.
pub struct InsertProjectionParams<'a> {
    pub projection_id: &'a str,
    pub source_namespace: &'a str,
    pub target_namespace: &'a str,
    pub filter_json: &'a str,
    pub compression_level: i32,
    pub live: bool,
    pub created_at: &'a str,
    pub created_by: &'a str,
}

/// Insert a new projection.
pub fn insert_projection(conn: &Connection, p: &InsertProjectionParams<'_>) -> CortexResult<()> {
    debug!(projection_id = p.projection_id, source_namespace = p.source_namespace, target_namespace = p.target_namespace, "inserting projection");
    conn.execute(
        "INSERT INTO memory_projections (projection_id, source_namespace, target_namespace, filter_json, compression_level, live, created_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![p.projection_id, p.source_namespace, p.target_namespace, p.filter_json, p.compression_level, p.live as i32, p.created_at, p.created_by],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get a projection by ID.
pub fn get_projection(conn: &Connection, projection_id: &str) -> CortexResult<Option<ProjectionRow>> {
    debug!(projection_id, "getting projection");
    let mut stmt = conn
        .prepare(
            "SELECT projection_id, source_namespace, target_namespace, filter_json, compression_level, live, created_at, created_by
             FROM memory_projections WHERE projection_id = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![projection_id], |row| {
            Ok(ProjectionRow {
                projection_id: row.get(0)?,
                source_namespace: row.get(1)?,
                target_namespace: row.get(2)?,
                filter_json: row.get(3)?,
                compression_level: row.get(4)?,
                live: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                created_by: row.get(7)?,
            })
        })
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

/// List projections for a namespace (as source or target).
pub fn list_projections(conn: &Connection, namespace_id: &str) -> CortexResult<Vec<ProjectionRow>> {
    debug!(namespace_id, "listing projections");
    let mut stmt = conn
        .prepare(
            "SELECT projection_id, source_namespace, target_namespace, filter_json, compression_level, live, created_at, created_by
             FROM memory_projections WHERE source_namespace = ?1 OR target_namespace = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![namespace_id], |row| {
            Ok(ProjectionRow {
                projection_id: row.get(0)?,
                source_namespace: row.get(1)?,
                target_namespace: row.get(2)?,
                filter_json: row.get(3)?,
                compression_level: row.get(4)?,
                live: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                created_by: row.get(7)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Delete a projection.
pub fn delete_projection(conn: &Connection, projection_id: &str) -> CortexResult<()> {
    debug!(projection_id, "deleting projection");
    conn.execute(
        "DELETE FROM memory_projections WHERE projection_id = ?1",
        params![projection_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

// ── Provenance ──────────────────────────────────────────────────────────────

/// Parameters for inserting a provenance hop.
pub struct InsertProvenanceHopParams<'a> {
    pub memory_id: &'a str,
    pub hop_index: i32,
    pub agent_id: &'a str,
    pub action: &'a str,
    pub timestamp: &'a str,
    pub confidence_delta: f64,
    pub details: Option<&'a str>,
}

/// Insert a provenance hop.
pub fn insert_provenance_hop(conn: &Connection, p: &InsertProvenanceHopParams<'_>) -> CortexResult<()> {
    debug!(memory_id = p.memory_id, hop_index = p.hop_index, agent_id = p.agent_id, action = p.action, "inserting provenance hop");
    conn.execute(
        "INSERT INTO provenance_log (memory_id, hop_index, agent_id, action, timestamp, confidence_delta, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![p.memory_id, p.hop_index, p.agent_id, p.action, p.timestamp, p.confidence_delta, p.details],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get the provenance chain for a memory (ordered by hop_index).
pub fn get_provenance_chain(conn: &Connection, memory_id: &str) -> CortexResult<Vec<ProvenanceRow>> {
    debug!(memory_id, "getting provenance chain");
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, hop_index, agent_id, action, timestamp, confidence_delta, details
             FROM provenance_log WHERE memory_id = ?1 ORDER BY hop_index ASC",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![memory_id], |row| {
            Ok(ProvenanceRow {
                memory_id: row.get(0)?,
                hop_index: row.get(1)?,
                agent_id: row.get(2)?,
                action: row.get(3)?,
                timestamp: row.get(4)?,
                confidence_delta: row.get(5)?,
                details: row.get(6)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Get the origin hop (hop_index = 0) for a memory.
pub fn get_provenance_origin(conn: &Connection, memory_id: &str) -> CortexResult<Option<ProvenanceRow>> {
    debug!(memory_id, "getting provenance origin");
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, hop_index, agent_id, action, timestamp, confidence_delta, details
             FROM provenance_log WHERE memory_id = ?1 AND hop_index = 0",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![memory_id], |row| {
            Ok(ProvenanceRow {
                memory_id: row.get(0)?,
                hop_index: row.get(1)?,
                agent_id: row.get(2)?,
                action: row.get(3)?,
                timestamp: row.get(4)?,
                confidence_delta: row.get(5)?,
                details: row.get(6)?,
            })
        })
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

// ── Trust ───────────────────────────────────────────────────────────────────

/// Insert or replace a trust record.
pub fn upsert_trust(
    conn: &Connection,
    agent_id: &str,
    target_agent: &str,
    overall_trust: f64,
    domain_trust_json: Option<&str>,
    evidence_json: &str,
    last_updated: &str,
) -> CortexResult<()> {
    debug!(agent_id, target_agent, overall_trust, "upserting trust");
    conn.execute(
        "INSERT OR REPLACE INTO agent_trust (agent_id, target_agent, overall_trust, domain_trust, evidence, last_updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![agent_id, target_agent, overall_trust, domain_trust_json, evidence_json, last_updated],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get trust from one agent toward another.
pub fn get_trust(conn: &Connection, agent_id: &str, target_agent: &str) -> CortexResult<Option<TrustRow>> {
    debug!(agent_id, target_agent, "getting trust");
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, target_agent, overall_trust, domain_trust, evidence, last_updated
             FROM agent_trust WHERE agent_id = ?1 AND target_agent = ?2",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![agent_id, target_agent], |row| {
            Ok(TrustRow {
                agent_id: row.get(0)?,
                target_agent: row.get(1)?,
                overall_trust: row.get(2)?,
                domain_trust: row.get(3)?,
                evidence: row.get(4)?,
                last_updated: row.get(5)?,
            })
        })
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

/// List all trust records for an agent.
pub fn list_trust_for_agent(conn: &Connection, agent_id: &str) -> CortexResult<Vec<TrustRow>> {
    debug!(agent_id, "listing trust records");
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, target_agent, overall_trust, domain_trust, evidence, last_updated
             FROM agent_trust WHERE agent_id = ?1",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![agent_id], |row| {
            Ok(TrustRow {
                agent_id: row.get(0)?,
                target_agent: row.get(1)?,
                overall_trust: row.get(2)?,
                domain_trust: row.get(3)?,
                evidence: row.get(4)?,
                last_updated: row.get(5)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

// ── Delta Queue ─────────────────────────────────────────────────────────────

/// Enqueue a delta for a target agent.
pub fn enqueue_delta(
    conn: &Connection,
    source_agent: &str,
    target_agent: &str,
    memory_id: &str,
    delta_json: &str,
    vector_clock_json: &str,
    created_at: &str,
) -> CortexResult<()> {
    debug!(target_agent, memory_id, "enqueuing delta");
    conn.execute(
        "INSERT INTO delta_queue (source_agent, target_agent, memory_id, delta_json, vector_clock, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![source_agent, target_agent, memory_id, delta_json, vector_clock_json, created_at],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Dequeue pending deltas for a target agent (up to limit).
pub fn dequeue_deltas(conn: &Connection, target_agent: &str, limit: usize) -> CortexResult<Vec<DeltaRow>> {
    debug!(target_agent, limit, "dequeuing deltas");
    let mut stmt = conn
        .prepare(
            "SELECT delta_id, source_agent, target_agent, memory_id, delta_json, vector_clock, created_at
             FROM delta_queue WHERE target_agent = ?1 AND applied = 0
             ORDER BY created_at ASC LIMIT ?2",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![target_agent, limit as i64], |row| {
            Ok(DeltaRow {
                delta_id: row.get(0)?,
                source_agent: row.get(1)?,
                target_agent: row.get(2)?,
                memory_id: row.get(3)?,
                delta_json: row.get(4)?,
                vector_clock: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Mark deltas as applied.
pub fn mark_deltas_applied(conn: &Connection, delta_ids: &[i64], applied_at: &str) -> CortexResult<()> {
    debug!(count = delta_ids.len(), "marking deltas applied");
    for id in delta_ids {
        conn.execute(
            "UPDATE delta_queue SET applied = 1, applied_at = ?2 WHERE delta_id = ?1",
            params![id, applied_at],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    }
    Ok(())
}

/// Count pending deltas for a target agent.
pub fn pending_delta_count(conn: &Connection, target_agent: &str) -> CortexResult<usize> {
    debug!(target_agent, "counting pending deltas");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM delta_queue WHERE target_agent = ?1 AND applied = 0",
            params![target_agent],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(count as usize)
}

/// Purge applied deltas older than the given timestamp.
pub fn purge_applied_deltas(conn: &Connection, older_than: &str) -> CortexResult<usize> {
    debug!(older_than, "purging applied deltas");
    let count = conn
        .execute(
            "DELETE FROM delta_queue WHERE applied = 1 AND applied_at < ?1",
            params![older_than],
        )
        .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(count)
}

// ── Peer Clocks ─────────────────────────────────────────────────────────────

/// Ensure the peer_clocks table exists (idempotent).
pub fn ensure_peer_clocks_table(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS peer_clocks (
            agent_id TEXT NOT NULL,
            peer_agent TEXT NOT NULL,
            vector_clock_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, peer_agent)
        )",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Upsert a peer's vector clock after sync acknowledgment.
pub fn upsert_peer_clock(
    conn: &Connection,
    agent_id: &str,
    peer_agent: &str,
    vector_clock_json: &str,
    updated_at: &str,
) -> CortexResult<()> {
    debug!(agent_id, peer_agent, "upserting peer clock");
    ensure_peer_clocks_table(conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO peer_clocks (agent_id, peer_agent, vector_clock_json, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![agent_id, peer_agent, vector_clock_json, updated_at],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Get a peer's last-known vector clock.
pub fn get_peer_clock(
    conn: &Connection,
    agent_id: &str,
    peer_agent: &str,
) -> CortexResult<Option<PeerClockRow>> {
    debug!(agent_id, peer_agent, "getting peer clock");
    ensure_peer_clocks_table(conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, peer_agent, vector_clock_json, updated_at
             FROM peer_clocks WHERE agent_id = ?1 AND peer_agent = ?2",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let result = stmt
        .query_row(params![agent_id, peer_agent], |row| {
            Ok(PeerClockRow {
                agent_id: row.get(0)?,
                peer_agent: row.get(1)?,
                vector_clock_json: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .optional()
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(result)
}

// ── Memory namespace/agent queries ──────────────────────────────────────────

/// Get memories by namespace.
pub fn get_memories_by_namespace(conn: &Connection, namespace_id: &str) -> CortexResult<Vec<String>> {
    debug!(namespace_id, "getting memories by namespace");
    let mut stmt = conn
        .prepare("SELECT id FROM memories WHERE namespace_id = ?1 AND archived = 0")
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![namespace_id], |row| row.get::<_, String>(0))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Get memories by source agent.
pub fn get_memories_by_agent(conn: &Connection, agent_id: &str) -> CortexResult<Vec<String>> {
    debug!(agent_id, "getting memories by agent");
    let mut stmt = conn
        .prepare("SELECT id FROM memories WHERE source_agent = ?1 AND archived = 0")
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map(params![agent_id], |row| row.get::<_, String>(0))
        .map_err(|e| to_storage_err(e.to_string()))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| to_storage_err(e.to_string()))?);
    }
    Ok(results)
}

/// Update a memory's namespace_id.
pub fn update_memory_namespace(conn: &Connection, memory_id: &str, namespace_id: &str) -> CortexResult<()> {
    debug!(memory_id, namespace_id, "updating memory namespace");
    conn.execute(
        "UPDATE memories SET namespace_id = ?2 WHERE id = ?1",
        params![memory_id, namespace_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

/// Archive a memory (set archived = 1).
pub fn archive_memory(conn: &Connection, memory_id: &str) -> CortexResult<()> {
    debug!(memory_id, "archiving memory");
    conn.execute(
        "UPDATE memories SET archived = 1 WHERE id = ?1",
        params![memory_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

// ── Row types ───────────────────────────────────────────────────────────────

/// Raw row from agent_registry.
#[derive(Debug, Clone)]
pub struct AgentRow {
    pub agent_id: String,
    pub name: String,
    pub namespace_id: String,
    pub capabilities: Option<String>,
    pub parent_agent: Option<String>,
    pub registered_at: String,
    pub last_active: String,
    pub status: String,
}

/// Raw row from memory_namespaces.
#[derive(Debug, Clone)]
pub struct NamespaceRow {
    pub namespace_id: String,
    pub scope: String,
    pub owner_agent: Option<String>,
    pub created_at: String,
    pub metadata: Option<String>,
}

/// Raw row from memory_projections.
#[derive(Debug, Clone)]
pub struct ProjectionRow {
    pub projection_id: String,
    pub source_namespace: String,
    pub target_namespace: String,
    pub filter_json: String,
    pub compression_level: i32,
    pub live: bool,
    pub created_at: String,
    pub created_by: String,
}

/// Raw row from provenance_log.
#[derive(Debug, Clone)]
pub struct ProvenanceRow {
    pub memory_id: String,
    pub hop_index: i32,
    pub agent_id: String,
    pub action: String,
    pub timestamp: String,
    pub confidence_delta: f64,
    pub details: Option<String>,
}

/// Raw row from agent_trust.
#[derive(Debug, Clone)]
pub struct TrustRow {
    pub agent_id: String,
    pub target_agent: String,
    pub overall_trust: f64,
    pub domain_trust: Option<String>,
    pub evidence: String,
    pub last_updated: String,
}

/// Raw row from delta_queue.
#[derive(Debug, Clone)]
pub struct DeltaRow {
    pub delta_id: i64,
    pub source_agent: String,
    pub target_agent: String,
    pub memory_id: String,
    pub delta_json: String,
    pub vector_clock: String,
    pub created_at: String,
}

/// Raw row from peer_clocks.
#[derive(Debug, Clone)]
pub struct PeerClockRow {
    pub agent_id: String,
    pub peer_agent: String,
    pub vector_clock_json: String,
    pub updated_at: String,
}

/// Helper trait for optional query results.
trait OptionalRow<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalRow<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
