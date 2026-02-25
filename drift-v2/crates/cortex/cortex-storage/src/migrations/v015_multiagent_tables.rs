//! v015: Multi-agent memory tables — agent registry, namespaces, permissions,
//! projections, provenance, trust, delta queue, and memory table extensions.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Run the v015 migration: create multi-agent tables and extend the memories table.
pub fn migrate(conn: &Connection) -> CortexResult<()> {
    tracing::info!("v015: creating multi-agent memory tables");

    conn.execute_batch(
        "
        -- Agent identity store
        CREATE TABLE IF NOT EXISTS agent_registry (
            agent_id      TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            namespace_id  TEXT NOT NULL,
            capabilities  TEXT,
            parent_agent  TEXT,
            registered_at TEXT NOT NULL,
            last_active   TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'active',
            FOREIGN KEY (parent_agent) REFERENCES agent_registry(agent_id)
        );

        CREATE INDEX IF NOT EXISTS idx_agent_status ON agent_registry(status);
        CREATE INDEX IF NOT EXISTS idx_agent_parent ON agent_registry(parent_agent);

        -- Namespace metadata
        CREATE TABLE IF NOT EXISTS memory_namespaces (
            namespace_id TEXT PRIMARY KEY,
            scope        TEXT NOT NULL,
            owner_agent  TEXT,
            created_at   TEXT NOT NULL,
            metadata     TEXT,
            FOREIGN KEY (owner_agent) REFERENCES agent_registry(agent_id)
        );

        -- Namespace ACL entries
        CREATE TABLE IF NOT EXISTS namespace_permissions (
            namespace_id TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            permissions  TEXT NOT NULL,
            granted_at   TEXT NOT NULL,
            granted_by   TEXT NOT NULL,
            PRIMARY KEY (namespace_id, agent_id),
            FOREIGN KEY (namespace_id) REFERENCES memory_namespaces(namespace_id),
            FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id)
        );

        -- Projection definitions
        CREATE TABLE IF NOT EXISTS memory_projections (
            projection_id    TEXT PRIMARY KEY,
            source_namespace TEXT NOT NULL,
            target_namespace TEXT NOT NULL,
            filter_json      TEXT NOT NULL,
            compression_level INTEGER NOT NULL DEFAULT 0,
            live             INTEGER NOT NULL DEFAULT 0,
            created_at       TEXT NOT NULL,
            created_by       TEXT NOT NULL,
            FOREIGN KEY (source_namespace) REFERENCES memory_namespaces(namespace_id),
            FOREIGN KEY (target_namespace) REFERENCES memory_namespaces(namespace_id),
            FOREIGN KEY (created_by) REFERENCES agent_registry(agent_id)
        );

        CREATE INDEX IF NOT EXISTS idx_proj_source ON memory_projections(source_namespace);
        CREATE INDEX IF NOT EXISTS idx_proj_target ON memory_projections(target_namespace);

        -- Append-only provenance chain
        CREATE TABLE IF NOT EXISTS provenance_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id        TEXT NOT NULL,
            hop_index        INTEGER NOT NULL,
            agent_id         TEXT NOT NULL,
            action           TEXT NOT NULL,
            timestamp        TEXT NOT NULL,
            confidence_delta REAL DEFAULT 0.0,
            details          TEXT,
            FOREIGN KEY (memory_id) REFERENCES memories(id),
            FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id)
        );

        CREATE INDEX IF NOT EXISTS idx_prov_memory ON provenance_log(memory_id, hop_index);
        CREATE INDEX IF NOT EXISTS idx_prov_agent ON provenance_log(agent_id);

        -- Per-agent trust scores
        CREATE TABLE IF NOT EXISTS agent_trust (
            agent_id      TEXT NOT NULL,
            target_agent  TEXT NOT NULL,
            overall_trust REAL NOT NULL DEFAULT 0.5,
            domain_trust  TEXT,
            evidence      TEXT NOT NULL,
            last_updated  TEXT NOT NULL,
            PRIMARY KEY (agent_id, target_agent),
            FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id),
            FOREIGN KEY (target_agent) REFERENCES agent_registry(agent_id)
        );

        -- Persistent delta queue for CRDT sync
        CREATE TABLE IF NOT EXISTS delta_queue (
            delta_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            source_agent TEXT NOT NULL,
            target_agent TEXT NOT NULL,
            memory_id    TEXT NOT NULL,
            delta_json   TEXT NOT NULL,
            vector_clock TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            applied      INTEGER NOT NULL DEFAULT 0,
            applied_at   TEXT,
            FOREIGN KEY (source_agent) REFERENCES agent_registry(agent_id),
            FOREIGN KEY (target_agent) REFERENCES agent_registry(agent_id)
        );

        CREATE INDEX IF NOT EXISTS idx_delta_target ON delta_queue(target_agent, applied);
        CREATE INDEX IF NOT EXISTS idx_delta_created ON delta_queue(created_at);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // ALTER TABLE for existing memories — add namespace and source_agent columns.
    // SQLite doesn't support IF NOT EXISTS for ALTER TABLE, so we check first.
    add_column_if_missing(conn, "memories", "namespace_id", "TEXT DEFAULT 'agent://default/'")?;
    add_column_if_missing(conn, "memories", "source_agent", "TEXT DEFAULT 'default'")?;

    // Indexes on the new columns.
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_memories_namespace ON memories(namespace_id);
        CREATE INDEX IF NOT EXISTS idx_memories_source_agent ON memories(source_agent);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    tracing::info!("v015: multi-agent tables created successfully");
    Ok(())
}

/// Add a column to a table if it doesn't already exist.
fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> CortexResult<()> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| to_storage_err(e.to_string()))?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| to_storage_err(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    if !columns.iter().any(|c| c == column) {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"))
            .map_err(|e| to_storage_err(e.to_string()))?;
        tracing::debug!("v015: added column {table}.{column}");
    }
    Ok(())
}
