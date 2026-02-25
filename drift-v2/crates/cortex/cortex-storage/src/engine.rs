//! StorageEngine — owns ConnectionPool, implements IMemoryStorage + ICausalStorage,
//! startup pragma configuration, shutdown cleanup.

use std::path::Path;

use chrono::{DateTime, Utc};

use cortex_core::errors::CortexResult;
use cortex_core::memory::{
    BaseMemory, ConstraintLink, FileLink, FunctionLink, Importance, MemoryType, PatternLink,
    RelationshipEdge, RelationshipType,
};
use cortex_core::models::{AuditActor, AuditOperation};
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage, IMemoryStorage};

use crate::audit::AuditLogger;
use crate::migrations;
use crate::pool::ConnectionPool;
use crate::versioning::VersionTracker;

/// The main storage engine. Owns the connection pool and provides
/// the full IMemoryStorage + ICausalStorage interface.
pub struct StorageEngine {
    pool: ConnectionPool,
    /// When true, use the read pool for read operations (file-backed mode).
    /// When false, route all reads through the writer (in-memory mode,
    /// because in-memory read pool connections are isolated databases).
    use_read_pool: bool,
}

impl StorageEngine {
    /// Open a storage engine backed by a file on disk.
    pub fn open(path: &Path) -> CortexResult<Self> {
        let pool = ConnectionPool::open(path, 4)?;
        let engine = Self { pool, use_read_pool: true };
        engine.initialize()?;
        Ok(engine)
    }

    /// Open an in-memory storage engine (for testing).
    /// Routes all reads through the writer since in-memory read pool
    /// connections are isolated databases that can't see writer's changes.
    pub fn open_in_memory() -> CortexResult<Self> {
        let pool = ConnectionPool::open_in_memory(1)?;
        let engine = Self { pool, use_read_pool: false };
        engine.initialize()?;
        Ok(engine)
    }

    /// Open with a temp file (for integration tests that need read/write separation).
    pub fn open_temp(path: &Path) -> CortexResult<Self> {
        Self::open(path)
    }

    /// Run migrations and verify pragmas.
    fn initialize(&self) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            migrations::run_migrations(conn)?;
            Ok(())
        })
    }

    /// Get a reference to the connection pool (for advanced operations).
    pub fn pool(&self) -> &ConnectionPool {
        &self.pool
    }

    /// Execute a read-only query on the best available connection.
    /// File-backed: uses the read pool (no writer contention).
    /// In-memory: uses the writer (read pool is isolated).
    fn with_reader<F, T>(&self, f: F) -> CortexResult<T>
    where
        F: FnOnce(&rusqlite::Connection) -> CortexResult<T>,
    {
        if self.use_read_pool {
            self.pool.readers.with_conn(f)
        } else {
            self.pool.writer.with_conn_sync(f)
        }
    }
}

impl IMemoryStorage for StorageEngine {
    fn create(&self, memory: &BaseMemory) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::memory_crud::insert_memory(conn, memory)?;
            AuditLogger::log_create(conn, &memory.id, AuditActor::System)?;
            Ok(())
        })
    }

    fn get(&self, id: &str) -> CortexResult<Option<BaseMemory>> {
        self.with_reader(|conn| crate::queries::memory_crud::get_memory(conn, id))
    }

    fn update(&self, memory: &BaseMemory) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            // Snapshot current version before updating.
            if let Some(existing) = crate::queries::memory_crud::get_memory(conn, &memory.id)? {
                VersionTracker::snapshot(conn, &existing, "system", "update")?;
            }
            crate::queries::memory_crud::update_memory(conn, memory)?;
            AuditLogger::log_update(conn, &memory.id, AuditActor::System, "update")?;
            Ok(())
        })
    }

    fn delete(&self, id: &str) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::memory_crud::delete_memory(conn, id)?;
            AuditLogger::log(
                conn,
                id,
                AuditOperation::Archive,
                AuditActor::System,
                serde_json::json!({"action": "delete"}),
            )?;
            Ok(())
        })
    }

    fn create_bulk(&self, memories: &[BaseMemory]) -> CortexResult<usize> {
        self.pool
            .writer
            .with_conn_sync(|conn| crate::queries::memory_crud::bulk_insert(conn, memories))
    }

    fn get_bulk(&self, ids: &[String]) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| crate::queries::memory_crud::bulk_get(conn, ids))
    }

    fn query_by_type(&self, memory_type: MemoryType) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| crate::queries::memory_query::query_by_type(conn, memory_type, None))
    }

    fn query_by_importance(&self, min: Importance) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| crate::queries::memory_query::query_by_importance(conn, min, None))
    }

    fn query_by_confidence_range(&self, min: f64, max: f64) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| {
            crate::queries::memory_query::query_by_confidence_range(conn, min, max, None)
        })
    }

    fn query_by_date_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| {
            crate::queries::memory_query::query_by_date_range(conn, from, to, None)
        })
    }

    fn query_by_tags(&self, tags: &[String]) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| crate::queries::memory_query::query_by_tags(conn, tags, None))
    }

    fn search_fts5(&self, query: &str, limit: usize) -> CortexResult<Vec<BaseMemory>> {
        self.with_reader(|conn| crate::queries::memory_search::search_fts5(conn, query, limit))
    }

    fn search_vector(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> CortexResult<Vec<(BaseMemory, f64)>> {
        self.with_reader(|conn| {
            crate::queries::vector_search::search_vector(conn, embedding, limit)
        })
    }

    fn get_relationships(
        &self,
        memory_id: &str,
        rel_type: Option<RelationshipType>,
    ) -> CortexResult<Vec<RelationshipEdge>> {
        self.with_reader(|conn| {
            crate::queries::relationship_ops::get_relationships(conn, memory_id, rel_type)
        })
    }

    fn add_relationship(&self, edge: &RelationshipEdge) -> CortexResult<()> {
        self.pool
            .writer
            .with_conn_sync(|conn| crate::queries::relationship_ops::add_relationship(conn, edge))
    }

    fn remove_relationship(&self, source_id: &str, target_id: &str) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::relationship_ops::remove_relationship(conn, source_id, target_id)
        })
    }

    fn add_pattern_link(&self, memory_id: &str, link: &PatternLink) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::link_ops::add_pattern_link(conn, memory_id, link)
        })
    }

    fn add_constraint_link(&self, memory_id: &str, link: &ConstraintLink) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::link_ops::add_constraint_link(conn, memory_id, link)
        })
    }

    fn add_file_link(&self, memory_id: &str, link: &FileLink) -> CortexResult<()> {
        self.pool
            .writer
            .with_conn_sync(|conn| crate::queries::link_ops::add_file_link(conn, memory_id, link))
    }

    fn add_function_link(&self, memory_id: &str, link: &FunctionLink) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::link_ops::add_function_link(conn, memory_id, link)
        })
    }

    fn count_by_type(&self) -> CortexResult<Vec<(MemoryType, usize)>> {
        self.with_reader(crate::queries::aggregation::count_by_type)
    }

    fn average_confidence(&self) -> CortexResult<f64> {
        self.with_reader(crate::queries::aggregation::average_confidence)
    }

    fn stale_count(&self, threshold_days: u64) -> CortexResult<usize> {
        self.with_reader(|conn| crate::queries::aggregation::stale_count(conn, threshold_days))
    }

    fn vacuum(&self) -> CortexResult<()> {
        self.pool
            .writer
            .with_conn_sync(crate::queries::maintenance::full_vacuum)
    }
}

impl ICausalStorage for StorageEngine {
    fn add_edge(&self, edge: &CausalEdge) -> CortexResult<()> {
        self.pool
            .writer
            .with_conn_sync(|conn| crate::queries::causal_ops::add_edge(conn, edge))
    }

    fn get_edges(&self, node_id: &str) -> CortexResult<Vec<CausalEdge>> {
        self.with_reader(|conn| crate::queries::causal_ops::get_edges(conn, node_id))
    }

    fn remove_edge(&self, source_id: &str, target_id: &str) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::causal_ops::remove_edge(conn, source_id, target_id)
        })
    }

    fn update_strength(&self, source_id: &str, target_id: &str, strength: f64) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::causal_ops::update_strength(conn, source_id, target_id, strength)
        })
    }

    fn add_evidence(
        &self,
        source_id: &str,
        target_id: &str,
        evidence: &CausalEvidence,
    ) -> CortexResult<()> {
        self.pool.writer.with_conn_sync(|conn| {
            crate::queries::causal_ops::add_evidence(conn, source_id, target_id, evidence)
        })
    }

    fn has_cycle(&self, source_id: &str, target_id: &str) -> CortexResult<bool> {
        self.with_reader(|conn| {
            crate::queries::causal_ops::has_cycle(conn, source_id, target_id)
        })
    }

    fn list_all_node_ids(&self) -> CortexResult<Vec<String>> {
        self.with_reader(crate::queries::causal_ops::list_all_node_ids)
    }

    fn edge_count(&self) -> CortexResult<usize> {
        self.with_reader(crate::queries::causal_ops::edge_count)
    }

    fn node_count(&self) -> CortexResult<usize> {
        self.with_reader(crate::queries::causal_ops::node_count)
    }

    fn remove_orphaned_edges(&self) -> CortexResult<usize> {
        self.pool
            .writer
            .with_conn_sync(crate::queries::causal_ops::remove_orphaned_edges)
    }
}
