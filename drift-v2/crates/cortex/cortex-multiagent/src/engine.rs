//! MultiAgentEngine — implements `IMultiAgentEngine`, orchestrates all submodules.

use std::collections::HashMap;
use std::sync::Arc;

use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::agent::{AgentId, AgentRegistration, AgentStatus};
use cortex_core::models::cross_agent::AgentTrust;
use cortex_core::models::namespace::{MemoryProjection, NamespaceId, NamespacePermission};
use cortex_core::models::provenance::ProvenanceRecord;
use cortex_core::traits::{IEmbeddingProvider, IMemoryStorage, IMultiAgentEngine};

use cortex_storage::pool::{ReadPool, WriteConnection};

use crate::consolidation::ConsensusDetector;
use crate::namespace::NamespaceManager;
use crate::namespace::permissions::NamespacePermissionManager;
use crate::projection::ProjectionEngine;
use crate::registry::AgentRegistry;
use crate::share;

/// The main multi-agent engine. Orchestrates registry, namespace, projection,
/// and share operations. Holds references to the storage layer.
pub struct MultiAgentEngine {
    writer: Arc<WriteConnection>,
    readers: Arc<ReadPool>,
    config: MultiAgentConfig,
    /// When true, use the read pool for read operations (file-backed mode).
    /// When false, route all reads through the writer (in-memory mode,
    /// because in-memory read pool connections are isolated databases).
    use_read_pool: bool,
    /// Optional embedding provider for consensus detection similarity.
    embedding_provider: Option<Box<dyn IEmbeddingProvider>>,
    /// Optional storage for querying memories by namespace.
    storage: Option<Arc<dyn IMemoryStorage>>,
}

impl MultiAgentEngine {
    /// Create a new MultiAgentEngine with the given storage connections and config.
    pub fn new(
        writer: Arc<WriteConnection>,
        readers: Arc<ReadPool>,
        config: MultiAgentConfig,
    ) -> Self {
        Self {
            writer,
            readers,
            config,
            use_read_pool: true,
            embedding_provider: None,
            storage: None,
        }
    }

    /// Disable the read pool (for in-memory mode where readers are isolated).
    /// When disabled, all reads are routed through the writer connection.
    pub fn with_read_pool_disabled(mut self) -> Self {
        self.use_read_pool = false;
        self
    }

    /// Execute a read-only query on the best available connection.
    /// File-backed: uses the read pool (no writer contention).
    /// In-memory: uses the writer (read pool is isolated).
    async fn with_reader<F, T>(&self, f: F) -> CortexResult<T>
    where
        F: FnOnce(&rusqlite::Connection) -> CortexResult<T>,
    {
        if self.use_read_pool {
            self.readers.with_conn(f)
        } else {
            self.writer.with_conn(f).await
        }
    }

    /// Set an embedding provider for consensus detection.
    pub fn set_embedding_provider(&mut self, provider: Box<dyn IEmbeddingProvider>) {
        self.embedding_provider = Some(provider);
    }

    /// Set storage for querying memories by namespace.
    pub fn set_storage(&mut self, storage: Arc<dyn IMemoryStorage>) {
        self.storage = Some(storage);
    }

    /// Get the config.
    pub fn config(&self) -> &MultiAgentConfig {
        &self.config
    }
}

impl MultiAgentEngine {
    /// B-07: Sync with real result counts returned.
    /// The trait `sync_with` returns `()`, so this method provides the counts
    /// for NAPI callers that need them.
    pub async fn sync_with_counts(
        &self,
        source_agent: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<crate::sync::protocol::SyncResult> {
        let src = source_agent.clone();
        let tgt = target_agent.clone();
        self.writer
            .with_conn(move |conn| {
                let mut clock = cortex_crdt::VectorClock::new();
                crate::sync::DeltaSyncEngine::initiate_sync(conn, &src, &tgt, &mut clock)
            })
            .await
    }
}

impl IMultiAgentEngine for MultiAgentEngine {
    async fn register_agent(
        &self,
        name: &str,
        capabilities: Vec<String>,
    ) -> CortexResult<AgentRegistration> {
        self.writer
            .with_conn(|conn| AgentRegistry::register(conn, name, capabilities.clone()))
            .await
    }

    async fn deregister_agent(&self, agent_id: &AgentId) -> CortexResult<()> {
        let id = agent_id.clone();
        self.writer
            .with_conn(move |conn| AgentRegistry::deregister(conn, &id))
            .await
    }

    async fn get_agent(
        &self,
        agent_id: &AgentId,
    ) -> CortexResult<Option<AgentRegistration>> {
        let id = agent_id.clone();
        // A-04: Route reads through readers pool (or writer in in-memory mode).
        self.with_reader(move |conn| AgentRegistry::get_agent(conn, &id)).await
    }

    async fn list_agents(
        &self,
        filter: Option<AgentStatus>,
    ) -> CortexResult<Vec<AgentRegistration>> {
        // A-04: Route reads through readers pool (or writer in in-memory mode).
        self.with_reader(move |conn| AgentRegistry::list_agents(conn, filter.as_ref())).await
    }

    async fn create_namespace(
        &self,
        namespace: NamespaceId,
        owner: &AgentId,
    ) -> CortexResult<NamespaceId> {
        let ns = namespace.clone();
        let own = owner.clone();
        self.writer
            .with_conn(move |conn| NamespaceManager::create_namespace(conn, &ns, &own))
            .await
    }

    async fn check_permission(
        &self,
        namespace: &NamespaceId,
        agent_id: &AgentId,
        permission: NamespacePermission,
    ) -> CortexResult<bool> {
        let ns = namespace.clone();
        let aid = agent_id.clone();
        // A-04: Route reads through readers pool (or writer in in-memory mode).
        self.with_reader(move |conn| NamespacePermissionManager::check(conn, &ns, &aid, permission)).await
    }

    async fn share_memory(
        &self,
        memory_id: &str,
        target_namespace: &NamespaceId,
        agent_id: &AgentId,
    ) -> CortexResult<()> {
        let mid = memory_id.to_string();
        let ns = target_namespace.clone();
        let aid = agent_id.clone();
        self.writer
            .with_conn(move |conn| share::actions::share(conn, &mid, &ns, &aid))
            .await
    }

    async fn create_projection(
        &self,
        projection: MemoryProjection,
    ) -> CortexResult<String> {
        let proj = projection.clone();
        self.writer
            .with_conn(move |conn| ProjectionEngine::create_projection(conn, &proj))
            .await
    }

    // ── Phase C: Provenance, Trust, Sync ───────────────────────────────

    async fn sync_with(
        &self,
        source_agent: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<()> {
        self.sync_with_counts(source_agent, target_agent).await?;
        Ok(())
    }

    async fn get_provenance(
        &self,
        memory_id: &str,
    ) -> CortexResult<Option<ProvenanceRecord>> {
        let mid = memory_id.to_string();
        // A-04: Route reads through readers pool (or writer in in-memory mode).
        self.with_reader(move |conn| crate::provenance::ProvenanceTracker::get_provenance(conn, &mid)).await
    }

    async fn get_trust(
        &self,
        agent_id: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<AgentTrust> {
        let aid = agent_id.clone();
        let tgt = target_agent.clone();
        // A-04: Route reads through readers pool (or writer in in-memory mode).
        self.with_reader(move |conn| crate::trust::TrustScorer::get_trust(conn, &aid, &tgt)).await
    }

    async fn detect_consensus(
        &self,
        namespace: &NamespaceId,
    ) -> CortexResult<Vec<(Vec<String>, f64)>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        // A-01: Wire to real ConsensusDetector with embedding similarity.
        let embedding_provider = match &self.embedding_provider {
            Some(provider) => provider,
            None => return Ok(Vec::new()),
        };

        // Query memories in this namespace grouped by source_agent.
        let ns_uri = namespace.to_uri();
        let memory_ids: Vec<String> = self.with_reader(move |conn| {
            cortex_storage::queries::multiagent_ops::get_memories_by_namespace(conn, &ns_uri)
        }).await?;

        if memory_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Load full memories via storage trait.
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
        for mid in &memory_ids {
            if let Some(mem) = storage.get(mid)? {
                let agent_id = mem.source_agent.clone();
                memories_by_agent.entry(agent_id).or_default().push(mem);
            }
        }

        // Build similarity function using embedding provider.
        let similarity_fn = |a: &BaseMemory, b: &BaseMemory| -> f64 {
            let embed_a = embedding_provider.embed(&a.summary);
            let embed_b = embedding_provider.embed(&b.summary);
            match (embed_a, embed_b) {
                (Ok(va), Ok(vb)) => cosine_similarity(&va, &vb),
                _ => 0.0,
            }
        };

        let detector = ConsensusDetector::new(&self.config);
        let candidates = detector.detect_consensus(
            &memories_by_agent,
            &similarity_fn,
            self.config.consensus_similarity_threshold,
        )?;

        // Convert ConsensusCandidate → (Vec<String>, f64) as the trait expects.
        let results: Vec<(Vec<String>, f64)> = candidates
            .into_iter()
            .map(|c| {
                let memory_ids: Vec<String> = c.memories.into_iter().map(|(_, mid)| mid).collect();
                (memory_ids, c.similarity)
            })
            .collect();

        Ok(results)
    }
}

/// Compute cosine similarity between two vectors.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (x, y) in a.iter().zip(b.iter()) {
        let x = *x as f64;
        let y = *y as f64;
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom < f64::EPSILON {
        0.0
    } else {
        (dot / denom).clamp(-1.0, 1.0)
    }
}
