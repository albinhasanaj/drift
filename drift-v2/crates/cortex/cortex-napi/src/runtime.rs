//! CortexRuntime — owns all engines, background task scheduler, graceful shutdown.
//!
//! The runtime is a singleton stored behind `OnceLock`. It's initialized once
//! via `initialize()` and accessed via `get()` for the lifetime of the process.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use cortex_causal::CausalEngine;
use cortex_cloud::CloudEngine;
use cortex_compression::CompressionEngine;
use cortex_consolidation::ConsolidationEngine;
use cortex_core::config::CortexConfig;
use cortex_core::errors::CortexResult;
use cortex_decay::DecayEngine;
use cortex_embeddings::EmbeddingEngine;
use cortex_learning::LearningEngine;
use cortex_multiagent::MultiAgentEngine;
use cortex_observability::ObservabilityEngine;
use cortex_prediction::PredictionEngine;
use cortex_privacy::PrivacyEngine;
use cortex_session::SessionManager;
use cortex_storage::StorageEngine;
use cortex_temporal::TemporalEngine;
use cortex_validation::ValidationEngine;

use crate::conversions::error_types;

/// Global singleton.
static RUNTIME: OnceLock<Arc<CortexRuntime>> = OnceLock::new();

/// The central runtime owning all Cortex engines.
///
/// Engines that require `&mut self` are wrapped in `Mutex` to allow
/// safe concurrent access from async NAPI callbacks.
pub struct CortexRuntime {
    pub storage: Arc<StorageEngine>,
    pub embeddings: Mutex<EmbeddingEngine>,
    pub compression: CompressionEngine,
    pub causal: CausalEngine,
    pub decay: DecayEngine,
    pub validation: ValidationEngine,
    pub learning: Mutex<LearningEngine>,
    pub consolidation: Mutex<ConsolidationEngine>,
    pub prediction: PredictionEngine<Arc<StorageEngine>>,
    pub session: SessionManager,
    pub privacy: PrivacyEngine,
    pub observability: Mutex<ObservabilityEngine>,
    pub cloud: Option<Mutex<CloudEngine>>,
    pub temporal: TemporalEngine,
    pub multiagent: Mutex<MultiAgentEngine>,
    pub config: CortexConfig,
}

/// Options for initializing the runtime.
#[derive(Default)]
pub struct RuntimeOptions {
    /// Path to the SQLite database. If None, uses in-memory.
    pub db_path: Option<PathBuf>,
    /// TOML configuration string. If None, uses defaults.
    pub config_toml: Option<String>,
    /// Whether to enable cloud sync.
    pub cloud_enabled: bool,
}

impl CortexRuntime {
    /// Create a new runtime with the given options.
    fn new(opts: RuntimeOptions) -> CortexResult<Self> {
        let config = match &opts.config_toml {
            Some(toml_str) => CortexConfig::from_toml(toml_str)
                .map_err(|e| cortex_core::CortexError::ConfigError(e.to_string()))?,
            None => CortexConfig::default(),
        };

        // Storage — wrapped in Arc for sharing with learning/consolidation engines
        let storage = Arc::new(match &opts.db_path {
            Some(path) => StorageEngine::open(path)?,
            None => StorageEngine::open_in_memory()?,
        });
        // Create a trait-object Arc for engines that need IMemoryStorage
        let storage_trait: Arc<dyn cortex_core::traits::IMemoryStorage> = storage.clone();

        // Embeddings — D-01: use persistent L2 cache when file-backed.
        let embeddings = match storage.pool().db_path.as_ref() {
            Some(db_path) => EmbeddingEngine::new_with_db_path(config.embedding.clone(), db_path),
            None => EmbeddingEngine::new(config.embedding.clone()),
        };

        // Compression
        let compression = CompressionEngine::new();

        // Causal — hydrate graph from storage (C-04)
        let causal = CausalEngine::new();
        let _ = causal.hydrate(storage.as_ref());

        // Decay
        let decay = DecayEngine::new();

        // Validation
        let validation = ValidationEngine::default();

        // Learning — wired to shared storage for persistence
        let mut learning = LearningEngine::with_storage(storage_trait.clone());
        // Pre-populate existing memories for dedup.
        let _ = learning.refresh_existing_memories();

        // Consolidation — B-03: shares the main EmbeddingEngine via clone instead of
        // creating a duplicate. The main engine's cache and provider chain are reused.
        let consolidation_embedder = embeddings.clone_provider();
        let consolidation =
            ConsolidationEngine::new(consolidation_embedder)
                .with_storage(storage_trait.clone());

        // Prediction — shares the same Arc<StorageEngine> (B-01: no duplicate pool)
        let prediction = PredictionEngine::new(storage.clone());

        // Session
        let session = SessionManager::new();

        // Privacy
        let privacy = PrivacyEngine::new();

        // Observability
        let observability = ObservabilityEngine::new();

        // Cloud (optional) — C-09: read API key from env, not hardcoded empty string.
        let cloud = if opts.cloud_enabled {
            let api_key = std::env::var("CORTEX_CLOUD_API_KEY").unwrap_or_default();
            if api_key.is_empty() {
                tracing::warn!("Cloud enabled but CORTEX_CLOUD_API_KEY is empty — cloud sync will fail");
            }
            Some(Mutex::new(CloudEngine::new(
                cortex_cloud::auth::login_flow::AuthMethod::ApiKey(api_key),
                cortex_cloud::HttpClientConfig::default(),
                cortex_cloud::QuotaLimits::default(),
            )))
        } else {
            None
        };

        // Temporal — shares writer+readers from storage pool (B-02: no duplicate connections)
        let temporal = TemporalEngine::new(
            storage.pool().writer.clone(),
            storage.pool().readers.clone(),
            config.temporal.clone(),
        );

        // Multi-agent — shares writer+readers from storage pool (B-04: no per-call connections)
        let mut multiagent = MultiAgentEngine::new(
            storage.pool().writer.clone(),
            storage.pool().readers.clone(),
            config.multiagent.clone(),
        );
        // In-memory mode: readers are isolated DBs, route reads through writer
        if storage.pool().db_path.is_none() {
            multiagent = multiagent.with_read_pool_disabled();
        }
        // A-01: Wire embedding provider for consensus detection.
        multiagent.set_embedding_provider(embeddings.clone_provider());
        // A-01: Wire storage for querying memories by namespace.
        multiagent.set_storage(storage_trait.clone());

        Ok(Self {
            storage,
            embeddings: Mutex::new(embeddings),
            compression,
            causal,
            decay,
            validation,
            learning: Mutex::new(learning),
            consolidation: Mutex::new(consolidation),
            prediction,
            session,
            privacy,
            observability: Mutex::new(observability),
            cloud,
            temporal,
            multiagent: Mutex::new(multiagent),
            config,
        })
    }
}

/// Initialize the global CortexRuntime singleton.
///
/// Returns an error if already initialized or if initialization fails.
pub fn initialize(opts: RuntimeOptions) -> napi::Result<()> {
    let runtime = CortexRuntime::new(opts).map_err(error_types::to_napi_error)?;
    RUNTIME
        .set(Arc::new(runtime))
        .map_err(|_| napi::Error::from_reason("CortexRuntime already initialized"))
}

/// Get a reference to the global CortexRuntime.
///
/// Returns an error if not yet initialized.
pub fn get() -> napi::Result<Arc<CortexRuntime>> {
    RUNTIME
        .get()
        .cloned()
        .ok_or_else(error_types::runtime_not_initialized)
}

/// Check if the runtime has been initialized.
pub fn is_initialized() -> bool {
    RUNTIME.get().is_some()
}
