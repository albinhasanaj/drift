//! DriftRuntime — singleton via `OnceLock`, lock-free after initialization.
//!
//! The runtime owns the database manager, configuration, and event dispatcher.
//! It is initialized once via `initialize()` and accessed via `get()` for the
//! lifetime of the process. Scanner/parsers are stateless — no Mutex wrappers needed.
//!
//! Pattern reference: `cortex-napi/src/runtime.rs`

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use drift_core::config::DriftConfig;
use drift_core::events::dispatcher::EventDispatcher;
use drift_storage::DriftStorageEngine;

use cortex_drift_bridge::BridgeConfig;
use cortex_drift_bridge::event_mapping::{BridgeEventHandler, EventDeduplicator};
use cortex_drift_bridge::storage::engine::BridgeStorageEngine;
use cortex_drift_bridge::traits::{CortexMemoryWriter, IBridgeStorage};

use crate::conversions::error_codes;

// ─── CortexStorageWriter (P0-3) ──────────────────────────────────────────

/// Adapter from `cortex_storage::StorageEngine` to bridge's `CortexMemoryWriter`.
///
/// This is the dual-write endpoint: when cortex.db exists, bridge memories
/// are also written to cortex.db's `memories` table via cortex-storage's
/// full transactional insert (memory + links + audit).
struct CortexStorageWriter {
    engine: cortex_storage::StorageEngine,
}

impl CortexMemoryWriter for CortexStorageWriter {
    fn write_memory(
        &self,
        memory: &cortex_core::memory::BaseMemory,
    ) -> cortex_drift_bridge::errors::BridgeResult<()> {
        use cortex_core::traits::IMemoryStorage;
        self.engine.create(memory).map_err(|e| {
            cortex_drift_bridge::errors::BridgeError::StorageWrite(format!(
                "cortex.db dual-write failed: {e}"
            ))
        })
    }
}

/// Global singleton — lock-free after first `initialize()` call.
static RUNTIME: OnceLock<Arc<DriftRuntime>> = OnceLock::new();

/// The central runtime owning all Drift subsystems.
///
/// `DatabaseManager` handles its own write serialization internally
/// (`Mutex<Connection>` for writer, read pool for readers).
/// Scanner and parsers are stateless or use `thread_local!` storage,
/// so no additional Mutex wrappers are needed here.
pub struct DriftRuntime {
    pub storage: DriftStorageEngine,
    pub config: DriftConfig,
    pub dispatcher: EventDispatcher,
    pub project_root: Option<PathBuf>,
    // ─── Bridge fields (Phase C: trait-based) ───────────────────────────
    pub bridge_store: Option<Arc<BridgeStorageEngine>>,
    pub bridge_config: BridgeConfig,
    pub causal_engine: Option<cortex_causal::CausalEngine>,
    pub bridge_initialized: bool,
    /// Read-only drift.db access for bridge evidence collection.
    /// Provided by DriftStorageEngine::as_drift_reader() (Phase B).
    pub drift_db_for_bridge: Option<Mutex<rusqlite::Connection>>,
    // ─── Bridge event pipeline (Phase B) ─────────────────────────────────
    pub bridge_deduplicator: Mutex<EventDeduplicator>,
}

/// Options for initializing the runtime.
#[derive(Default)]
pub struct RuntimeOptions {
    /// Path to drift.db. If None, uses default location (.drift/drift.db).
    pub db_path: Option<PathBuf>,
    /// Path to project root for scanning.
    pub project_root: Option<PathBuf>,
    /// TOML configuration string. If None, uses defaults.
    pub config_toml: Option<String>,
    /// Path to bridge.db. If None, defaults to .drift/bridge.db (sibling of drift.db).
    pub bridge_db_path: Option<PathBuf>,
    /// Path to cortex.db. If Some and the file exists, bridge memories are
    /// dual-written to cortex.db for Cortex retrieval visibility (P0-3).
    /// When None or the file doesn't exist, bridge operates in standalone mode.
    pub cortex_db_path: Option<PathBuf>,
}

impl DriftRuntime {
    /// Get the bridge storage engine (trait-based access).
    pub fn bridge_storage(&self) -> Option<&Arc<BridgeStorageEngine>> {
        self.bridge_store.as_ref()
    }

    /// Lock the drift_db_for_bridge Mutex and return a guard.
    /// Returns None if the dedicated drift.db read connection is not available.
    pub fn lock_drift_db_for_bridge(&self) -> Option<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.drift_db_for_bridge.as_ref().and_then(|m| m.lock().ok())
    }
}

impl DriftRuntime {
    /// Create a new runtime with the given options.
    fn new(opts: RuntimeOptions) -> Result<Self, napi::Error> {
        // Resolve configuration
        let config = match &opts.config_toml {
            Some(toml_str) => DriftConfig::from_toml(toml_str).map_err(|e| {
                napi::Error::from_reason(format!("[{}] {e}", error_codes::CONFIG_ERROR))
            })?,
            None => {
                // Try loading from project root, fall back to defaults
                if let Some(ref root) = opts.project_root {
                    DriftConfig::load(root, None).unwrap_or_default()
                } else {
                    DriftConfig::default()
                }
            }
        };

        // Resolve database path
        let db_path = match &opts.db_path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "[{}] Failed to create database directory: {e}",
                            error_codes::INIT_ERROR
                        ))
                    })?;
                }
                path.clone()
            }
            None => {
                let p = opts
                    .project_root
                    .as_deref()
                    .unwrap_or_else(|| Path::new("."))
                    .join(".drift")
                    .join("drift.db");
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "[{}] Failed to create .drift directory: {e}",
                            error_codes::INIT_ERROR
                        ))
                    })?;
                }
                p
            }
        };

        // Open the unified storage engine (DatabaseManager + BatchWriter)
        let storage = DriftStorageEngine::open(&db_path).map_err(|e| {
            napi::Error::from_reason(format!(
                "[{}] {e}",
                error_codes::STORAGE_ERROR
            ))
        })?;

        let mut dispatcher = EventDispatcher::new();

        // ─── Bridge initialization (non-fatal) ─────────────────────────
        let mut bridge_db: Option<Arc<BridgeStorageEngine>> = None;
        let mut bridge_initialized = false;
        let bridge_config = BridgeConfig::default();
        let mut causal_engine = None;

        let bridge_db_path = opts.bridge_db_path.unwrap_or_else(|| {
            opts.project_root
                .as_deref()
                .unwrap_or_else(|| Path::new("."))
                .join(".drift")
                .join("bridge.db")
        });

        // Optionally open cortex.db for dual-write (P0-3).
        // When cortex_db_path is provided and the file exists, bridge memories
        // are also written to cortex.db so they are visible to Cortex retrieval.
        let cortex_writer: Option<Arc<dyn CortexMemoryWriter>> = opts
            .cortex_db_path
            .as_ref()
            .filter(|p| p.exists())
            .and_then(|cortex_path| {
                match cortex_storage::StorageEngine::open(cortex_path) {
                    Ok(engine) => {
                        tracing::info!(
                            path = %cortex_path.display(),
                            "cortex.db opened for bridge dual-write"
                        );
                        Some(Arc::new(CortexStorageWriter { engine }) as Arc<dyn CortexMemoryWriter>)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %cortex_path.display(),
                            "Failed to open cortex.db for dual-write — bridge will write to bridge.db only"
                        );
                        None
                    }
                }
            });

        match BridgeStorageEngine::open(&bridge_db_path) {
            Ok(engine) => {
                let store: Arc<BridgeStorageEngine> = Arc::new(engine);
                // Register BridgeEventHandler with the dispatcher so drift_analyze()
                // events automatically create bridge memories (BW-EVT-01).
                // When cortex_writer is available, memories are dual-written (P0-3).
                let handler = match cortex_writer {
                    Some(ref writer) => BridgeEventHandler::with_cortex_writer(
                        Some(Arc::clone(&store) as Arc<dyn IBridgeStorage>),
                        bridge_config.license_tier,
                        Arc::clone(writer),
                    ),
                    None => BridgeEventHandler::new(
                        Some(Arc::clone(&store) as Arc<dyn IBridgeStorage>),
                        bridge_config.license_tier,
                    ),
                };
                dispatcher.register(Arc::new(handler));

                bridge_db = Some(store);
                causal_engine = Some(cortex_causal::CausalEngine::new());
                bridge_initialized = true;
                tracing::info!(path = %bridge_db_path.display(), "Bridge initialized with event handler");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Bridge initialization failed — non-fatal, bridge features unavailable");
            }
        }

        // Open a dedicated read-only drift.db connection for bridge cross-DB queries
        let drift_db_for_bridge = if bridge_initialized {
            storage.path().and_then(|p| {
                match rusqlite::Connection::open_with_flags(
                    p,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                ) {
                    Ok(conn) => {
                        tracing::info!("Bridge: opened read-only drift.db connection for cross-DB queries");
                        Some(Mutex::new(conn))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Bridge: failed to open drift.db read connection — grounding will have no evidence");
                        None
                    }
                }
            })
        } else {
            None
        };

        Ok(Self {
            storage,
            config,
            dispatcher,
            project_root: opts.project_root,
            bridge_store: bridge_db,
            bridge_config,
            causal_engine,
            bridge_initialized,
            drift_db_for_bridge,
            bridge_deduplicator: Mutex::new(EventDeduplicator::new()),
        })
    }

    // init_bridge and open_bridge_for_handler removed in Phase C.
    // BridgeStorageEngine::open() handles directory creation, connection setup,
    // WAL mode, and migrations internally.
}

/// Initialize the global DriftRuntime singleton.
///
/// Returns an error if already initialized or if initialization fails.
/// After this call, `get()` is lock-free.
pub fn initialize(opts: RuntimeOptions) -> napi::Result<()> {
    let runtime = DriftRuntime::new(opts)?;
    RUNTIME.set(Arc::new(runtime)).map_err(|_| {
        napi::Error::from_reason(format!(
            "[{}] DriftRuntime already initialized",
            error_codes::ALREADY_INITIALIZED
        ))
    })
}

/// Get a reference to the global DriftRuntime.
///
/// Returns an error if not yet initialized. Lock-free after init.
pub fn get() -> napi::Result<Arc<DriftRuntime>> {
    RUNTIME.get().cloned().ok_or_else(|| {
        napi::Error::from_reason(format!(
            "[{}] DriftRuntime not initialized. Call driftInitialize() first.",
            error_codes::RUNTIME_NOT_INITIALIZED
        ))
    })
}

/// Check if the runtime has been initialized.
pub fn is_initialized() -> bool {
    RUNTIME.get().is_some()
}
