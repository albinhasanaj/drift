//! # cortex-drift-bridge
//!
//! The integration bridge between Cortex memory and Drift analysis.
//! This is the ONLY crate that imports from both systems (D4: leaf, not spine).
//!
//! ## Modules (15)
//! - `causal` — typed edge creation, counterfactual/intervention analysis, pruning, narrative
//! - `config` — BridgeConfig, GroundingConfig, EventConfig, EvidenceConfig, validation
//! - `errors` — BridgeError, ErrorContext, RecoveryAction, ErrorChain
//! - `event_mapping` — 21 event→memory mappings, dedup, memory builder
//! - `grounding` — evidence collection, scoring, contradiction, scheduling
//! - `health` — per-subsystem checks, readiness probes, degradation tracking
//! - `intents` — 10 code-specific intents, intent→data source resolver
//! - `license` — tier gating, feature matrix (25 features), usage tracking
//! - `link_translation` — Drift PatternLink → Cortex EntityLink (5 constructors)
//! - `napi` — 20 NAPI-ready bridge functions
//! - `query` — ATTACH lifecycle, drift queries, cortex queries, cross-DB ops
//! - `specification` — corrections, adaptive weights with decay/bounds, narrative
//! - `storage` — SQLite PRAGMAs, migrations, schema, retention, tables
//! - `tools` — 6 MCP tools (why, learn, grounding_check, counterfactual, intervention, health)
//! - `types` — shared data structures (GroundingResult, GroundingVerdict, etc.)

pub mod causal;
pub mod config;
pub mod errors;
pub mod event_mapping;
pub mod grounding;
pub mod health;
pub mod intents;
pub mod license;
pub mod link_translation;
pub mod napi;
pub mod query;
pub mod specification;
pub mod storage;
pub mod tools;
pub mod traits;
pub mod types;

// Re-export BridgeConfig at crate root for backward compatibility.
pub use config::BridgeConfig;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing::{info, warn};

/// The main bridge runtime. Manages connections to both drift.db and cortex.db.
pub struct BridgeRuntime {
    /// Connection to drift.db (read-only via ATTACH or direct).
    #[deprecated(note = "Use BridgeStorageEngine instead — Phase C cloud migration")]
    drift_db: Option<Mutex<rusqlite::Connection>>,
    /// Connection to cortex.db (read/write for memory creation).
    #[deprecated(note = "Use BridgeStorageEngine instead — Phase C cloud migration")]
    cortex_db: Option<Mutex<rusqlite::Connection>>,
    /// Bridge-specific tables (stored in cortex.db or separate bridge.db).
    #[deprecated(note = "Use BridgeStorageEngine instead — Phase C cloud migration")]
    bridge_db: Option<Mutex<rusqlite::Connection>>,
    /// Whether the bridge is available (cortex.db exists and is accessible).
    available: AtomicBool,
    /// Bridge configuration.
    config: BridgeConfig,
    /// Event deduplicator (in-memory, TTL-based).
    dedup: Mutex<event_mapping::EventDeduplicator>,
    /// Usage tracker for metered features (Community tier).
    usage_tracker: license::UsageTracker,
    /// Degradation tracker.
    degradation: Mutex<health::DegradationTracker>,
}


#[allow(deprecated)]
impl BridgeRuntime {
    /// Create a new bridge runtime with the given configuration.
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            drift_db: None,
            cortex_db: None,
            bridge_db: None,
            available: AtomicBool::new(false),
            config,
            dedup: Mutex::new(event_mapping::EventDeduplicator::new()),
            usage_tracker: license::UsageTracker::new(),
            degradation: Mutex::new(health::DegradationTracker::new()),
        }
    }

    /// Initialize the bridge: open databases, create bridge tables.
    /// Returns Ok(true) if bridge is fully available, Ok(false) if degraded.
    pub fn initialize(&mut self) -> Result<bool, errors::BridgeError> {
        if !self.config.enabled {
            info!("Bridge disabled by configuration");
            return Ok(false);
        }

        // Try to open cortex.db
        let cortex_path = self.config.cortex_db_path.as_deref().unwrap_or("cortex.db");
        if !Path::new(cortex_path).exists() {
            info!(path = cortex_path, "cortex.db not found — bridge in degraded mode");
            self.available.store(false, Ordering::SeqCst);
            return Ok(false);
        }

        match rusqlite::Connection::open(cortex_path) {
            Ok(conn) => {
                storage::configure_connection(&conn)?;
                self.cortex_db = Some(Mutex::new(conn));
            }
            Err(e) => {
                warn!(error = %e, "Failed to open cortex.db — bridge in degraded mode");
                self.available.store(false, Ordering::SeqCst);
                return Ok(false);
            }
        }

        // Try to open drift.db (read-only)
        let drift_path = self.config.drift_db_path.as_deref().unwrap_or("drift.db");
        if Path::new(drift_path).exists() {
            match rusqlite::Connection::open_with_flags(
                drift_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) {
                Ok(conn) => {
                    if let Err(e) = storage::configure_readonly_connection(&conn) {
                        warn!(error = %e, "Failed to configure drift.db PRAGMAs");
                    }
                    self.drift_db = Some(Mutex::new(conn));
                }
                Err(e) => {
                    warn!(error = %e, "Failed to open drift.db — grounding unavailable");
                }
            }
        }

        // Run schema migrations (creates tables if needed, upgrades if outdated)
        if let Some(ref db) = self.cortex_db {
            let conn = db.lock().map_err(|e| errors::BridgeError::Config(e.to_string()))?;
            storage::migrate(&conn)?;

            // Apply retention policy to clean up old data on startup
            let is_community = matches!(self.config.license_tier, license::LicenseTier::Community);
            if let Err(e) = storage::apply_retention(&conn, is_community) {
                warn!(error = %e, "Retention cleanup failed during initialization — non-fatal");
            }

            // Restore usage counts from previous session (P2-7)
            if let Err(e) = self.usage_tracker.load(&conn) {
                warn!(error = %e, "Failed to load usage tracker state — starting fresh");
            }
        }

        self.available.store(true, Ordering::SeqCst);
        info!("Bridge initialized successfully");
        Ok(true)
    }

    /// Check if the bridge is available (cortex.db accessible).
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }

    /// Shutdown the bridge, closing all connections.
    pub fn shutdown(&mut self) {
        // Persist usage counts before closing connections (P2-7)
        if let Some(ref db) = self.cortex_db {
            if let Ok(conn) = db.lock() {
                if let Err(e) = self.usage_tracker.persist(&conn) {
                    warn!(error = %e, "Failed to persist usage tracker state on shutdown");
                }
            }
        }

        self.drift_db = None;
        self.cortex_db = None;
        self.bridge_db = None;
        self.available.store(false, Ordering::SeqCst);
        info!("Bridge shut down");
    }

    /// Get the bridge configuration.
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    /// Run health checks on all subsystems.
    pub fn health_check(&self) -> health::BridgeHealth {
        let checks = vec![
            health::checks::check_cortex_db(self.cortex_db.as_ref()),
            health::checks::check_drift_db(self.drift_db.as_ref()),
            health::checks::check_bridge_db(self.bridge_db.as_ref()),
        ];
        health::compute_health(&checks)
    }

    /// Check if a dedup hash has been seen recently.
    pub fn is_duplicate_event(&self, event_type: &str, entity_id: &str, extra: &str) -> bool {
        match self.dedup.lock() {
            Ok(mut d) => d.is_duplicate(event_type, entity_id, extra),
            Err(_) => false, // Poisoned lock — allow event through
        }
    }

    /// Record a metered feature usage. Returns Err if limit exceeded.
    pub fn record_usage(&self, feature: &str) -> Result<(), license::UsageLimitExceeded> {
        self.usage_tracker.record(feature)
    }

    /// Get the degradation tracker.
    pub fn degradation(&self) -> &Mutex<health::DegradationTracker> {
        &self.degradation
    }
}
