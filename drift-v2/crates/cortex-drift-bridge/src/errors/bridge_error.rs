//! Bridge error types (per AD6 — thiserror).

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Cortex unavailable: {reason}")]
    CortexUnavailable { reason: String },

    #[error("Drift unavailable: {reason}")]
    DriftUnavailable { reason: String },

    #[error("ATTACH failed for {db_path}: {source}")]
    AttachFailed {
        db_path: String,
        source: rusqlite::Error,
    },

    #[error("Grounding failed for memory {memory_id}: {reason}")]
    GroundingFailed { memory_id: String, reason: String },

    #[error("Event mapping failed: {event_type} → {memory_type}: {reason}")]
    EventMappingFailed {
        event_type: String,
        memory_type: String,
        reason: String,
    },

    #[error("Link translation failed: {source_type} → EntityLink: {reason}")]
    LinkTranslationFailed {
        source_type: String,
        reason: String,
    },

    #[error("Cross-DB query failed: {query}: {source}")]
    CrossDbQueryFailed {
        query: String,
        source: rusqlite::Error,
    },

    #[error("Memory creation failed: {memory_type}: {reason}")]
    MemoryCreationFailed {
        memory_type: String,
        reason: String,
    },

    #[error("Causal engine error: {operation}: {reason}")]
    Causal { operation: String, reason: String },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("Cortex error: {0}")]
    Cortex(#[from] cortex_core::CortexError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("License tier insufficient: {feature} requires {required_tier}")]
    LicenseInsufficient {
        feature: String,
        required_tier: String,
    },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Storage write failed: {0}")]
    StorageWrite(String),
}

pub type BridgeResult<T> = Result<T, BridgeError>;
