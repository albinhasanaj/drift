//! CortexError → napi::Error conversion with structured error info.

use cortex_core::CortexError;
use napi::Status;

/// Error code strings for structured JS error handling.
pub mod codes {
    pub const MEMORY_NOT_FOUND: &str = "MEMORY_NOT_FOUND";
    pub const INVALID_TYPE: &str = "INVALID_TYPE";
    pub const EMBEDDING_ERROR: &str = "EMBEDDING_ERROR";
    pub const STORAGE_ERROR: &str = "STORAGE_ERROR";
    pub const CAUSAL_CYCLE: &str = "CAUSAL_CYCLE";
    pub const TOKEN_BUDGET_EXCEEDED: &str = "TOKEN_BUDGET_EXCEEDED";
    pub const MIGRATION_ERROR: &str = "MIGRATION_ERROR";
    pub const SANITIZATION_ERROR: &str = "SANITIZATION_ERROR";
    pub const CONSOLIDATION_ERROR: &str = "CONSOLIDATION_ERROR";
    pub const VALIDATION_ERROR: &str = "VALIDATION_ERROR";
    pub const SERIALIZATION_ERROR: &str = "SERIALIZATION_ERROR";
    pub const CONCURRENCY_ERROR: &str = "CONCURRENCY_ERROR";
    pub const CLOUD_SYNC_ERROR: &str = "CLOUD_SYNC_ERROR";
    pub const CONFIG_ERROR: &str = "CONFIG_ERROR";
    pub const DEGRADED_MODE: &str = "DEGRADED_MODE";
    pub const RUNTIME_NOT_INITIALIZED: &str = "RUNTIME_NOT_INITIALIZED";
    pub const TEMPORAL_ERROR: &str = "TEMPORAL_ERROR";
    pub const MULTI_AGENT_ERROR: &str = "MULTI_AGENT_ERROR";
}

/// Map a CortexError to a structured napi::Error with an error code.
pub fn to_napi_error(err: CortexError) -> napi::Error {
    let (code, message) = match &err {
        CortexError::MemoryNotFound { id } => {
            (codes::MEMORY_NOT_FOUND, format!("Memory not found: {id}"))
        }
        CortexError::InvalidType { type_name } => (
            codes::INVALID_TYPE,
            format!("Invalid memory type: {type_name}"),
        ),
        CortexError::EmbeddingError(e) => (codes::EMBEDDING_ERROR, format!("Embedding error: {e}")),
        CortexError::StorageError(e) => (codes::STORAGE_ERROR, format!("Storage error: {e}")),
        CortexError::CausalCycle { path } => (
            codes::CAUSAL_CYCLE,
            format!("Causal cycle detected: {path}"),
        ),
        CortexError::TokenBudgetExceeded { needed, available } => (
            codes::TOKEN_BUDGET_EXCEEDED,
            format!("Token budget exceeded: needed {needed}, available {available}"),
        ),
        CortexError::MigrationError(msg) => {
            (codes::MIGRATION_ERROR, format!("Migration error: {msg}"))
        }
        CortexError::SanitizationError(msg) => (
            codes::SANITIZATION_ERROR,
            format!("Sanitization error: {msg}"),
        ),
        CortexError::ConsolidationError(e) => (
            codes::CONSOLIDATION_ERROR,
            format!("Consolidation error: {e}"),
        ),
        CortexError::ValidationError(msg) => {
            (codes::VALIDATION_ERROR, format!("Validation error: {msg}"))
        }
        CortexError::SerializationError(e) => (
            codes::SERIALIZATION_ERROR,
            format!("Serialization error: {e}"),
        ),
        CortexError::ConcurrencyError(msg) => (
            codes::CONCURRENCY_ERROR,
            format!("Concurrency error: {msg}"),
        ),
        CortexError::CloudSyncError(e) => {
            (codes::CLOUD_SYNC_ERROR, format!("Cloud sync error: {e}"))
        }
        CortexError::ConfigError(msg) => (codes::CONFIG_ERROR, format!("Config error: {msg}")),
        CortexError::DegradedMode {
            component,
            fallback,
        } => (
            codes::DEGRADED_MODE,
            format!("Degraded mode: {component} using fallback: {fallback}"),
        ),
        CortexError::TemporalError(ref e) => {
            (codes::TEMPORAL_ERROR, format!("Temporal error: {e}"))
        }
        CortexError::MultiAgentError(ref e) => {
            (codes::MULTI_AGENT_ERROR, format!("Multi-agent error: {e}"))
        }
    };

    napi::Error::new(Status::GenericFailure, format!("[{code}] {message}"))
}

/// Convenience: convert a CortexResult<T> to napi::Result<T>.
pub fn from_cortex<T>(result: cortex_core::CortexResult<T>) -> napi::Result<T> {
    result.map_err(to_napi_error)
}

/// Create a "runtime not initialized" error.
pub fn runtime_not_initialized() -> napi::Error {
    napi::Error::new(
        Status::GenericFailure,
        format!(
            "[{}] CortexRuntime not initialized. Call initialize() first.",
            codes::RUNTIME_NOT_INITIALIZED
        ),
    )
}
