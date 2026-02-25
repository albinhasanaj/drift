//! Call graph errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during call graph operations.
#[derive(Debug, thiserror::Error)]
pub enum CallGraphError {
    #[error("Cycle detected in call graph: {path:?}")]
    CycleDetected { path: Vec<String> },

    #[error("Resolution failed for {name}: {message}")]
    ResolutionFailed { name: String, message: String },

    #[error("Memory exceeded during call graph construction")]
    MemoryExceeded,

    #[error("CTE fallback failed: {message}")]
    CteFallbackFailed { message: String },
}

impl DriftErrorCode for CallGraphError {
    fn error_code(&self) -> &'static str {
        error_code::CALL_GRAPH_ERROR
    }
}
