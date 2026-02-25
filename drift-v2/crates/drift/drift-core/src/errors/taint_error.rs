//! Taint analysis errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during taint analysis.
#[derive(Debug, thiserror::Error)]
pub enum TaintError {
    #[error("Invalid taint source: {0}")]
    InvalidSource(String),

    #[error("Invalid taint sink: {0}")]
    InvalidSink(String),

    #[error("Taint path too long ({length} nodes, max {max})")]
    PathTooLong { length: usize, max: usize },

    #[error("Summary conflict: {0}")]
    SummaryConflict(String),
}

impl DriftErrorCode for TaintError {
    fn error_code(&self) -> &'static str {
        error_code::TAINT_ERROR
    }
}
