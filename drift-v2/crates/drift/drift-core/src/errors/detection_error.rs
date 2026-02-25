//! Detection errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during pattern detection.
#[derive(Debug, thiserror::Error)]
pub enum DetectionError {
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    #[error("Query compilation failed: {0}")]
    QueryCompilationFailed(String),

    #[error("Detector {id} panicked: {message}")]
    DetectorPanic { id: String, message: String },

    #[error("Detection timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
}

impl DriftErrorCode for DetectionError {
    fn error_code(&self) -> &'static str {
        error_code::DETECTION_ERROR
    }
}
