//! Boundary detection errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during boundary detection.
#[derive(Debug, thiserror::Error)]
pub enum BoundaryError {
    #[error("Unknown ORM: {0}")]
    UnknownOrm(String),

    #[error("Extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("Sensitive field conflict: {field} in {model}")]
    SensitiveFieldConflict { field: String, model: String },
}

impl DriftErrorCode for BoundaryError {
    fn error_code(&self) -> &'static str {
        error_code::BOUNDARY_ERROR
    }
}
