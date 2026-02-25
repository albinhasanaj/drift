//! Constraint errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during constraint verification.
#[derive(Debug, thiserror::Error)]
pub enum ConstraintError {
    #[error("Invalid invariant: {0}")]
    InvalidInvariant(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Conflicting constraints: {a} vs {b}")]
    ConflictingConstraints { a: String, b: String },
}

impl DriftErrorCode for ConstraintError {
    fn error_code(&self) -> &'static str {
        error_code::CONSTRAINT_ERROR
    }
}
