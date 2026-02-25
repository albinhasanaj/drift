//! Quality gate errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during quality gate evaluation.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("Gate evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("Dependency not met: {gate} requires {dependency}")]
    DependencyNotMet { gate: String, dependency: String },

    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}

impl DriftErrorCode for GateError {
    fn error_code(&self) -> &'static str {
        error_code::GATE_FAILED
    }
}
