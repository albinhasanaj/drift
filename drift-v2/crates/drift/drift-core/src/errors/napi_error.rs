//! NAPI error conversion.
//! Converts all Drift error types to structured NAPI error strings.

use super::error_code::DriftErrorCode;
use super::{
    BoundaryError, CallGraphError, ConfigError, ConstraintError, DetectionError,
    GateError, ParseError, PipelineError, ScanError, StorageError, TaintError,
};

/// NAPI-specific error wrapper that converts any Drift error
/// to a structured `[ERROR_CODE] message` string.
#[derive(Debug, thiserror::Error)]
#[error("[{code}] {message}")]
pub struct NapiError {
    pub code: &'static str,
    pub message: String,
}

impl NapiError {
    pub fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
}

impl DriftErrorCode for NapiError {
    fn error_code(&self) -> &'static str {
        self.code
    }
}

impl From<ScanError> for NapiError {
    fn from(e: ScanError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<ParseError> for NapiError {
    fn from(e: ParseError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<StorageError> for NapiError {
    fn from(e: StorageError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<DetectionError> for NapiError {
    fn from(e: DetectionError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<CallGraphError> for NapiError {
    fn from(e: CallGraphError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<PipelineError> for NapiError {
    fn from(e: PipelineError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<TaintError> for NapiError {
    fn from(e: TaintError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<ConstraintError> for NapiError {
    fn from(e: ConstraintError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<BoundaryError> for NapiError {
    fn from(e: BoundaryError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<GateError> for NapiError {
    fn from(e: GateError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}

impl From<ConfigError> for NapiError {
    fn from(e: ConfigError) -> Self {
        Self::new(e.error_code(), e.to_string())
    }
}
