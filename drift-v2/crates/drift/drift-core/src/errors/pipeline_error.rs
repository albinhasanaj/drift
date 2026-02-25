//! Pipeline errors and non-fatal error collection.

use super::error_code::{self, DriftErrorCode};
use super::{
    CallGraphError, ConfigError, DetectionError, GateError, ParseError, ScanError,
    StorageError,
};

/// Errors that can occur during pipeline execution.
/// Aggregates subsystem errors via `From` conversions.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("Scan error: {0}")]
    Scan(#[from] ScanError),

    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Detection error: {0}")]
    Detection(#[from] DetectionError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Call graph error: {0}")]
    CallGraph(#[from] CallGraphError),

    #[error("Gate error: {0}")]
    Gate(#[from] GateError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Pipeline cancelled")]
    Cancelled,
}

impl DriftErrorCode for PipelineError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Scan(e) => e.error_code(),
            Self::Parse(e) => e.error_code(),
            Self::Detection(e) => e.error_code(),
            Self::Storage(e) => e.error_code(),
            Self::CallGraph(e) => e.error_code(),
            Self::Gate(e) => e.error_code(),
            Self::Config(e) => e.error_code(),
            Self::Cancelled => error_code::CANCELLED,
        }
    }
}

/// Result of a pipeline run that accumulates non-fatal errors.
/// Allows partial results to be returned even when some files fail.
#[derive(Debug, Default)]
pub struct PipelineResult<T: Default = ()> {
    /// The successful result data.
    pub data: T,
    /// Non-fatal errors collected during the pipeline run.
    pub errors: Vec<PipelineError>,
}

impl<T: Default> PipelineResult<T> {
    /// Create a new empty pipeline result.
    pub fn new(data: T) -> Self {
        Self {
            data,
            errors: Vec::new(),
        }
    }

    /// Add a non-fatal error to the result.
    pub fn add_error(&mut self, error: PipelineError) {
        self.errors.push(error);
    }

    /// Returns true if there are no non-fatal errors.
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns the number of non-fatal errors.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}
