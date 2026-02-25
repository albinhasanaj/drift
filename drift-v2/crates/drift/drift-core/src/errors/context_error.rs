//! Context generation errors.

use super::error_code::DriftErrorCode;

/// Errors that can occur during context generation.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("Token budget exceeded: {used} tokens used, {budget} budget")]
    TokenBudgetExceeded { used: usize, budget: usize },

    #[error("Invalid context depth: {depth}")]
    InvalidDepth { depth: String },

    #[error("Invalid context intent: {intent}")]
    InvalidIntent { intent: String },

    #[error("Tokenizer error: {message}")]
    TokenizerError { message: String },

    #[error("Format error: {message}")]
    FormatError { message: String },

    #[error("Session error: {message}")]
    SessionError { message: String },

    #[error("Weight provider error: {message}")]
    WeightProviderError { message: String },

    #[error("Specification error: {message}")]
    SpecificationError { message: String },

    #[error("Package manager error: {message}")]
    PackageManagerError { message: String },

    #[error("Storage error: {0}")]
    Storage(#[from] super::StorageError),
}

impl DriftErrorCode for ContextError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::TokenBudgetExceeded { .. } => "CONTEXT_TOKEN_BUDGET_EXCEEDED",
            Self::InvalidDepth { .. } => "CONTEXT_INVALID_DEPTH",
            Self::InvalidIntent { .. } => "CONTEXT_INVALID_INTENT",
            Self::TokenizerError { .. } => "CONTEXT_TOKENIZER_ERROR",
            Self::FormatError { .. } => "CONTEXT_FORMAT_ERROR",
            Self::SessionError { .. } => "CONTEXT_SESSION_ERROR",
            Self::WeightProviderError { .. } => "CONTEXT_WEIGHT_PROVIDER_ERROR",
            Self::SpecificationError { .. } => "CONTEXT_SPECIFICATION_ERROR",
            Self::PackageManagerError { .. } => "CONTEXT_PACKAGE_MANAGER_ERROR",
            Self::Storage(e) => e.error_code(),
        }
    }
}
