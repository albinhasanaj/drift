//! Parser errors.

use std::path::PathBuf;

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during file parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Grammar not found for language: {language}")]
    GrammarNotFound { language: String },

    #[error("Tree-sitter error parsing {path}: {message}")]
    TreeSitterError { path: PathBuf, message: String },

    #[error("Parse timeout for {path} after {timeout_ms}ms")]
    Timeout { path: PathBuf, timeout_ms: u64 },

    #[error("Unsupported language: {extension}")]
    UnsupportedLanguage { extension: String },

    #[error("Partial parse of {path}: {message}")]
    PartialParse { path: PathBuf, message: String },
}

impl DriftErrorCode for ParseError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::UnsupportedLanguage { .. } => error_code::UNSUPPORTED_LANGUAGE,
            _ => error_code::PARSE_ERROR,
        }
    }
}
