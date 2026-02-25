//! Configuration errors.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during configuration loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Config file not found: {path}")]
    FileNotFound { path: String },

    #[error("Config parse error in {path}: {message}")]
    ParseError { path: String, message: String },

    #[error("Config validation failed for {field}: {message}")]
    ValidationFailed { field: String, message: String },

    #[error("Invalid config value for {field}: {message}")]
    InvalidValue { field: String, message: String },
}

impl DriftErrorCode for ConfigError {
    fn error_code(&self) -> &'static str {
        error_code::CONFIG_ERROR
    }
}
