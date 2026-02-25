//! Scanner errors.

use std::path::PathBuf;

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur during file scanning.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("IO error scanning {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Permission denied: {path}")]
    PermissionDenied { path: PathBuf },

    #[error("Scan cancelled")]
    Cancelled,

    #[error("File too large: {path} ({size} bytes, max {max})")]
    MaxFileSizeExceeded { path: PathBuf, size: u64, max: u64 },

    #[error("Unsupported encoding in {path}: {encoding}")]
    UnsupportedEncoding { path: PathBuf, encoding: String },
}

impl DriftErrorCode for ScanError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Cancelled => error_code::CANCELLED,
            _ => error_code::SCAN_ERROR,
        }
    }
}
