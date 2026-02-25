//! Storage-layer errors for SQLite operations.

use super::error_code::{self, DriftErrorCode};

/// Errors that can occur in the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("SQLite error: {message}")]
    SqliteError { message: String },

    #[error("Migration failed at version {version}: {message}")]
    MigrationFailed { version: u32, message: String },

    #[error("Database busy (another operation in progress)")]
    DbBusy,

    #[error("Database corrupt: {details}")]
    DbCorrupt { details: String },

    #[error("Disk full")]
    DiskFull,

    #[error("Connection pool exhausted: {active} active connections")]
    ConnectionPoolExhausted { active: usize },

    #[error("Operation not supported: {operation} — {reason}")]
    NotSupported { operation: String, reason: String },
}

impl DriftErrorCode for StorageError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::DbBusy => error_code::DB_BUSY,
            Self::DbCorrupt { .. } => error_code::DB_CORRUPT,
            Self::DiskFull => error_code::DISK_FULL,
            Self::MigrationFailed { .. } => error_code::MIGRATION_FAILED,
            _ => error_code::STORAGE_ERROR,
        }
    }
}
