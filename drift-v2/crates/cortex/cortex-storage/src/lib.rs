//! # cortex-storage
//!
//! SQLite persistence layer for the Cortex memory system.
//! Implements `IMemoryStorage` and `ICausalStorage` traits.
//! Single write connection + read pool (WAL mode).

pub mod audit;
pub mod compaction;
pub mod engine;
pub mod migrations;
pub mod pool;
pub mod queries;
pub mod recovery;
pub mod temporal_events;
pub mod versioning;

pub use engine::StorageEngine;

/// Helper to convert a string message into a CortexError::Storage.
pub fn to_storage_err(msg: String) -> cortex_core::CortexError {
    cortex_core::CortexError::StorageError(cortex_core::errors::StorageError::SqliteError {
        message: msg,
    })
}
