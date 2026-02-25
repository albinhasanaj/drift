//! # drift-storage
//!
//! SQLite persistence layer for the Drift analysis engine.
//! WAL mode, write-serialized + read-pooled, batch writer,
//! keyset pagination, schema migrations.

// Note: dead_code warnings are expected — many query functions are not yet
// called from NAPI bindings. See STORAGE-HARDENING-TASKS.md Phase B.
// PH4-04: Blanket dead_code suppression removed. Add targeted #[allow] on specific items if needed.

pub mod connection;
pub mod batch;
pub mod engine;
pub mod migrations;
pub mod queries;
pub mod pagination;
pub mod materialized;
pub mod retention;

pub use connection::DatabaseManager;
pub use batch::BatchWriter;
pub use engine::DriftStorageEngine;
