//! # drift-napi
//!
//! NAPI-RS v3 bindings for the Drift analysis engine.
//! Provides the TypeScript/JavaScript bridge layer.
//!
//! Architecture:
//! - `runtime` — `DriftRuntime` singleton via `OnceLock` (lock-free after init)
//! - `conversions` — Rust ↔ JS type conversions, error code mapping
//! - `bindings` — NAPI-exported functions (lifecycle, scanner)

// PH4-01: Blanket dead_code/unused suppression removed. Add targeted #[allow] on specific items if needed.

pub mod runtime;
pub mod conversions;
pub mod bindings;
pub mod feedback_store;
