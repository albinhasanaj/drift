//! Observability system for Drift.
//! `tracing` crate with `EnvFilter`, per-subsystem log levels.

pub mod metrics;
pub mod setup;

pub use setup::init_tracing;
