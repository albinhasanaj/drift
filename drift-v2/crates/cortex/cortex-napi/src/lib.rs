//! # cortex-napi
//!
//! NAPI bindings for TypeScript interop.
//! Owns `CortexRuntime` singleton with all engines, background task scheduler (tokio), and graceful shutdown.
//!
//! ## Architecture
//!
//! - `runtime.rs` — Global `CortexRuntime` singleton owning all engines
//! - `bindings/` — 17 domain-specific NAPI binding modules (68 exported functions)
//! - `conversions/` — Rust ↔ JS type conversions via serde_json

pub mod bindings;
pub mod conversions;
pub mod runtime;
