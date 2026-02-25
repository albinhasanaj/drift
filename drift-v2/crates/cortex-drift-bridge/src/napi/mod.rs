//! NAPI bindings for the bridge — 20 functions exposed to TypeScript.
//!
//! These are the function signatures that cortex-drift-napi will wrap.
//! The actual NAPI macros live in the cortex-drift-napi crate.

pub mod functions;

pub use functions::*;
