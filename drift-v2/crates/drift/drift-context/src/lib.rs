//! # drift-context
//!
//! Context generation for the Drift analysis engine.
//! Provides context building, tokenization, output formats,
//! package manager support, and specification engine.

// PH4-05: Blanket dead_code/unused suppression removed. Add targeted #[allow] on specific items if needed.

pub mod generation;
pub mod tokenization;
pub mod formats;
pub mod packages;
pub mod specification;
