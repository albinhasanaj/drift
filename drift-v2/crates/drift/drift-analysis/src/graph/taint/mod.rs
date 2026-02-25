//! Taint analysis — source/sink/sanitizer model with 17 CWE categories.
//!
//! Two-phase analysis:
//! 1. Intraprocedural (<1ms/function) — within-function dataflow
//! 2. Interprocedural (<100ms/function) — cross-function via summaries
//!
//! TOML-driven registry for extensibility. SARIF output for CI integration.

pub mod types;
pub mod registry;
pub mod intraprocedural;
pub mod interprocedural;
pub mod propagation;
pub mod sarif;
pub mod framework_specs;

pub use types::*;
pub use registry::TaintRegistry;
pub use intraprocedural::analyze_intraprocedural;
pub use interprocedural::analyze_interprocedural;
pub use sarif::generate_sarif;
