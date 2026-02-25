//! Error handling analysis — 8-phase topology engine with 20+ framework support.
//!
//! Detects unhandled error paths, empty catch blocks, swallowed errors,
//! and framework-specific error handling patterns.

pub mod types;
pub mod profiler;
pub mod handler_detection;
pub mod propagation;
pub mod gap_analysis;
pub mod frameworks;
pub mod cwe_mapping;

pub use types::*;
pub use profiler::profile_error_types;
pub use handler_detection::detect_handlers;
pub use propagation::trace_propagation;
pub use gap_analysis::analyze_gaps;
pub use frameworks::detect_framework_handlers;
pub use cwe_mapping::map_to_cwe;
