//! Test topology — coverage mapping, smell detection, quality scoring.
//!
//! Maps test functions to source functions via call graph BFS,
//! detects 24 test smells, computes 7-dimension quality scores,
//! and supports 45+ test frameworks.

pub mod types;
pub mod coverage;
pub mod smells;
pub mod quality_scorer;
pub mod minimum_set;
pub mod frameworks;

pub use types::*;
pub use coverage::compute_coverage;
pub use smells::detect_smells;
pub use quality_scorer::compute_quality_score;
pub use minimum_set::compute_minimum_test_set;
pub use frameworks::detect_test_framework;
