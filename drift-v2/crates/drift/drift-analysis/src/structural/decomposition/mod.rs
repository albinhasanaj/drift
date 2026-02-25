//! Module Decomposition Enhancement — decompose_with_priors(), 6-signal decomposition.
//!
//! D1 compliant: all types and algorithms live in drift-analysis.
//! They accept priors as parameters but have ZERO knowledge of Cortex.

pub mod types;
pub mod decomposer;

pub use types::*;
pub use decomposer::decompose_with_priors;
