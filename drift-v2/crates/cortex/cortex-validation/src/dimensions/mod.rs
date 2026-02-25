//! 4-dimension validation framework.
//!
//! Each dimension produces a score (0.0–1.0) and a list of healing actions.
//! The engine aggregates these into an overall ValidationResult.

pub mod citation;
pub mod contradiction;
pub mod pattern_alignment;
pub mod temporal;
