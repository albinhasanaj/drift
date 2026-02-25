//! Decision Mining — git2-based institutional decision extraction.
//!
//! 12 decision categories, ADR detection, temporal correlation.

pub mod types;
pub mod git_analysis;
pub mod adr_detection;
pub mod categorizer;
pub mod temporal;

pub use types::*;
pub use git_analysis::GitAnalyzer;
pub use adr_detection::AdrDetector;
pub use categorizer::DecisionCategorizer;
pub use temporal::TemporalCorrelator;
