//! DNA System (System 24) — 10 gene extractors, health scoring, mutation detection.
//!
//! The capstone metric system that synthesizes convention data from across the
//! entire codebase into a biologically-inspired model.

pub mod types;
pub mod extractor;
pub mod extractors;
pub mod health;
pub mod mutations;
pub mod context_builder;
pub mod regex_set;

pub use types::*;
pub use extractor::{GeneExtractor, GeneExtractorRegistry};
