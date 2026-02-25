//! Unified Analysis Engine — 4-phase per-file pipeline with single-pass visitor pattern (AD4).
//!
//! The engine runs all detectors as visitors in a single AST traversal per file,
//! providing 10-100x performance improvement over multi-pass approaches.

pub mod types;
pub mod visitor;
pub mod pipeline;
pub mod string_extraction;
pub mod regex_engine;
pub mod resolution;
pub mod incremental;
pub mod toml_patterns;
pub mod gast;

pub use types::{AnalysisResult, PatternMatch, PatternCategory, DetectionMethod, AnalysisPhase};
pub use visitor::{DetectorHandler, FileDetectorHandler, LearningDetectorHandler, DetectionContext, DetectionEngine, VisitorRegistry};
pub use pipeline::AnalysisPipeline;
pub use resolution::ResolutionIndex;
pub use incremental::IncrementalAnalyzer;
pub use toml_patterns::{TomlPatternLoader, CompiledQuery};
