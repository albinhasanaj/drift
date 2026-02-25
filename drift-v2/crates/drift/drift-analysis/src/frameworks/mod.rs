//! Framework Definition System — TOML-driven, user-extensible framework detection.
//!
//! Replaces V1's 441 hand-written TypeScript detector files with declarative TOML
//! framework packs that operate on V2's rich `ParseResult` data.
//!
//! Architecture:
//! - `types.rs` — FrameworkSpec, PatternDef, MatchPredicate serde types
//! - `loader.rs` — TOML parsing → CompiledFrameworkPack (regex pre-compiled)
//! - `matcher.rs` — FileDetectorHandler that matches patterns against ParseResult
//! - `learner.rs` — LearningDetectorHandler for convention deviation detection
//! - `registry.rs` — Framework detection + pack loading from built-in + .drift/frameworks/

pub mod types;
pub mod loader;
pub mod matcher;
pub mod learner;
pub mod registry;
pub mod diagnostics;

pub use loader::CompiledFrameworkPack;
pub use matcher::FrameworkMatcher;
pub use learner::FrameworkLearner;
pub use registry::FrameworkPackRegistry;
pub use diagnostics::FrameworkDiagnostics;
