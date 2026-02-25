//! # cortex-compression
//!
//! 4-level hierarchical memory compression.
//! L0: IDs only (~5 tokens), L1: one-liners (~50), L2: with examples (~200), L3: full context (~500).
//! Priority-weighted bin-packing ensures critical memories get at least L1.

pub mod engine;
pub mod levels;
pub mod packing;

pub use engine::CompressionEngine;
pub use levels::CompressionLevel;
