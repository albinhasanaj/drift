//! GAST — Generic AST normalization layer.
//!
//! Normalizes language-specific tree-sitter ASTs into a common representation
//! with ~40-50 node types + an `Other` catch-all for zero data loss.

pub mod types;
pub mod base_normalizer;
pub mod normalizers;

pub use types::GASTNode;
pub use base_normalizer::BaseNormalizer;
