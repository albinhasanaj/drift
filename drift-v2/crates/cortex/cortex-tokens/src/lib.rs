//! # cortex-tokens
//!
//! Accurate token counting via `tiktoken-rs` (`cl100k_base`).
//! Replaces string-length approximation with exact tokenizer-based counting.
//! Caches results per content hash for performance.

pub mod budget;
pub mod counter;

pub use budget::{Allocation, TokenBudget};
pub use counter::TokenCounter;
