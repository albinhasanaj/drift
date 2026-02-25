//! Token counter — tiktoken-rs wrapper for accurate model-aware token counting.

use drift_core::errors::ContextError;
use std::sync::OnceLock;

/// Token counter using tiktoken-rs for accurate counting.
/// Caches the BPE instance for performance.
pub struct TokenCounter {
    /// Model name for tokenizer selection.
    model: String,
    /// Cached BPE tokenizer (loaded lazily on first use).
    bpe: OnceLock<Option<tiktoken_rs::CoreBPE>>,
}

impl TokenCounter {
    /// Create a new token counter for the given model.
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            bpe: OnceLock::new(),
        }
    }

    /// Get or initialize the cached BPE tokenizer.
    fn get_bpe(&self) -> Result<&tiktoken_rs::CoreBPE, ContextError> {
        let cached = self.bpe.get_or_init(|| {
            tiktoken_rs::get_bpe_from_model(&self.model)
                .or_else(|_| tiktoken_rs::get_bpe_from_model("gpt-4"))
                .ok()
        });
        cached.as_ref().ok_or_else(|| ContextError::TokenizerError {
            message: format!("Failed to load tokenizer for model '{}'", self.model),
        })
    }

    /// Count tokens in the given text.
    pub fn count(&self, text: &str) -> Result<usize, ContextError> {
        let bpe = self.get_bpe()?;
        Ok(bpe.encode_with_special_tokens(text).len())
    }

    /// Count tokens with a fast approximation (4 chars ≈ 1 token).
    pub fn count_approximate(text: &str) -> usize {
        text.len().div_ceil(4)
    }

    /// Get the model name.
    pub fn model(&self) -> &str {
        &self.model
    }
}

impl Default for TokenCounter {
    fn default() -> Self {
        Self::new("gpt-4")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_tokens_basic() {
        let counter = TokenCounter::new("gpt-4");
        let count = counter.count("Hello, world!").unwrap();
        assert!(count > 0);
        assert!(count < 10);
    }

    #[test]
    fn test_count_empty_string() {
        let counter = TokenCounter::new("gpt-4");
        let count = counter.count("").unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_unicode() {
        let counter = TokenCounter::new("gpt-4");
        let count = counter.count("你好世界 🌍").unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_approximate_count() {
        let count = TokenCounter::count_approximate("Hello, world! This is a test.");
        assert!(count > 0);
        assert!((5..=15).contains(&count));
    }

    #[test]
    fn test_fallback_model() {
        let counter = TokenCounter::new("unknown-model-xyz");
        let count = counter.count("test text").unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_cached_bpe_performance() {
        let counter = TokenCounter::new("gpt-4");
        // First call loads BPE
        let _ = counter.count("warmup");
        // Subsequent calls should be fast
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = counter.count("Hello, world! This is a test of token counting.");
        }
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 500, "100 counts took {}ms", elapsed.as_millis());
    }
}
