use moka::sync::Cache;
use std::sync::Arc;
use tiktoken_rs::CoreBPE;

/// Accurate token counter wrapping tiktoken's cl100k_base tokenizer.
/// Caches results per blake3 content hash for performance.
pub struct TokenCounter {
    bpe: Arc<CoreBPE>,
    cache: Cache<String, usize>,
}

impl TokenCounter {
    /// Create a new TokenCounter with the given cache capacity.
    pub fn new(cache_capacity: u64) -> Self {
        let bpe = tiktoken_rs::cl100k_base().expect("failed to load cl100k_base tokenizer");
        Self {
            bpe: Arc::new(bpe),
            cache: Cache::new(cache_capacity),
        }
    }

    /// Count tokens in the given text (uncached).
    pub fn count(&self, text: &str) -> usize {
        self.bpe.encode_ordinary(text).len()
    }

    /// Count tokens with blake3 content-hash caching.
    /// Repeated calls with the same text return the cached result.
    pub fn count_cached(&self, text: &str) -> usize {
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        self.cache.get_with(hash, || self.count(text))
    }
}

impl Default for TokenCounter {
    fn default() -> Self {
        Self::new(10_000)
    }
}
