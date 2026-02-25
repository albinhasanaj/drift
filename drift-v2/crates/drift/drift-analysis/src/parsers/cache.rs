//! Parse cache: Moka LRU in-memory + optional SQLite persistence.
//! Keyed by (content_hash, language) — same content parsed as different
//! languages produces separate cache entries.

use moka::sync::Cache;

use super::types::ParseResult;
use crate::scanner::language_detect::Language;

/// Cache key combining content hash with language discriminant.
/// This prevents cross-language collisions (e.g. identical content in .c and .cs).
type CacheKey = (u64, std::mem::Discriminant<Language>);

fn make_key(content_hash: u64, lang: Language) -> CacheKey {
    (content_hash, std::mem::discriminant(&lang))
}

/// In-memory parse cache using Moka (TinyLFU admission).
pub struct ParseCache {
    inner: Cache<CacheKey, ParseResult>,
}

impl ParseCache {
    /// Create a new parse cache with the given capacity.
    pub fn new(capacity: u64) -> Self {
        Self {
            inner: Cache::new(capacity),
        }
    }

    /// Get a cached parse result by content hash and language.
    pub fn get(&self, content_hash: u64, lang: Language) -> Option<ParseResult> {
        self.inner.get(&make_key(content_hash, lang))
    }

    /// Insert a parse result into the cache.
    pub fn insert(&self, content_hash: u64, lang: Language, result: ParseResult) {
        self.inner.insert(make_key(content_hash, lang), result);
    }

    /// Returns the number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    /// Invalidate a cache entry.
    pub fn invalidate(&self, content_hash: u64, lang: Language) {
        self.inner.invalidate(&make_key(content_hash, lang));
    }
}

impl Default for ParseCache {
    fn default() -> Self {
        // Default: cache up to 10,000 parse results
        Self::new(10_000)
    }
}
